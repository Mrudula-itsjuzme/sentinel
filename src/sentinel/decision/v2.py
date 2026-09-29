from __future__ import annotations

from sentinel.decision.utility import calculate_utility
from sentinel.domain.actions import apply_intervention
from sentinel.decision.verification import build_verification_plan, verify_simulated_execution
from sentinel.domain.decision import (
    AdaptiveDecisionStep,
    AdaptiveResolution,
    AuditMetadata,
    CandidateDecision,
    DecisionBundle,
    DecisionOutcome,
    DecisionSelection,
    EvidenceValueEstimate,
)
from sentinel.evaluation.config import ControllerV2Config
from sentinel.execution.adapter import execute_independently
from sentinel.execution.verification import compare_prediction
from sentinel.policy.engine import PolicyDecision
from sentinel.policy.v2 import evaluate_policy_v2
from sentinel.scenarios.suite import ScenarioDefinition
from sentinel.simulator.engine import simulate_intervention
from sentinel.simulator.reachability import attack_paths


def _rank(decisions: list[CandidateDecision]) -> list[CandidateDecision]:
    eligible = [item for item in decisions if item.policy.decision is PolicyDecision.ALLOW]
    return sorted(eligible, key=lambda item: (-item.utility.total_utility, item.candidate.intervention.action.value, item.candidate.intervention.target))


def _estimate_evidence_value(
    scenario: ScenarioDefinition,
    decisions: list[CandidateDecision],
    pre_paths: int,
    config: ControllerV2Config,
) -> EvidenceValueEstimate:
    current = _rank(decisions)
    current_best = current[0].utility.total_utility if current else 0.0
    current_second = current[1].utility.total_utility if len(current) > 1 else 0.0
    current_action = current[0].candidate.intervention.action if current and current_best > 0 else None
    resolved: list[tuple[CandidateDecision, float]] = []
    for item in decisions:
        resolved_candidate = item.candidate.model_copy(update={"model_estimated_uncertainty": config.evidence_value.resolved_uncertainty})
        utility = calculate_utility(
            pre_attack_paths=pre_paths,
            pre_sensitive_assets=item.pre_action_sensitive_assets_reachable,
            candidate=resolved_candidate,
            simulation=item.simulation,
            policy=item.policy,
            weights=config.utility_weights,
        )
        if item.policy.decision is PolicyDecision.ALLOW:
            resolved.append((item, utility.total_utility))
    resolved.sort(key=lambda pair: (-pair[1], pair[0].candidate.intervention.action.value))
    resolved_best = resolved[0][1] if resolved else 0.0
    resolved_action = resolved[0][0].candidate.intervention.action if resolved and resolved_best > 0 else None
    selected_operational_cost = current[0].utility.operational_cost if current and current_best > 0 else 0.0
    score_improvement = max(0.0, resolved_best - max(0.0, current_best))
    avoidable_harm = selected_operational_cost * scenario.model_estimated_uncertainty
    improvement = score_improvement + avoidable_harm
    acquisition_cost = config.evidence_value.acquisition_cost
    delay_cost = (
        pre_paths
        * config.evidence_value.delay_cost_per_attack_path
        * (1 - scenario.model_estimated_uncertainty)
    )
    net = improvement - acquisition_cost - delay_cost
    changes = current_action != resolved_action or (
        current_action is not None
        and scenario.model_estimated_uncertainty >= 0.65
        and selected_operational_cost > 0
    )
    worthwhile = bool(
        scenario.evidence_request
        and changes
        and net >= config.evidence_value.minimum_expected_value
        and abs(current_best - current_second) <= config.evidence_value.material_action_margin
    )
    return EvidenceValueEstimate(
        current_action_margin=round(current_best - current_second, 4),
        decision_changes_if_uncertainty_resolves=changes,
        expected_decision_improvement=round(improvement, 4),
        acquisition_cost=acquisition_cost,
        delay_cost=round(delay_cost, 4),
        net_value=round(net, 4),
        request_worthwhile=worthwhile,
        explanation=(
            f"Current best utility is {current_best:.2f}; resolved-evidence best is {resolved_best:.2f}.",
            f"Expected avoidable harm and score improvement {improvement:.2f} minus acquisition {acquisition_cost:.2f} and probability-weighted delay {delay_cost:.2f} gives net {net:.2f}.",
            "Evidence is requested only when uncertainty could change action necessity or ranking and the current margin is material-sensitive.",
        ),
    )


def build_decision_bundle_v2(scenario: ScenarioDefinition, config: ControllerV2Config) -> DecisionBundle:
    paths = attack_paths(scenario.world)
    pre_sensitive = len({path[-1] for path in paths})
    decisions: list[CandidateDecision] = []
    for candidate in scenario.candidates:
        simulation = simulate_intervention(scenario.world, candidate.intervention)
        policy = evaluate_policy_v2(
            simulation,
            candidate,
            pre_attack_paths=len(paths),
            verification_available=True,
            config=config,
        )
        utility = calculate_utility(
            pre_attack_paths=len(paths),
            pre_sensitive_assets=pre_sensitive,
            candidate=candidate,
            simulation=simulation,
            policy=policy,
            weights=config.utility_weights,
        )
        decisions.append(CandidateDecision(
            candidate=candidate,
            pre_action_attack_paths=len(paths),
            pre_action_sensitive_assets_reachable=pre_sensitive,
            simulation=simulation,
            policy=policy,
            utility=utility,
            verification_plan=build_verification_plan(candidate.intervention, simulation),
            verification_result=verify_simulated_execution(scenario.world, candidate.intervention, simulation),
        ))
    evidence_value = _estimate_evidence_value(scenario, decisions, len(paths), config)
    ranked = _rank(decisions)
    if evidence_value.request_worthwhile:
        selection = DecisionSelection(
            outcome=DecisionOutcome.REQUEST_MORE_EVIDENCE,
            rationale=evidence_value.explanation,
            evidence_request=scenario.evidence_request,
        )
    elif not ranked or ranked[0].utility.total_utility <= 0:
        selection = DecisionSelection(outcome=DecisionOutcome.DEFER, rationale=("No policy-allowed candidate has positive utility after evidence-value analysis.",))
    else:
        winner = ranked[0]
        selection = DecisionSelection(
            outcome=DecisionOutcome.ACT,
            selected_action=winner.candidate.intervention.action.value,
            selected_target=winner.candidate.intervention.target,
            rationale=(
                f"Selected positive-utility policy-allowed action at {winner.utility.total_utility:.2f}.",
                f"Evidence request net value was {evidence_value.net_value:.2f}.",
            ),
        )
    generated_at = max(item.observed_at for item in scenario.evidence.observations)
    bundle = DecisionBundle(
        incident_summary=scenario.incident_summary,
        evidence=scenario.evidence,
        hypotheses=scenario.hypotheses,
        model_estimated_uncertainty=scenario.model_estimated_uncertainty,
        candidates=tuple(decisions),
        selection=selection,
        audit=AuditMetadata(generated_at=generated_at, engine_version="0.2.0", scenario_id=scenario.id, uncertainty_source=scenario.fixture_note),
    )
    return bundle.model_copy(update={
        "adaptive_resolution": AdaptiveResolution(
            initial_decision=selection,
            evidence_value=evidence_value,
            requested_evidence=selection.evidence_request,
            steps=(),
            replan_count=0,
            cumulative_operational_cost=0,
            final_residual_attack_paths=None,
            final_resolution="PENDING",
            escalation_required=False,
        )
    })


def execute_and_replan(bundle: DecisionBundle, scenario: ScenarioDefinition, config: ControllerV2Config, seed: int) -> DecisionBundle:
    selection = bundle.selection
    steps: list[AdaptiveDecisionStep] = []
    attempted: set[tuple[str, str]] = set()
    cumulative_cost = 0.0
    replan_count = 0
    final_paths = None
    escalation = False
    last_observed = None
    last_verification = None
    execution_world = scenario.world.clone()
    while selection.outcome is DecisionOutcome.ACT:
        selected = next(item for item in bundle.candidates if item.candidate.intervention.action.value == selection.selected_action and item.candidate.intervention.target == selection.selected_target)
        key = (selection.selected_action, selection.selected_target)
        if key in attempted and not config.replanning.repeat_same_action:
            escalation = True
            break
        attempted.add(key)
        prediction = simulate_intervention(execution_world, selected.candidate.intervention)
        observed = execute_independently(execution_world, selected.candidate.intervention, seed + len(steps) * 101)
        verification = compare_prediction(prediction, observed)
        last_observed, last_verification = observed, verification
        cumulative_cost += (
            config.utility_weights.disrupted_service * observed.services_disrupted
            + config.utility_weights.impacted_user * observed.users_impacted
            + (0 if observed.payroll_available else config.utility_weights.payroll_outage)
        )
        final_paths = observed.residual_attack_paths
        steps.append(AdaptiveDecisionStep(step=len(steps), phase="INITIAL_EXECUTION" if not steps else "REPLAN_EXECUTION", selection=selection, observed_outcome=observed, verification=verification))
        if observed.action_applied_fully:
            apply_intervention(execution_world, selected.candidate.intervention)
        critical_mismatch = not verification.critical_service_availability_match
        if not verification.escalation_required:
            break
        if critical_mismatch and config.replanning.escalate_on_critical_service_mismatch:
            escalation = True
            break
        if replan_count >= config.replanning.maximum_replans:
            escalation = True
            break
        revised: list[CandidateDecision] = []
        revised_paths = attack_paths(execution_world)
        revised_sensitive = len({path[-1] for path in revised_paths})
        for item in bundle.candidates:
            if (item.candidate.intervention.action.value, item.candidate.intervention.target) in attempted:
                continue
            simulation = simulate_intervention(execution_world, item.candidate.intervention)
            policy = evaluate_policy_v2(simulation, item.candidate, pre_attack_paths=len(revised_paths), verification_available=True, config=config)
            utility = calculate_utility(pre_attack_paths=len(revised_paths), pre_sensitive_assets=revised_sensitive, candidate=item.candidate, simulation=simulation, policy=policy, weights=config.utility_weights)
            revised.append(item.model_copy(update={"pre_action_attack_paths": len(revised_paths), "pre_action_sensitive_assets_reachable": revised_sensitive, "simulation": simulation, "policy": policy, "utility": utility}))
        alternatives = _rank(revised)
        if not alternatives:
            escalation = True
            break
        next_item = alternatives[0]
        selection = DecisionSelection(
            outcome=DecisionOutcome.ACT,
            selected_action=next_item.candidate.intervention.action.value,
            selected_target=next_item.candidate.intervention.target,
            rationale=("Verification mismatch triggered deterministic replanning; the failed action is excluded.",),
        )
        replan_count += 1
    resolution = "ESCALATED" if escalation else ("RESOLVED" if final_paths == 0 else "UNRESOLVED")
    adaptive = bundle.adaptive_resolution.model_copy(update={
        "steps": tuple(steps),
        "replan_count": replan_count,
        "cumulative_operational_cost": round(cumulative_cost, 4),
        "final_residual_attack_paths": final_paths,
        "final_resolution": resolution,
        "escalation_required": escalation,
    })
    return bundle.model_copy(update={"observed_outcome": last_observed, "independent_verification": last_verification, "adaptive_resolution": adaptive})
