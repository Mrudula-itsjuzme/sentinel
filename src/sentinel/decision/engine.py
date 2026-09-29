from sentinel import __version__
from sentinel.decision.utility import calculate_utility
from sentinel.decision.verification import build_verification_plan, verify_simulated_execution
from sentinel.domain.decision import (
    AuditMetadata,
    CandidateDecision,
    DecisionBundle,
    DecisionOutcome,
    DecisionSelection,
    UtilityWeights,
)
from sentinel.policy.engine import PolicyDecision, evaluate_policy
from sentinel.scenarios.suite import ScenarioDefinition
from sentinel.simulator.engine import simulate_intervention
from sentinel.simulator.reachability import attack_paths


def build_decision_bundle(
    scenario: ScenarioDefinition,
    *,
    weights: UtilityWeights | None = None,
    ignore_policy: bool = False,
    ignore_uncertainty: bool = False,
    ignore_operations: bool = False,
    uncertainty_request_threshold: float = 0.65,
) -> DecisionBundle:
    pre_paths = attack_paths(scenario.world)
    pre_sensitive = len({path[-1] for path in pre_paths})
    decisions: list[CandidateDecision] = []
    for candidate in scenario.candidates:
        simulation = simulate_intervention(scenario.world, candidate.intervention)
        policy = evaluate_policy(simulation, scenario.policy, destructive=candidate.intervention.destructive)
        utility = calculate_utility(
            pre_attack_paths=len(pre_paths),
            pre_sensitive_assets=pre_sensitive,
            candidate=candidate,
            simulation=simulation,
            policy=policy,
            weights=weights,
            ignore_policy=ignore_policy,
            ignore_uncertainty=ignore_uncertainty,
            ignore_operations=ignore_operations,
        )
        decisions.append(
            CandidateDecision(
                candidate=candidate,
                pre_action_attack_paths=len(pre_paths),
                pre_action_sensitive_assets_reachable=pre_sensitive,
                simulation=simulation,
                policy=policy,
                utility=utility,
                verification_plan=build_verification_plan(candidate.intervention, simulation),
                verification_result=verify_simulated_execution(scenario.world, candidate.intervention, simulation),
            )
        )

    if (
        not ignore_uncertainty
        and scenario.model_estimated_uncertainty >= uncertainty_request_threshold
        and scenario.evidence_request is not None
    ):
        selection = DecisionSelection(
            outcome=DecisionOutcome.REQUEST_MORE_EVIDENCE,
            rationale=(
                f"Model-estimated uncertainty {scenario.model_estimated_uncertainty:.2f} exceeds threshold {uncertainty_request_threshold:.2f}.",
                "A bounded evidence request is available before disruptive action.",
            ),
            evidence_request=scenario.evidence_request,
        )
    else:
        eligible = [
            item for item in decisions
            if ignore_policy or item.policy.decision is PolicyDecision.ALLOW
        ]
        eligible.sort(
            key=lambda item: (
                -item.utility.total_utility,
                item.candidate.intervention.action.value,
                item.candidate.intervention.target,
            )
        )
        if not eligible or eligible[0].utility.total_utility <= 0:
            selection = DecisionSelection(
                outcome=DecisionOutcome.DEFER,
                rationale=("No policy-eligible intervention has positive modeled utility.",),
            )
        else:
            winner = eligible[0]
            losers = [item for item in decisions if item is not winner]
            rationale = [
                f"Selected {winner.candidate.intervention.action.value} with utility {winner.utility.total_utility:.2f}.",
                f"Predicted residual attack paths: {winner.simulation.security.remaining_attack_paths}.",
                f"Policy result: {winner.policy.decision.value} ({winner.policy.code}).",
            ]
            if losers:
                runner_up = max(losers, key=lambda item: item.utility.total_utility)
                rationale.append(
                    f"Next alternative {runner_up.candidate.intervention.action.value} scored {runner_up.utility.total_utility:.2f}."
                )
            selection = DecisionSelection(
                outcome=DecisionOutcome.ACT,
                selected_action=winner.candidate.intervention.action.value,
                selected_target=winner.candidate.intervention.target,
                rationale=tuple(rationale),
            )

    generated_at = max(item.observed_at for item in scenario.evidence.observations)
    return DecisionBundle(
        incident_summary=scenario.incident_summary,
        evidence=scenario.evidence,
        hypotheses=scenario.hypotheses,
        model_estimated_uncertainty=scenario.model_estimated_uncertainty,
        candidates=tuple(decisions),
        selection=selection,
        audit=AuditMetadata(
            generated_at=generated_at,
            engine_version=__version__,
            scenario_id=scenario.id,
            uncertainty_source=scenario.fixture_note,
        ),
    )
