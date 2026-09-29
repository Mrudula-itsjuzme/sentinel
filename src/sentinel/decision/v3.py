from __future__ import annotations

from dataclasses import dataclass

from sentinel.decision.utility import calculate_utility
from sentinel.decision.v2 import _rank, build_decision_bundle_v2
from sentinel.domain.actions import apply_intervention
from sentinel.domain.decision import AdaptiveDecisionStep, DecisionBundle, DecisionOutcome, DecisionSelection
from sentinel.domain.execution import ExecutionStateEstimate, ObservedExecutionOutcome, RecoveryDecision, RecoveryOutcome
from sentinel.evaluation.config import ControllerV3Config
from sentinel.execution.adapter import execute_independently
from sentinel.execution.estimator import estimate_execution_state
from sentinel.execution.observation import observe_execution
from sentinel.policy.v2 import evaluate_policy_v2
from sentinel.scenarios.suite import ScenarioDefinition
from sentinel.simulator.engine import simulate_intervention
from sentinel.simulator.reachability import attack_paths


@dataclass(frozen=True)
class RecoveryRun:
    bundle: DecisionBundle
    hidden_outcomes: tuple[ObservedExecutionOutcome, ...]
    final_hidden_residual_paths: int
    final_hidden_critical_available: bool
    mismatch_detected_at_step: int | None


def _operational_cost(outcome: ObservedExecutionOutcome, config: ControllerV3Config) -> float:
    weights=config.controller_v2.utility_weights
    return weights.disrupted_service*outcome.services_disrupted+weights.impacted_user*outcome.users_impacted+(0 if outcome.payroll_available else weights.payroll_outage)


def _authorized_alternatives(bundle: DecisionBundle, belief_world, attempted, config: ControllerV3Config):
    paths=attack_paths(belief_world); sensitive=len({p[-1] for p in paths}); revised=[]
    for original in bundle.candidates:
        key=(original.candidate.intervention.action.value,original.candidate.intervention.target)
        if key in attempted: continue
        simulation=simulate_intervention(belief_world,original.candidate.intervention)
        policy=evaluate_policy_v2(simulation,original.candidate,pre_attack_paths=len(paths),verification_available=True,config=config.controller_v2)
        utility=calculate_utility(pre_attack_paths=len(paths),pre_sensitive_assets=sensitive,candidate=original.candidate,simulation=simulation,policy=policy,weights=config.controller_v2.utility_weights)
        revised.append(original.model_copy(update={"simulation":simulation,"policy":policy,"utility":utility,"pre_action_attack_paths":len(paths),"pre_action_sensitive_assets_reachable":sensitive}))
    return _rank(revised)


def _recovery_decision(estimate: ExecutionStateEstimate, current, alternatives, cumulative_cost: float, config: ControllerV3Config) -> RecoveryDecision:
    recovery=config.recovery
    if estimate.critical_service_available_probability < recovery.escalate_critical_below_probability:
        return RecoveryDecision(outcome=RecoveryOutcome.ESCALATE,rationale=("Estimated critical-service availability is below the frozen safety threshold.",))
    if cumulative_cost >= recovery.maximum_cumulative_operational_cost:
        return RecoveryDecision(outcome=RecoveryOutcome.ESCALATE,rationale=("Cumulative observed harm reached the frozen bound.",))
    if estimate.residual_risk_confidence < recovery.request_evidence_below_confidence or estimate.unknown_changes:
        return RecoveryDecision(outcome=RecoveryOutcome.REQUEST_MORE_EVIDENCE,rationale=("Post-action state confidence is insufficient for another intervention.",))
    if estimate.estimated_residual_attack_paths == 0 and estimate.action_applied_probability >= config.estimator.contradicted_threshold:
        return RecoveryDecision(outcome=RecoveryOutcome.ACCEPT,rationale=("Observed evidence supports containment without further intervention.",))
    reliability=config.estimator.action_reliability.get(current.candidate.intervention.action.value,0)
    if estimate.action_applied_probability <= config.estimator.contradicted_threshold and reliability >= recovery.retry_minimum_reliability:
        return RecoveryDecision(outcome=RecoveryOutcome.RETRY,selected_action=current.candidate.intervention.action.value,selected_target=current.candidate.intervention.target,rationale=("The action appears unapplied and calibrated retry reliability exceeds threshold.",))
    if alternatives:
        chosen=alternatives[0]
        outcome=RecoveryOutcome.COMPENSATE if estimate.action_applied_probability > config.estimator.contradicted_threshold else RecoveryOutcome.SWITCH_ACTION
        return RecoveryDecision(outcome=outcome,selected_action=chosen.candidate.intervention.action.value,selected_target=chosen.candidate.intervention.target,rationale=("A distinct policy-authorized action has the best positive utility under estimated state.",))
    return RecoveryDecision(outcome=RecoveryOutcome.ESCALATE,rationale=("No policy-authorized bounded recovery remains.",))


def execute_with_recovery(scenario: ScenarioDefinition, config: ControllerV3Config, seed: int) -> RecoveryRun:
    bundle=build_decision_bundle_v2(scenario,config.controller_v2)
    if bundle.selection.outcome is not DecisionOutcome.ACT:
        return RecoveryRun(bundle,(),len(attack_paths(scenario.world)),True,None)
    actual_world=scenario.world.clone(); belief_world=scenario.world.clone(); attempted=set(); steps=[]; hidden_outcomes=[]; cumulative=0.0; selection=bundle.selection; mismatch_step=None; escalation=False
    for step_index in range(config.recovery.maximum_steps+1):
        current=next(item for item in bundle.candidates if item.candidate.intervention.action.value==selection.selected_action and item.candidate.intervention.target==selection.selected_target)
        prediction=simulate_intervention(belief_world,current.candidate.intervention)
        hidden=execute_independently(actual_world,current.candidate.intervention,seed+step_index*101)
        hidden_outcomes.append(hidden); cumulative+=_operational_cost(hidden,config)
        if hidden.action_applied_fully: apply_intervention(actual_world,current.candidate.intervention)
        observations=observe_execution(current.candidate.intervention,hidden,seed+step_index*101)
        estimate=estimate_execution_state(current.candidate.intervention,prediction,observations,config.estimator)
        if estimate.contradicted_predictions and mismatch_step is None: mismatch_step=step_index
        if estimate.action_applied_probability>=config.estimator.confirmed_threshold: apply_intervention(belief_world,current.candidate.intervention)
        attempted.add((selection.selected_action,selection.selected_target))
        alternatives=_authorized_alternatives(bundle,belief_world,attempted,config)
        recovery=_recovery_decision(estimate,current,alternatives,cumulative,config)
        if (
            recovery.outcome is RecoveryOutcome.ESCALATE
            and estimate.critical_service_available_probability < config.recovery.escalate_critical_below_probability
        ):
            recovery=RecoveryDecision(outcome=RecoveryOutcome.REQUEST_MORE_EVIDENCE,rationale=("A single critical-service signal requires corroboration before escalation.",))
        if recovery.outcome is RecoveryOutcome.REQUEST_MORE_EVIDENCE:
            extra=observe_execution(current.candidate.intervention,hidden,seed+step_index*101,collection_step=1)
            observations=(*observations,*extra)
            estimate=estimate_execution_state(current.candidate.intervention,prediction,observations,config.estimator)
            recovery=_recovery_decision(estimate,current,alternatives,cumulative,config)
            if recovery.outcome is RecoveryOutcome.REQUEST_MORE_EVIDENCE:
                recovery=RecoveryDecision(outcome=RecoveryOutcome.ESCALATE,rationale=("A second observation round remained insufficient; bounded recovery escalates.",))
        steps.append(AdaptiveDecisionStep(step=step_index,phase="INITIAL_EXECUTION" if step_index==0 else "RECOVERY_EXECUTION",selection=selection,execution_receipt=observations[0],post_execution_observations=tuple(observations),state_estimate=estimate,recovery_decision=recovery))
        if recovery.outcome is RecoveryOutcome.ACCEPT: break
        if recovery.outcome is RecoveryOutcome.ESCALATE or step_index>=config.recovery.maximum_steps: escalation=True; break
        selection=DecisionSelection(outcome=DecisionOutcome.ACT,selected_action=recovery.selected_action,selected_target=recovery.selected_target,rationale=recovery.rationale)
    final=hidden_outcomes[-1] if hidden_outcomes else None
    adaptive=bundle.adaptive_resolution.model_copy(update={"steps":tuple(steps),"replan_count":max(0,len(steps)-1),"cumulative_operational_cost":round(cumulative,4),"final_residual_attack_paths":final.residual_attack_paths if final else len(attack_paths(actual_world)),"final_resolution":"ESCALATED" if escalation else ("RESOLVED" if final and final.residual_attack_paths==0 and final.payroll_available else "UNRESOLVED"),"escalation_required":escalation})
    bundle=bundle.model_copy(update={"adaptive_resolution":adaptive,"observed_outcome":None,"independent_verification":None})
    return RecoveryRun(bundle,tuple(hidden_outcomes),final.residual_attack_paths if final else len(attack_paths(actual_world)),final.payroll_available if final else True,mismatch_step)
