from __future__ import annotations

from dataclasses import dataclass

from sentinel.decision.v2 import build_decision_bundle_v2
from sentinel.decision.v3 import RecoveryRun, _authorized_alternatives, _operational_cost
from sentinel.domain.actions import apply_intervention
from sentinel.domain.decision import AdaptiveDecisionStep, DecisionOutcome, DecisionSelection
from sentinel.domain.execution import ObservationKind, RecoveryDecision, RecoveryOutcome
from sentinel.evaluation.config import ControllerV4Config
from sentinel.execution.adapter import execute_independently
from sentinel.execution.estimator import estimate_execution_state
from sentinel.execution.observation import observe_execution
from sentinel.scenarios.suite import ScenarioDefinition
from sentinel.simulator.engine import simulate_intervention
from sentinel.simulator.reachability import attack_paths


def _target_kind(action: str, critical_uncertain: bool, structural_uncertain: bool) -> ObservationKind:
    if critical_uncertain: return ObservationKind.DEPENDENCY_STATUS
    if structural_uncertain: return ObservationKind.ATTACK_PATH_INDICATOR
    if action == "DISABLE_ACCOUNT": return ObservationKind.AUTHENTICATION_PROBE
    if action == "ISOLATE_HOST": return ObservationKind.ENDPOINT_TELEMETRY
    return ObservationKind.CONNECTIVITY_PROBE


def _evidence_value(estimate, kind: ObservationKind, config: ControllerV4Config) -> float:
    probability={ObservationKind.DEPENDENCY_STATUS:estimate.critical_service_available_probability,ObservationKind.ATTACK_PATH_INDICATOR:estimate.alternate_path_probability,ObservationKind.AUTHENTICATION_PROBE:estimate.credential_invalid_probability,ObservationKind.ENDPOINT_TELEMETRY:estimate.action_applied_probability,ObservationKind.CONNECTIVITY_PROBE:estimate.network_contained_probability}[kind]
    ambiguity=1-abs(2*probability-1)
    contradiction_bonus=(25.0 if kind is ObservationKind.DEPENDENCY_STATUS else 8.0) if estimate.contradicted_predictions else 0.0
    return round(20*ambiguity+contradiction_bonus-config.recovery.evidence_acquisition_cost-config.recovery.evidence_delay_cost,4)


def _choose(estimate,current,alternatives,retries,cumulative,config:ControllerV4Config):
    rules=config.recovery; action=current.candidate.intervention.action.value
    if cumulative>=config.controller_v3.recovery.maximum_cumulative_operational_cost:
        return RecoveryDecision(outcome=RecoveryOutcome.ESCALATE,rationale=("Cumulative harm reached the frozen bound.",),rejected_retry_reason="harm bound")
    critical_uncertain=estimate.critical_service_available_probability<.5
    structural=(estimate.action_applied_probability>=config.controller_v3.estimator.confirmed_threshold and estimate.alternate_path_probability>=rules.structural_switch_alternate_path_probability and estimate.estimated_residual_attack_paths>0)
    kind=_target_kind(action,critical_uncertain,structural)
    value=_evidence_value(estimate,kind,config)
    if (critical_uncertain or estimate.unknown_changes) and value>=rules.targeted_evidence_minimum_value:
        return RecoveryDecision(outcome=RecoveryOutcome.REQUEST_MORE_EVIDENCE,rationale=(f"Targeted {kind.value} expected net decision value {value:.2f}.",),rejected_retry_reason="targeted evidence has positive value")
    if critical_uncertain:
        return RecoveryDecision(outcome=RecoveryOutcome.ESCALATE,rationale=("Corroborated critical-service risk requires escalation.",),rejected_retry_reason="critical-service risk")
    if estimate.estimated_residual_attack_paths==0:
        return RecoveryDecision(outcome=RecoveryOutcome.ACCEPT,rationale=("Estimated containment is complete and critical service remains available.",),rejected_retry_reason="no residual path")
    if structural and alternatives:
        chosen=alternatives[0]
        return RecoveryDecision(outcome=RecoveryOutcome.SWITCH_ACTION,selected_action=chosen.candidate.intervention.action.value,selected_target=chosen.candidate.intervention.target,rationale=("Residual-path evidence indicates structural failure; retry cannot remove the alternate route.",),rejected_retry_reason="structural alternate path")
    if rules.partial_retry_minimum_probability<=estimate.action_applied_probability<=rules.partial_retry_maximum_probability and retries<rules.maximum_retries_per_action:
        return RecoveryDecision(outcome=RecoveryOutcome.RETRY,selected_action=action,selected_target=current.candidate.intervention.target,rationale=("Application appears partial rather than structurally ineffective; one bounded retry is allowed.",))
    if alternatives:
        chosen=alternatives[0]
        return RecoveryDecision(outcome=RecoveryOutcome.COMPENSATE,selected_action=chosen.candidate.intervention.action.value,selected_target=chosen.candidate.intervention.target,rationale=("Retry confidence is outside the partial-success band; use the best authorized alternative.",),rejected_retry_reason="outside partial retry band")
    return RecoveryDecision(outcome=RecoveryOutcome.ESCALATE,rationale=("No authorized bounded recovery remains.",),rejected_retry_reason="no candidate")


def execute_with_selective_recovery(scenario:ScenarioDefinition,config:ControllerV4Config,seed:int)->RecoveryRun:
    v3=config.controller_v3; bundle=build_decision_bundle_v2(scenario,v3.controller_v2)
    if bundle.selection.outcome is not DecisionOutcome.ACT: return RecoveryRun(bundle,(),len(attack_paths(scenario.world)),True,None)
    actual=scenario.world.clone(); belief=scenario.world.clone(); attempted=set(); retries={}; steps=[]; hidden=[]; cumulative=0.0; selection=bundle.selection; mismatch_step=None; escalation=False
    for index in range(config.recovery.maximum_steps+1):
        current=next(item for item in bundle.candidates if item.candidate.intervention.action.value==selection.selected_action and item.candidate.intervention.target==selection.selected_target)
        prediction=simulate_intervention(belief,current.candidate.intervention); truth=execute_independently(actual,current.candidate.intervention,seed+index*101); hidden.append(truth); cumulative+=_operational_cost(truth,v3)
        if truth.action_applied_fully: apply_intervention(actual,current.candidate.intervention)
        observations=observe_execution(current.candidate.intervention,truth,seed+index*101); estimate=estimate_execution_state(current.candidate.intervention,prediction,observations,v3.estimator)
        if estimate.contradicted_predictions and mismatch_step is None: mismatch_step=index
        if estimate.action_applied_probability>=v3.estimator.confirmed_threshold: apply_intervention(belief,current.candidate.intervention)
        key=(selection.selected_action,selection.selected_target); alternatives=_authorized_alternatives(bundle,belief,attempted|{key},v3)
        decision=_choose(estimate,current,alternatives,retries.get(key,0),cumulative,config)
        if decision.outcome is RecoveryOutcome.REQUEST_MORE_EVIDENCE:
            target=_target_kind(current.candidate.intervention.action.value,estimate.critical_service_available_probability<.5,estimate.action_applied_probability>=config.controller_v3.estimator.confirmed_threshold and estimate.alternate_path_probability>=config.recovery.structural_switch_alternate_path_probability)
            extra=tuple(item for item in observe_execution(current.candidate.intervention,truth,seed+index*101,collection_step=1) if item.kind is target)
            observations=(*observations,*extra); estimate=estimate_execution_state(current.candidate.intervention,prediction,observations,v3.estimator)
            decision=_choose(estimate,current,alternatives,retries.get(key,0),cumulative,config)
            if decision.outcome is RecoveryOutcome.REQUEST_MORE_EVIDENCE: decision=RecoveryDecision(outcome=RecoveryOutcome.ESCALATE,rationale=("Targeted observation did not resolve the decision boundary.",),rejected_retry_reason="persistent ambiguity")
        steps.append(AdaptiveDecisionStep(step=index,phase="INITIAL_EXECUTION" if index==0 else "RECOVERY_EXECUTION",selection=selection,execution_receipt=observations[0],post_execution_observations=tuple(observations),state_estimate=estimate,recovery_decision=decision))
        if decision.outcome is RecoveryOutcome.ACCEPT: break
        if decision.outcome is RecoveryOutcome.ESCALATE or index>=config.recovery.maximum_steps: escalation=True; break
        if decision.outcome is RecoveryOutcome.RETRY: retries[key]=retries.get(key,0)+1
        else: attempted.add(key)
        selection=DecisionSelection(outcome=DecisionOutcome.ACT,selected_action=decision.selected_action,selected_target=decision.selected_target,rationale=decision.rationale)
    final=hidden[-1] if hidden else None; adaptive=bundle.adaptive_resolution.model_copy(update={"steps":tuple(steps),"replan_count":max(0,len(steps)-1),"cumulative_operational_cost":round(cumulative,4),"final_residual_attack_paths":final.residual_attack_paths if final else len(attack_paths(actual)),"final_resolution":"ESCALATED" if escalation else ("RESOLVED" if final and final.residual_attack_paths==0 and final.payroll_available else "UNRESOLVED"),"escalation_required":escalation})
    return RecoveryRun(bundle.model_copy(update={"adaptive_resolution":adaptive,"observed_outcome":None,"independent_verification":None}),tuple(hidden),final.residual_attack_paths if final else len(attack_paths(actual)),final.payroll_available if final else True,mismatch_step)
