from __future__ import annotations

from sentinel.decision.v2 import build_decision_bundle_v2
from sentinel.decision.v3 import RecoveryRun,_authorized_alternatives,_operational_cost
from sentinel.domain.actions import ActionType,apply_intervention
from sentinel.domain.decision import AdaptiveDecisionStep,DecisionOutcome,DecisionSelection
from sentinel.domain.execution import RecoveryDecision,RecoveryOutcome
from sentinel.evaluation.config import ControllerV4Config,ControllerV5Config
from sentinel.execution.adapter import execute_independently
from sentinel.execution.estimator import estimate_execution_state
from sentinel.execution.observation import observe_execution
from sentinel.scenarios.suite import ScenarioDefinition
from sentinel.simulator.engine import simulate_intervention
from sentinel.simulator.reachability import attack_paths,typed_attack_paths


def _path_targeted(path:dict,intervention,world)->bool:
    action=intervention.action
    if action is ActionType.ISOLATE_HOST: return path["hosts"][0]==intervention.target
    if action is ActionType.BLOCK_SMB: return any(world.connections[item].protocol.value=="SMB" for item in path["connection_ids"])
    if action is ActionType.DISABLE_ACCOUNT: return any(world.connections[item].required_account_id==intervention.target for item in path["connection_ids"])
    if action is ActionType.REVOKE_SESSION: return any(world.connections[item].cached_session_account_id==intervention.target for item in path["connection_ids"])
    if action is ActionType.RESTRICT_CONNECTION: return intervention.target in path["connection_ids"]
    return False


def _structural_switch(current,estimate,belief_before,belief_after,alternatives,v5:ControllerV5Config):
    if estimate.action_applied_probability<v5.confirmed_application_threshold or estimate.residual_risk_confidence<v5.structural_residual_confidence_threshold: return None,()
    before=typed_attack_paths(belief_before); after=typed_attack_paths(belief_after)
    targeted_before=[path for path in before if _path_targeted(path,current.candidate.intervention,belief_before)]
    targeted_after=[path for path in after if _path_targeted(path,current.candidate.intervention,belief_after)]
    distinct=[path for path in after if not _path_targeted(path,current.candidate.intervention,belief_after)]
    if not targeted_before or len(targeted_after)>=len(targeted_before) or not distinct: return None,()
    ordered=sorted(alternatives,key=lambda item:(item.simulation.security.remaining_attack_paths,item.utility.operational_cost,item.candidate.intervention.action.value,item.candidate.intervention.target))
    for alternative in ordered:
        prediction=alternative.simulation
        if prediction.security.remaining_attack_paths<len(after) and alternative.policy.decision.value=="ALLOW":
            kinds=sorted({kind for path in distinct for kind in path["path_kinds"]}); connections=sorted({item for path in distinct for item in path["connection_ids"]})
            evidence=(f"application_probability={estimate.action_applied_probability:.4f}",f"targeted_paths_before={len(targeted_before)}",f"targeted_paths_after={len(targeted_after)}",f"distinct_residual_path_kinds={','.join(kinds)}",f"distinct_residual_connections={','.join(connections)}",f"alternative_reduces_paths={len(after)-prediction.security.remaining_attack_paths}")
            return alternative,evidence
    return None,()


def execute_default_sequence(scenario:ScenarioDefinition,v4:ControllerV4Config,v5:ControllerV5Config,seed:int,*,enable_structural_switch:bool=True)->RecoveryRun:
    v3=v4.controller_v3; bundle=build_decision_bundle_v2(scenario,v3.controller_v2)
    if bundle.selection.outcome is not DecisionOutcome.ACT: return RecoveryRun(bundle,(),len(attack_paths(scenario.world)),True,None)
    actual=scenario.world.clone(); belief=scenario.world.clone(); selection=bundle.selection; initial_key=(selection.selected_action,selection.selected_target); attempted=set(); hidden=[]; steps=[]; cumulative=0.0; mismatch_step=None; escalation=False; retry_count=0
    for index in range(v5.maximum_sequence_steps):
        current=next(item for item in bundle.candidates if item.candidate.intervention.action.value==selection.selected_action and item.candidate.intervention.target==selection.selected_target)
        belief_before=belief.clone(); prediction=simulate_intervention(belief,current.candidate.intervention); truth=execute_independently(actual,current.candidate.intervention,seed+index*101); hidden.append(truth); cumulative+=_operational_cost(truth,v3)
        if truth.action_applied_fully: apply_intervention(actual,current.candidate.intervention)
        observations=observe_execution(current.candidate.intervention,truth,seed+index*101); estimate=estimate_execution_state(current.candidate.intervention,prediction,observations,v3.estimator)
        if estimate.contradicted_predictions and mismatch_step is None: mismatch_step=index
        if estimate.action_applied_probability>=v5.confirmed_application_threshold: apply_intervention(belief,current.candidate.intervention)
        key=(selection.selected_action,selection.selected_target); attempted.add(key)
        alternatives=_authorized_alternatives(bundle,belief,attempted,v3)
        if estimate.critical_service_available_probability<.5:
            decision=RecoveryDecision(outcome=RecoveryOutcome.ESCALATE,rationale=("Critical-service telemetry requires escalation.",),rejected_retry_reason="critical-service risk")
        elif estimate.estimated_residual_attack_paths==0:
            decision=RecoveryDecision(outcome=RecoveryOutcome.ACCEPT,rationale=("Verification supports resolution.",),rejected_retry_reason="no residual path")
        else:
            switch,evidence=_structural_switch(current,estimate,belief_before,belief,alternatives,v5) if enable_structural_switch else (None,())
            if index==0 and switch is not None:
                decision=RecoveryDecision(outcome=RecoveryOutcome.SWITCH_ACTION,selected_action=switch.candidate.intervention.action.value,selected_target=switch.candidate.intervention.target,rationale=("Narrow structural-switch condition passed; deviate from retry default.",),rejected_retry_reason="confirmed distinct residual path",structural_switch_evidence=evidence)
            elif retry_count<v5.maximum_retries:
                retry_count+=1
                decision=RecoveryDecision(outcome=RecoveryOutcome.RETRY,selected_action=current.candidate.intervention.action.value,selected_target=current.candidate.intervention.target,rationale=("Default bounded retry before fallback.",))
            elif alternatives:
                fallback=alternatives[0]
                decision=RecoveryDecision(outcome=RecoveryOutcome.COMPENSATE,selected_action=fallback.candidate.intervention.action.value,selected_target=fallback.candidate.intervention.target,rationale=("Retry exhausted; use best policy-authorized fallback.",),rejected_retry_reason="retry limit reached")
            else:
                decision=RecoveryDecision(outcome=RecoveryOutcome.ESCALATE,rationale=("Retry exhausted and no authorized fallback remains.",),rejected_retry_reason="no fallback")
        steps.append(AdaptiveDecisionStep(step=index,phase="INITIAL_EXECUTION" if index==0 else "SEQUENCE_RECOVERY",selection=selection,execution_receipt=observations[0],post_execution_observations=observations,state_estimate=estimate,recovery_decision=decision))
        if decision.outcome is RecoveryOutcome.ACCEPT: break
        if decision.outcome is RecoveryOutcome.ESCALATE or index==v5.maximum_sequence_steps-1: escalation=True; break
        selection=DecisionSelection(outcome=DecisionOutcome.ACT,selected_action=decision.selected_action,selected_target=decision.selected_target,rationale=decision.rationale)
    final=hidden[-1] if hidden else None; adaptive=bundle.adaptive_resolution.model_copy(update={"steps":tuple(steps),"replan_count":max(0,len(steps)-1),"cumulative_operational_cost":round(cumulative,4),"final_residual_attack_paths":final.residual_attack_paths if final else len(attack_paths(actual)),"final_resolution":"ESCALATED" if escalation else ("RESOLVED" if final and final.residual_attack_paths==0 and final.payroll_available else "UNRESOLVED"),"escalation_required":escalation})
    return RecoveryRun(bundle.model_copy(update={"adaptive_resolution":adaptive,"observed_outcome":None,"independent_verification":None}),tuple(hidden),final.residual_attack_paths if final else len(attack_paths(actual)),final.payroll_available if final else True,mismatch_step)
