from __future__ import annotations

from collections import Counter

from sentinel.decision.v2 import build_decision_bundle_v2
from sentinel.decision.v3 import execute_with_recovery
from sentinel.domain.actions import apply_intervention
from sentinel.domain.decision import DecisionOutcome
from sentinel.domain.execution import RecoveryOutcome
from sentinel.evaluation.config import ControllerV3Config
from sentinel.execution.adapter import execute_independently
from sentinel.execution.estimator import estimate_execution_state
from sentinel.execution.observation import observe_execution
from sentinel.policy.engine import PolicyDecision
from sentinel.scenarios.generator import GeneratedScenario


def _cost(outcome,weights):
    return weights.disrupted_service*outcome.services_disrupted+weights.impacted_user*outcome.users_impacted+(0 if outcome.payroll_available else weights.payroll_outage)


def _score(pre_paths,residual,cost,weights):
    return weights.attack_path_reduction*((pre_paths-residual)/max(1,pre_paths))-weights.residual_attack_reachability*(residual/max(1,pre_paths))-cost


def replay_recovery_point(generated:GeneratedScenario,config:ControllerV3Config,seed:int)->dict|None:
    bundle=build_decision_bundle_v2(generated.definition,config.controller_v2)
    if bundle.selection.outcome is not DecisionOutcome.ACT: return None
    selected=next(item for item in bundle.candidates if item.candidate.intervention.action.value==bundle.selection.selected_action and item.candidate.intervention.target==bundle.selection.selected_target)
    actual=generated.definition.world.clone(); first=execute_independently(actual,selected.candidate.intervention,seed)
    if first.action_applied_fully: apply_intervention(actual,selected.candidate.intervention)
    mismatch=(not first.action_applied_fully) or first.residual_attack_paths!=selected.simulation.security.remaining_attack_paths or first.payroll_available!=selected.simulation.operations.payroll_available
    if not mismatch: return None
    weights=config.controller_v2.utility_weights; first_cost=_cost(first,weights); options=[]
    options.append({"choice":"ESCALATE","action":None,"score":_score(generated.metadata.hidden_attack_paths,first.residual_attack_paths,first_cost,weights),"residual":first.residual_attack_paths,"critical":first.payroll_available,"policy_allowed":True})
    for index,candidate in enumerate(bundle.candidates):
        hidden=execute_independently(actual,candidate.candidate.intervention,seed+101+index)
        total_cost=first_cost+_cost(hidden,weights)
        options.append({"choice":"RETRY" if candidate is selected else "SWITCH_ACTION","action":candidate.candidate.intervention.action.value,"score":round(_score(generated.metadata.hidden_attack_paths,hidden.residual_attack_paths,total_cost,weights),4),"residual":hidden.residual_attack_paths,"critical":hidden.payroll_available,"policy_allowed":candidate.policy.decision is PolicyDecision.ALLOW,"execution_failed":not hidden.action_applied_fully})
    run=execute_with_recovery(generated.definition,config,seed); step=run.bundle.adaptive_resolution.steps[0]; estimate=step.state_estimate; decision=step.recovery_decision
    oracle=max(options,key=lambda item:(item["score"],item["choice"]=="RETRY"))
    selected_option=next((item for item in options if (decision.outcome is RecoveryOutcome.RETRY and item["choice"]=="RETRY") or (decision.selected_action and item["action"]==decision.selected_action) or (decision.outcome is RecoveryOutcome.ESCALATE and item["choice"]=="ESCALATE")),options[0])
    action=selected.candidate.intervention.action.value
    def correctness(candidate_estimate):
        return {
        "action_application":(candidate_estimate.action_applied_probability>=.5)==first.action_applied_fully,
        "network_reachability":True if action=="DISABLE_ACCOUNT" else (candidate_estimate.network_contained_probability>=.5)==(first.residual_attack_paths==0),
        "credential_validity":True if action!="DISABLE_ACCOUNT" else (candidate_estimate.credential_invalid_probability>=.5)==(first.action_applied_fully and not first.faults.credential_rotation_failure),
        "service_health":(candidate_estimate.service_healthy_probability>=.5)==(first.services_disrupted==0),
        "critical_service":(candidate_estimate.critical_service_available_probability>=.5)==first.payroll_available,
        "alternate_path":(candidate_estimate.alternate_path_probability>=.5)==first.faults.unknown_alternate_path,
        "business_dependency":(candidate_estimate.business_dependency_available_probability>=.5)==first.payroll_available,
        }
    component_correct=correctness(estimate)
    base_observations=step.post_execution_observations
    extra_observations=observe_execution(selected.candidate.intervention,first,seed,collection_step=1)
    targeted_values={}
    base_errors=sum(not value for value in component_correct.values())
    for kind in ("CONNECTIVITY_PROBE","AUTHENTICATION_PROBE","SERVICE_HEALTH","ENDPOINT_TELEMETRY","ATTACK_PATH_INDICATOR","DEPENDENCY_STATUS"):
        targeted=tuple(item for item in extra_observations if item.kind.value==kind)
        if not targeted: continue
        revised=estimate_execution_state(selected.candidate.intervention,selected.simulation,(*base_observations,*targeted),config.estimator)
        revised_correct=correctness(revised); improvement=base_errors-sum(not value for value in revised_correct.values())
        targeted_values[kind]={"component_errors_removed":improvement,"net_value":round(improvement*10-5,4),"useful":improvement>0}
    estimate_correct=all(component_correct.values())
    labels=[]
    if not estimate_correct: labels.append("incorrect_state_estimate")
    if estimate_correct and selected_option["choice"]!=oracle["choice"]: labels.append("correct_estimate_wrong_recovery_action")
    if selected_option["choice"]==oracle["choice"] and selected_option.get("execution_failed"): labels.append("correct_action_execution_failure")
    if decision.outcome is RecoveryOutcome.ESCALATE and first.residual_attack_paths==0 and first.payroll_available: labels.append("unnecessary_escalation")
    if not oracle["policy_allowed"]: labels.append("policy_blocking_useful_recovery")
    if first.faults.credential_rotation_failure: labels.append("missing_candidate_action")
    if first.faults.unknown_alternate_path or generated.metadata.alternate_path_present: labels.append("hidden_alternate_path")
    if estimate.unknown_changes or estimate.residual_risk_confidence<config.estimator.minimum_residual_confidence: labels.append("insufficient_observation")
    if first.faults.delayed_isolation: labels.append("bad_timing_delayed_effect")
    if oracle["choice"]=="RETRY" and decision.outcome is not RecoveryOutcome.RETRY: labels.append("retry_would_succeed_but_switched")
    predicted_selected=next((item.utility.total_utility for item in bundle.candidates if item.candidate.intervention.action.value==selected_option["action"]),0)
    return {"scenario_id":generated.definition.id,"seed":generated.metadata.seed,"initial_action":selected.candidate.intervention.action.value,"v3_choice":decision.outcome.value,"v3_action":decision.selected_action,"oracle_choice":oracle["choice"],"oracle_action":oracle["action"],"naive_retry_action":selected.candidate.intervention.action.value,"fixed_fallback_action":"ISOLATE_HOST","component_correct":component_correct,"targeted_observation_values":targeted_values,"labels":labels,"options":options,"action_selection_regret":round(max(0,oracle["score"]-selected_option["score"]),4),"state_estimation_regret":round(max(0,oracle["score"]-selected_option["score"]),4) if not estimate_correct else 0.0,"execution_regret":round(max(0,predicted_selected-selected_option["score"]),4),"estimate":estimate.model_dump(mode="json")}


def analyze_recovery_partition(generated,config,execution_offset):
    cases=[]
    for item in generated:
        case=replay_recovery_point(item,config,execution_offset+item.metadata.seed*10)
        if case: cases.append(case)
    labels=Counter(label for case in cases for label in case["labels"]); oracle=Counter(case["oracle_choice"] for case in cases)
    components={name:{"correct":sum(case["component_correct"][name] for case in cases),"total":len(cases),"accuracy":round(sum(case["component_correct"][name] for case in cases)/max(1,len(cases)),4),"mean_regret_when_wrong":round(sum(case["action_selection_regret"] for case in cases if not case["component_correct"][name])/max(1,sum(not case["component_correct"][name] for case in cases)),4)} for name in (cases[0]["component_correct"] if cases else [])}
    observation_kinds=sorted({kind for case in cases for kind in case["targeted_observation_values"]})
    observation_value={kind:{"available_cases":sum(kind in case["targeted_observation_values"] for case in cases),"useful_cases":sum(case["targeted_observation_values"].get(kind,{}).get("useful",False) for case in cases),"mean_net_value":round(sum(case["targeted_observation_values"].get(kind,{}).get("net_value",0) for case in cases if kind in case["targeted_observation_values"])/max(1,sum(kind in case["targeted_observation_values"] for case in cases)),4)} for kind in observation_kinds}
    return {"case_count":len(cases),"failure_labels":dict(labels),"oracle_choices":dict(oracle),"component_analysis":components,"targeted_observation_value":observation_value,"mean_action_selection_regret":round(sum(c["action_selection_regret"] for c in cases)/max(1,len(cases)),4),"mean_state_estimation_regret":round(sum(c["state_estimation_regret"] for c in cases)/max(1,len(cases)),4),"mean_execution_regret":round(sum(c["execution_regret"] for c in cases)/max(1,len(cases)),4),"cases":cases}
