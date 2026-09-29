from __future__ import annotations

import json
import random
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

from sentinel.decision.v2 import build_decision_bundle_v2
from sentinel.decision.v3 import execute_with_recovery
from sentinel.domain.actions import apply_intervention
from sentinel.domain.decision import DecisionOutcome
from sentinel.domain.execution import RecoveryOutcome
from sentinel.evaluation.config import BenchmarkV3Config, ControllerConfig, ControllerV3Config, canonical_hash, sha256_file
from sentinel.evaluation.sealed import _bootstrap_ci, _oracle, _selected_candidate
from sentinel.execution.adapter import execute_independently
from sentinel.execution.calibration import build_calibration_report
from sentinel.execution.estimator import estimate_execution_state
from sentinel.execution.observation import observe_execution
from sentinel.policy.engine import PolicyDecision
from sentinel.scenarios.generator_v3 import GeneratedScenario, generate_recovery_partition
from sentinel.simulator.engine import simulate_intervention


METHODS=("v2-immediate-escalation","naive-retry","fixed-fallback","v3-state-estimation-recovery")


@dataclass(frozen=True)
class RecoveryRecord:
    seed:int; method:str; true_attack:bool; initial_action:str|None; final_resolution:str
    initial_mismatch:int; estimation_action_correct:int|None; estimation_residual_correct:int|None; estimation_critical_correct:int|None
    false_confident_success:int|None; recovery_steps:int; recovery_success:int|None; escalation:int; unnecessary_escalation:int
    cumulative_operational_cost:float; final_residual_risk:int; mismatch_detection_delay:int|None; recovery_regret:float; policy_violation:int


def _cost(outcome,weights):
    return weights.disrupted_service*outcome.services_disrupted+weights.impacted_user*outcome.users_impacted+(0 if outcome.payroll_available else weights.payroll_outage)


def _score(pre_paths,residual,cost,weights):
    security=weights.attack_path_reduction*((pre_paths-residual)/max(1,pre_paths))-weights.residual_attack_reachability*(residual/max(1,pre_paths))
    return security-cost


def _baseline(generated:GeneratedScenario,method:str,config:ControllerV3Config,seed:int)->RecoveryRecord:
    bundle=build_decision_bundle_v2(generated.definition,config.controller_v2); weights=config.controller_v2.utility_weights
    selected=_selected_candidate(bundle,bundle.selection)
    oracle_total,_,_,_=_oracle(generated,bundle,seed,weights)
    if not selected:
        residual=generated.metadata.hidden_attack_paths
        return RecoveryRecord(generated.metadata.seed,method,generated.metadata.true_attack,None,"ESCALATED" if generated.metadata.true_attack else "ACCEPTED",0,None,None,None,None,0,None,int(generated.metadata.true_attack),0,0.0,residual,None,round(max(0,oracle_total),4),0)
    actual=generated.definition.world.clone(); prediction=selected.simulation
    hidden=execute_independently(actual,selected.candidate.intervention,seed)
    if hidden.action_applied_fully: apply_intervention(actual,selected.candidate.intervention)
    observations=observe_execution(selected.candidate.intervention,hidden,seed)
    estimate=estimate_execution_state(selected.candidate.intervention,prediction,observations,config.estimator)
    mismatch=int((not hidden.action_applied_fully) or hidden.residual_attack_paths!=prediction.security.remaining_attack_paths or hidden.payroll_available!=prediction.operations.payroll_available)
    action_correct=int((estimate.action_applied_probability>=.5)==hidden.action_applied_fully)
    residual_correct=int((estimate.estimated_residual_attack_paths==0)==(hidden.residual_attack_paths==0))
    critical_correct=int((estimate.critical_service_available_probability>=.5)==hidden.payroll_available)
    false_conf=int((estimate.action_applied_probability>=config.estimator.confirmed_threshold and not hidden.action_applied_fully) or (estimate.estimated_residual_attack_paths==0 and hidden.residual_attack_paths>0))
    outcomes=[hidden]; policy_violation=0; escalation=0; delay=0 if mismatch and estimate.contradicted_predictions else None
    negative=bool(estimate.contradicted_predictions or estimate.estimated_residual_attack_paths>0)
    if mismatch and method=="v2-immediate-escalation": escalation=1
    elif negative and method in ("naive-retry","fixed-fallback"):
        if method=="naive-retry": second=selected
        else:
            allowed=[item for item in bundle.candidates if item.policy.decision is PolicyDecision.ALLOW and item.candidate.intervention.action != selected.candidate.intervention.action]
            second=next((item for item in allowed if item.candidate.intervention.action.value=="ISOLATE_HOST"),allowed[0] if allowed else None)
        if second is None: escalation=1
        else:
            policy_violation+=int(second.policy.decision is PolicyDecision.DENY)
            hidden2=execute_independently(actual,second.candidate.intervention,seed+101)
            if hidden2.action_applied_fully: apply_intervention(actual,second.candidate.intervention)
            outcomes.append(hidden2)
    final=outcomes[-1]; cumulative=sum(_cost(item,weights) for item in outcomes)
    success=int(final.residual_attack_paths==0 and final.payroll_available) if mismatch and len(outcomes)>1 else None
    unnecessary=int(escalation and hidden.residual_attack_paths==0 and hidden.payroll_available)
    total=_score(generated.metadata.hidden_attack_paths,final.residual_attack_paths,cumulative,weights)
    resolution="ESCALATED" if escalation else ("RESOLVED" if final.residual_attack_paths==0 and final.payroll_available else "UNRESOLVED")
    return RecoveryRecord(generated.metadata.seed,method,generated.metadata.true_attack,selected.candidate.intervention.action.value,resolution,mismatch,action_correct,residual_correct,critical_correct,false_conf,max(0,len(outcomes)-1),success,escalation,unnecessary,round(cumulative,4),final.residual_attack_paths,delay,round(max(0,oracle_total-total),4),policy_violation)


def _v3(generated:GeneratedScenario,config:ControllerV3Config,seed:int)->tuple[RecoveryRecord,dict]:
    run=execute_with_recovery(generated.definition,config,seed); bundle=run.bundle; weights=config.controller_v2.utility_weights
    selected=_selected_candidate(bundle,bundle.selection); oracle_total,_,_,_=_oracle(generated,bundle,seed,weights)
    if not run.hidden_outcomes:
        residual=generated.metadata.hidden_attack_paths; escalation=int(generated.metadata.true_attack)
        record=RecoveryRecord(generated.metadata.seed,METHODS[-1],generated.metadata.true_attack,None,"ESCALATED" if escalation else "ACCEPTED",0,None,None,None,None,0,None,escalation,0,0.0,residual,None,round(max(0,oracle_total),4),0)
        return record,bundle.model_dump(mode="json")
    first_hidden=run.hidden_outcomes[0]; first_prediction=selected.simulation; first_step=bundle.adaptive_resolution.steps[0]; estimate=first_step.state_estimate
    mismatch=int((not first_hidden.action_applied_fully) or first_hidden.residual_attack_paths!=first_prediction.security.remaining_attack_paths or first_hidden.payroll_available!=first_prediction.operations.payroll_available)
    action_correct=int((estimate.action_applied_probability>=.5)==first_hidden.action_applied_fully)
    residual_correct=int((estimate.estimated_residual_attack_paths==0)==(first_hidden.residual_attack_paths==0))
    critical_correct=int((estimate.critical_service_available_probability>=.5)==first_hidden.payroll_available)
    false_conf=int((estimate.action_applied_probability>=config.estimator.confirmed_threshold and not first_hidden.action_applied_fully) or (estimate.estimated_residual_attack_paths==0 and first_hidden.residual_attack_paths>0))
    adaptive=bundle.adaptive_resolution; escalation=int(adaptive.escalation_required); success=int(run.final_hidden_residual_paths==0 and run.final_hidden_critical_available) if mismatch and adaptive.replan_count>0 else None
    unnecessary=int(escalation and first_hidden.residual_attack_paths==0 and first_hidden.payroll_available)
    total=_score(generated.metadata.hidden_attack_paths,run.final_hidden_residual_paths,adaptive.cumulative_operational_cost,weights)
    record=RecoveryRecord(generated.metadata.seed,METHODS[-1],generated.metadata.true_attack,selected.candidate.intervention.action.value,adaptive.final_resolution,mismatch,action_correct,residual_correct,critical_correct,false_conf,adaptive.replan_count,success,escalation,unnecessary,adaptive.cumulative_operational_cost,run.final_hidden_residual_paths,run.mismatch_detected_at_step,round(max(0,oracle_total-total),4),0)
    return record,bundle.model_dump(mode="json")


def summarize(records,benchmark):
    result=[]
    for method in METHODS:
        rows=[r for r in records if r.method==method]; mismatched=[r for r in rows if r.initial_mismatch]; recovered=[r for r in rows if r.recovery_success is not None]; estimates=[r for r in rows if r.estimation_action_correct is not None]
        detected=[r for r in mismatched if r.mismatch_detection_delay is not None]
        result.append({"method":method,"n":len(rows),"initial_mismatch_rate":round(sum(r.initial_mismatch for r in rows)/len(rows),4),"action_state_accuracy":round(sum(r.estimation_action_correct for r in estimates)/max(1,len(estimates)),4),"residual_state_accuracy":round(sum(r.estimation_residual_correct for r in estimates)/max(1,len(estimates)),4),"critical_state_accuracy":round(sum(r.estimation_critical_correct for r in estimates)/max(1,len(estimates)),4),"false_confident_success_rate":round(sum(r.false_confident_success for r in estimates)/max(1,len(estimates)),4),"mismatch_detection_rate":round(len(detected)/max(1,len(mismatched)),4),"recovery_success_rate":round(sum(r.recovery_success for r in recovered)/max(1,len(recovered)),4),"escalation_rate":round(sum(r.escalation for r in rows)/len(rows),4),"unnecessary_escalation_rate":round(sum(r.unnecessary_escalation for r in rows)/len(rows),4),"mean_cumulative_operational_cost":round(sum(r.cumulative_operational_cost for r in rows)/len(rows),4),"mean_final_residual_risk":round(sum(r.final_residual_risk for r in rows)/len(rows),4),"mean_recovery_steps":round(sum(r.recovery_steps for r in rows)/len(rows),4),"mean_mismatch_detection_delay":round(sum(r.mismatch_detection_delay for r in detected)/max(1,len(detected)),4),"final_resolution_rate":round(sum(r.final_resolution=="RESOLVED" for r in rows)/len(rows),4),"mean_recovery_regret":round(sum(r.recovery_regret for r in rows)/len(rows),4),"recovery_regret_95ci":_bootstrap_ci([r.recovery_regret for r in rows],benchmark.bootstrap_samples,benchmark.bootstrap_seed),"policy_violation_rate":round(sum(r.policy_violation for r in rows)/len(rows),4)})
    return result


def run_v3(v1:ControllerConfig,v3:ControllerV3Config,benchmark:BenchmarkV3Config):
    test=generate_recovery_partition("test",benchmark.test_seed_start,benchmark.test_count,v1); records=[]; bundles=[]
    for generated in test:
        seed=benchmark.execution_seed_offset+generated.metadata.seed*10
        for method in METHODS[:-1]: records.append(_baseline(generated,method,v3,seed))
        record,bundle=_v3(generated,v3,seed); records.append(record); bundles.append(bundle)
    return test,records,summarize(records,benchmark),bundles


def write_v3_artifacts(output:Path,v1:ControllerConfig,v3:ControllerV3Config,benchmark:BenchmarkV3Config):
    output.mkdir(parents=True,exist_ok=True); test,records,summary,bundles=run_v3(v1,v3,benchmark)
    train=build_calibration_report("train",7000,60,v1,1000000); dev=build_calibration_report("dev",8000,40,v1,1000000)
    files={name:output/name for name in ("manifest.json","calibration-corpus.json","scenario-metadata.json","per-scenario-results.json","aggregate-metrics.json","failure-taxonomy.json","decision-bundles.json")}
    manifest={"benchmark_version":benchmark.version,"generator_version":benchmark.generator_version,"controller_v3_sha256":sha256_file(Path(benchmark.controller_v3_config)),"benchmark_config_sha256":sha256_file(Path("configs/sealed-benchmark-v3.json")),"test_count":len(test),"test_seed_start":benchmark.test_seed_start,"test_scenario_hash":canonical_hash([item.metadata.model_dump(mode="json") for item in test]),"controller_v3_tuned_after_sealed_view":False}
    failures=defaultdict(Counter)
    for r in records:
        if r.false_confident_success: failures[r.method]["false_confident_success"]+=1
        if r.escalation: failures[r.method]["escalation"]+=1
        if r.unnecessary_escalation: failures[r.method]["unnecessary_escalation"]+=1
        if r.final_residual_risk: failures[r.method]["residual_risk"]+=1
    payloads={"manifest.json":manifest,"calibration-corpus.json":{"train":train,"dev":dev},"scenario-metadata.json":[item.metadata.model_dump(mode="json") for item in test],"per-scenario-results.json":[asdict(r) for r in records],"aggregate-metrics.json":summary,"failure-taxonomy.json":{k:dict(v) for k,v in failures.items()},"decision-bundles.json":bundles}
    for name,value in payloads.items(): files[name].write_text(json.dumps(value,indent=2)+"\n")
    return files
