from __future__ import annotations

import json
from collections import Counter,defaultdict
from dataclasses import asdict,replace
from pathlib import Path

from sentinel.decision.v2 import build_decision_bundle_v2
from sentinel.decision.v3 import execute_with_recovery
from sentinel.decision.v4 import execute_with_selective_recovery
from sentinel.domain.actions import apply_intervention
from sentinel.domain.decision import DecisionOutcome
from sentinel.evaluation.config import BenchmarkV4Config,ControllerConfig,ControllerV4Config,canonical_hash,sha256_file
from sentinel.evaluation.recovery_replay import analyze_recovery_partition,replay_recovery_point
from sentinel.evaluation.sealed import _bootstrap_ci,_oracle,_selected_candidate
from sentinel.evaluation.sealed_v3 import RecoveryRecord,_cost,_score
from sentinel.execution.adapter import execute_independently
from sentinel.execution.estimator import estimate_execution_state
from sentinel.execution.observation import observe_execution
from sentinel.policy.engine import PolicyDecision
from sentinel.scenarios.generator_v3 import generate_recovery_partition


METHODS=("v3-state-estimation-recovery","retry-until-limit","retry-on-partial-success","retry-then-fallback","v4-selective-recovery","recovery-oracle")


def _record_from_run(generated,method,run,config,seed):
    bundle=run.bundle; weights=config.controller_v3.controller_v2.utility_weights; selected=_selected_candidate(bundle,bundle.selection); oracle_total,_,_,_=_oracle(generated,bundle,seed,weights)
    if not run.hidden_outcomes:
        residual=generated.metadata.hidden_attack_paths; escalation=int(generated.metadata.true_attack)
        return RecoveryRecord(generated.metadata.seed,method,generated.metadata.true_attack,None,"ESCALATED" if escalation else "ACCEPTED",0,None,None,None,None,0,None,escalation,0,0.0,residual,None,round(max(0,oracle_total),4),0)
    first=run.hidden_outcomes[0]; prediction=selected.simulation; estimate=bundle.adaptive_resolution.steps[0].state_estimate
    mismatch=int((not first.action_applied_fully) or first.residual_attack_paths!=prediction.security.remaining_attack_paths or first.payroll_available!=prediction.operations.payroll_available)
    action_correct=int((estimate.action_applied_probability>=.5)==first.action_applied_fully); residual_correct=int((estimate.estimated_residual_attack_paths==0)==(first.residual_attack_paths==0)); critical_correct=int((estimate.critical_service_available_probability>=.5)==first.payroll_available)
    false_conf=int((estimate.action_applied_probability>=config.controller_v3.estimator.confirmed_threshold and not first.action_applied_fully) or (estimate.estimated_residual_attack_paths==0 and first.residual_attack_paths>0))
    adaptive=bundle.adaptive_resolution; escalation=int(adaptive.escalation_required); success=int(run.final_hidden_residual_paths==0 and run.final_hidden_critical_available) if mismatch and adaptive.replan_count>0 else None; unnecessary=int(escalation and first.residual_attack_paths==0 and first.payroll_available)
    total=_score(generated.metadata.hidden_attack_paths,run.final_hidden_residual_paths,adaptive.cumulative_operational_cost,weights)
    return RecoveryRecord(generated.metadata.seed,method,generated.metadata.true_attack,selected.candidate.intervention.action.value,adaptive.final_resolution,mismatch,action_correct,residual_correct,critical_correct,false_conf,adaptive.replan_count,success,escalation,unnecessary,adaptive.cumulative_operational_cost,run.final_hidden_residual_paths,run.mismatch_detected_at_step,round(max(0,oracle_total-total),4),0)


def _strong_baseline(generated,method,config,seed):
    v3=config.controller_v3; bundle=build_decision_bundle_v2(generated.definition,v3.controller_v2); selected=_selected_candidate(bundle,bundle.selection); weights=v3.controller_v2.utility_weights; oracle_total,_,_,_=_oracle(generated,bundle,seed,weights)
    if not selected: return RecoveryRecord(generated.metadata.seed,method,generated.metadata.true_attack,None,"ESCALATED" if generated.metadata.true_attack else "ACCEPTED",0,None,None,None,None,0,None,int(generated.metadata.true_attack),0,0.0,generated.metadata.hidden_attack_paths,None,round(max(0,oracle_total),4),0)
    actual=generated.definition.world.clone(); outcomes=[]; current=selected; estimate=None; mismatch=0; policy_violation=0
    max_followups=2
    for step in range(max_followups+1):
        hidden=execute_independently(actual,current.candidate.intervention,seed+step*101); outcomes.append(hidden)
        if hidden.action_applied_fully: apply_intervention(actual,current.candidate.intervention)
        prediction=current.simulation; observations=observe_execution(current.candidate.intervention,hidden,seed+step*101); estimate=estimate_execution_state(current.candidate.intervention,prediction,observations,v3.estimator)
        if step==0: mismatch=int((not hidden.action_applied_fully) or hidden.residual_attack_paths!=prediction.security.remaining_attack_paths or hidden.payroll_available!=prediction.operations.payroll_available); first_estimate=estimate; first_hidden=hidden
        if hidden.residual_attack_paths==0 and hidden.payroll_available: break
        if step>=max_followups: break
        if method=="retry-on-partial-success" and not (.15<=estimate.action_applied_probability<=.8): break
        if method=="retry-then-fallback" and step>=1:
            allowed=[item for item in bundle.candidates if item.policy.decision is PolicyDecision.ALLOW and item.candidate.intervention.action!=selected.candidate.intervention.action]
            if not allowed: break
            current=allowed[0]
        elif method=="recovery-oracle":
            replay=replay_recovery_point(generated,v3,seed)
            if not replay or replay["oracle_choice"]=="ESCALATE": break
            current=next(item for item in bundle.candidates if item.candidate.intervention.action.value==replay["oracle_action"])
        else: current=selected
    final=outcomes[-1]; cumulative=sum(_cost(item,weights) for item in outcomes); success=int(final.residual_attack_paths==0 and final.payroll_available) if mismatch and len(outcomes)>1 else None; total=_score(generated.metadata.hidden_attack_paths,final.residual_attack_paths,cumulative,weights)
    action_correct=int((first_estimate.action_applied_probability>=.5)==first_hidden.action_applied_fully); residual_correct=int((first_estimate.estimated_residual_attack_paths==0)==(first_hidden.residual_attack_paths==0)); critical_correct=int((first_estimate.critical_service_available_probability>=.5)==first_hidden.payroll_available); false_conf=int((first_estimate.action_applied_probability>=v3.estimator.confirmed_threshold and not first_hidden.action_applied_fully) or (first_estimate.estimated_residual_attack_paths==0 and first_hidden.residual_attack_paths>0))
    resolved=final.residual_attack_paths==0 and final.payroll_available; escalation=int(not resolved); unnecessary=int(escalation and first_hidden.residual_attack_paths==0 and first_hidden.payroll_available)
    resolution="RESOLVED" if resolved else "ESCALATED"
    return RecoveryRecord(generated.metadata.seed,method,generated.metadata.true_attack,selected.candidate.intervention.action.value,resolution,mismatch,action_correct,residual_correct,critical_correct,false_conf,max(0,len(outcomes)-1),success,escalation,unnecessary,round(cumulative,4),final.residual_attack_paths,0 if mismatch and first_estimate.contradicted_predictions else None,round(max(0,oracle_total-total),4),policy_violation)


def _summary(records,benchmark):
    result=[]
    for method in METHODS:
        rows=[r for r in records if r.method==method]; estimates=[r for r in rows if r.estimation_action_correct is not None]; mismatches=[r for r in rows if r.initial_mismatch]; recovered=[r for r in rows if r.recovery_success is not None]; detected=[r for r in mismatches if r.mismatch_detection_delay is not None]
        result.append({"method":method,"n":len(rows),"action_state_accuracy":round(sum(r.estimation_action_correct for r in estimates)/max(1,len(estimates)),4),"residual_state_accuracy":round(sum(r.estimation_residual_correct for r in estimates)/max(1,len(estimates)),4),"critical_state_accuracy":round(sum(r.estimation_critical_correct for r in estimates)/max(1,len(estimates)),4),"false_confident_success_rate":round(sum(r.false_confident_success for r in estimates)/max(1,len(estimates)),4),"mismatch_detection_rate":round(len(detected)/max(1,len(mismatches)),4),"recovery_success_rate":round(sum(r.recovery_success for r in recovered)/max(1,len(recovered)),4),"escalation_rate":round(sum(r.escalation for r in rows)/len(rows),4),"unnecessary_escalation_rate":round(sum(r.unnecessary_escalation for r in rows)/len(rows),4),"final_resolution_rate":round(sum(r.final_resolution=="RESOLVED" for r in rows)/len(rows),4),"mean_operational_cost":round(sum(r.cumulative_operational_cost for r in rows)/len(rows),4),"mean_residual_risk":round(sum(r.final_residual_risk for r in rows)/len(rows),4),"mean_recovery_steps":round(sum(r.recovery_steps for r in rows)/len(rows),4),"mean_regret":round(sum(r.recovery_regret for r in rows)/len(rows),4),"regret_95ci":_bootstrap_ci([r.recovery_regret for r in rows],benchmark.bootstrap_samples,benchmark.bootstrap_seed),"policy_violation_rate":round(sum(r.policy_violation for r in rows)/len(rows),4)})
    return result


def run_v4(v1:ControllerConfig,v4:ControllerV4Config,benchmark:BenchmarkV4Config):
    test=generate_recovery_partition("test",benchmark.test_seed_start,benchmark.test_count,v1); records=[]; bundles=[]
    for generated in test:
        seed=benchmark.execution_seed_offset+generated.metadata.seed*10
        records.append(_record_from_run(generated,METHODS[0],execute_with_recovery(generated.definition,v4.controller_v3,seed),v4,seed))
        for method in METHODS[1:4]: records.append(_strong_baseline(generated,method,v4,seed))
        run=execute_with_selective_recovery(generated.definition,v4,seed); records.append(_record_from_run(generated,METHODS[4],run,v4,seed)); bundles.append(run.bundle.model_dump(mode="json"))
        records.append(_strong_baseline(generated,METHODS[5],v4,seed))
    return test,records,_summary(records,benchmark),bundles


def write_v4_artifacts(output:Path,v1:ControllerConfig,v4:ControllerV4Config,benchmark:BenchmarkV4Config):
    output.mkdir(parents=True,exist_ok=True); test,records,summary,bundles=run_v4(v1,v4,benchmark)
    train=analyze_recovery_partition(generate_recovery_partition("train",10000,80,v1),v4.controller_v3,1400000); dev=analyze_recovery_partition(generate_recovery_partition("dev",11000,60,v1),v4.controller_v3,1400000)
    files={name:output/name for name in ("manifest.json","development-recovery-analysis.json","scenario-metadata.json","per-scenario-results.json","aggregate-metrics.json","regret-decomposition.json","failure-taxonomy.json","decision-bundles.json")}
    manifest={"benchmark_version":benchmark.version,"generator_version":benchmark.generator_version,"controller_v4_sha256":sha256_file(Path(benchmark.controller_v4_config)),"benchmark_config_sha256":sha256_file(Path("configs/sealed-benchmark-v4.json")),"test_count":len(test),"test_seed_start":benchmark.test_seed_start,"test_scenario_hash":canonical_hash([item.metadata.model_dump(mode="json") for item in test]),"controller_v4_tuned_after_sealed_view":False}
    replay=analyze_recovery_partition(test,v4.controller_v3,benchmark.execution_seed_offset); failures=Counter(label for case in replay["cases"] for label in case["labels"])
    payloads={"manifest.json":manifest,"development-recovery-analysis.json":{"train":train,"dev":dev},"scenario-metadata.json":[item.metadata.model_dump(mode="json") for item in test],"per-scenario-results.json":[asdict(r) for r in records],"aggregate-metrics.json":summary,"regret-decomposition.json":{k:v for k,v in replay.items() if k!="cases"},"failure-taxonomy.json":dict(failures),"decision-bundles.json":bundles}
    for name,value in payloads.items(): files[name].write_text(json.dumps(value,indent=2)+"\n")
    return files
