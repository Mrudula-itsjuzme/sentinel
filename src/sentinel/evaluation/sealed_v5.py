from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict,dataclass
from pathlib import Path

from sentinel.decision.v2 import build_decision_bundle_v2
from sentinel.decision.v4 import execute_with_selective_recovery
from sentinel.decision.v5 import execute_default_sequence
from sentinel.domain.actions import apply_intervention
from sentinel.domain.decision import DecisionOutcome
from sentinel.evaluation.config import BenchmarkV5Config,ControllerConfig,ControllerV4Config,ControllerV5Config,canonical_hash,sha256_file
from sentinel.evaluation.sealed import _bootstrap_ci,_selected_candidate
from sentinel.evaluation.sequence_planner import bounded_sequence_oracle
from sentinel.execution.adapter import execute_independently
from sentinel.scenarios.generator_v5 import GeneratedScenario,generate_sequence_partition


METHODS=("retry-until-limit","retry-then-fallback-default","fixed-sequence","v4-selective-recovery","structural-switch-controller","optimal-bounded-sequence")


@dataclass(frozen=True)
class SequenceRecord:
    seed:int; pattern:str; method:str; actions:tuple[str,...]; resolved:int; residual_risk:int; operational_cost:float; critical_outage:int; escalation:int; policy_violation:int; steps:int; steps_to_resolution:int|None; sequence_regret:float; structural_switch:int


def _run_record(generated,method,run,oracle_score):
    adaptive=run.bundle.adaptive_resolution; outcomes=run.hidden_outcomes; actions=tuple(step.selection.selected_action for step in adaptive.steps); outage=int(any(not item.payroll_available for item in outcomes)); resolved=int(run.final_hidden_residual_paths==0 and run.final_hidden_critical_available and not outage); cost=adaptive.cumulative_operational_cost; pre=generated.metadata.hidden_attack_paths; weights=None
    # Use oracle score minus realized security-minus-cost; weights match the frozen v2 controller.
    from sentinel.evaluation.config import load_controller_v4_config
    w=load_controller_v4_config().controller_v3.controller_v2.utility_weights
    security=w.attack_path_reduction*((pre-run.final_hidden_residual_paths)/max(1,pre))-w.residual_attack_reachability*(run.final_hidden_residual_paths/max(1,pre)); score=security-cost
    switched=int(any(step.recovery_decision and step.recovery_decision.structural_switch_evidence for step in adaptive.steps))
    return SequenceRecord(generated.metadata.seed,generated.metadata.sequence_pattern,method,actions,resolved,run.final_hidden_residual_paths,cost,outage,int(adaptive.escalation_required),0,len(outcomes),len(outcomes) if resolved else None,round(max(0,oracle_score-score),4),switched)


def _fixed_sequence(generated:GeneratedScenario,controller:ControllerV4Config,v5:ControllerV5Config,seed:int,oracle_score:float):
    bundle=build_decision_bundle_v2(generated.definition,controller.controller_v3.controller_v2); selected=_selected_candidate(bundle,bundle.selection)
    if not selected:
        resolved=int(generated.metadata.hidden_attack_paths==0)
        return SequenceRecord(generated.metadata.seed,generated.metadata.sequence_pattern,"fixed-sequence",(),resolved,generated.metadata.hidden_attack_paths,0,0,int(not resolved),0,0,0 if resolved else None,round(max(0,oracle_score),4),0)
    order=[selected]
    for action in ("REVOKE_SESSION","RESTRICT_CONNECTION","ISOLATE_HOST"):
        item=next((candidate for candidate in bundle.candidates if candidate.candidate.intervention.action.value==action and candidate is not selected),None)
        if item and item not in order: order.append(item)
    world=generated.definition.world.clone(); outcomes=[]; actions=[]; cost=0.0; weights=controller.controller_v3.controller_v2.utility_weights
    for index,item in enumerate(order[:v5.maximum_sequence_steps]):
        hidden=execute_independently(world,item.candidate.intervention,seed+index*101); outcomes.append(hidden); actions.append(item.candidate.intervention.action.value); cost+=weights.disrupted_service*hidden.services_disrupted+weights.impacted_user*hidden.users_impacted+(0 if hidden.payroll_available else weights.payroll_outage)
        if hidden.action_applied_fully: apply_intervention(world,item.candidate.intervention)
        if hidden.residual_attack_paths==0 and hidden.payroll_available: break
    final=outcomes[-1]; outage=int(any(not item.payroll_available for item in outcomes)); resolved=int(final.residual_attack_paths==0 and final.payroll_available and not outage); pre=generated.metadata.hidden_attack_paths; score=weights.attack_path_reduction*((pre-final.residual_attack_paths)/max(1,pre))-weights.residual_attack_reachability*(final.residual_attack_paths/max(1,pre))-cost
    return SequenceRecord(generated.metadata.seed,generated.metadata.sequence_pattern,"fixed-sequence",tuple(actions),resolved,final.residual_attack_paths,round(cost,4),outage,int(not resolved),0,len(outcomes),len(outcomes) if resolved else None,round(max(0,oracle_score-score),4),0)


def _oracle_record(generated,plan):
    return SequenceRecord(generated.metadata.seed,generated.metadata.sequence_pattern,"optimal-bounded-sequence",tuple(action for action,_ in plan.actions),int(plan.resolved),plan.final_residual_paths,plan.cumulative_operational_cost,int(plan.critical_outage),int(not plan.resolved),int(not plan.policy_compliant),plan.steps,plan.steps if plan.resolved else None,0.0,0)


def _summary(records,benchmark):
    rows=[]
    for method in METHODS:
        subset=[r for r in records if r.method==method]; resolved_steps=[r.steps_to_resolution for r in subset if r.steps_to_resolution is not None]
        rows.append({"method":method,"n":len(subset),"recovery_success_rate":round(sum(r.resolved for r in subset)/len(subset),4),"final_resolution_rate":round(sum(r.resolved for r in subset)/len(subset),4),"mean_residual_risk":round(sum(r.residual_risk for r in subset)/len(subset),4),"mean_cumulative_cost":round(sum(r.operational_cost for r in subset)/len(subset),4),"critical_outage_rate":round(sum(r.critical_outage for r in subset)/len(subset),4),"escalation_rate":round(sum(r.escalation for r in subset)/len(subset),4),"policy_violation_rate":round(sum(r.policy_violation for r in subset)/len(subset),4),"mean_steps":round(sum(r.steps for r in subset)/len(subset),4),"mean_steps_to_resolution":round(sum(resolved_steps)/max(1,len(resolved_steps)),4),"mean_sequence_regret":round(sum(r.sequence_regret for r in subset)/len(subset),4),"sequence_regret_95ci":_bootstrap_ci([r.sequence_regret for r in subset],benchmark.bootstrap_samples,benchmark.bootstrap_seed),"structural_switch_rate":round(sum(r.structural_switch for r in subset)/len(subset),4)})
    return rows


def run_v5(v1:ControllerConfig,v4:ControllerV4Config,v5:ControllerV5Config,benchmark:BenchmarkV5Config):
    test=generate_sequence_partition("test",benchmark.test_seed_start,benchmark.test_count,v1); records=[]; bundles=[]; attributions=Counter(); oracle_details=[]
    for generated in test:
        seed=benchmark.execution_seed_offset+generated.metadata.seed*10; oracle,plans=bounded_sequence_oracle(generated,v4,v5,seed); oracle_details.append(asdict(oracle))
        retry_v5=v5.model_copy(update={"maximum_retries":2})
        run=execute_default_sequence(generated.definition,v4,retry_v5,seed,enable_structural_switch=False); records.append(_run_record(generated,"retry-until-limit",run,oracle.score))
        default=execute_default_sequence(generated.definition,v4,v5,seed,enable_structural_switch=False); records.append(_run_record(generated,"retry-then-fallback-default",default,oracle.score))
        records.append(_fixed_sequence(generated,v4,v5,seed,oracle.score))
        v4run=execute_with_selective_recovery(generated.definition,v4,seed); records.append(_run_record(generated,"v4-selective-recovery",v4run,oracle.score))
        structural=execute_default_sequence(generated.definition,v4,v5,seed,enable_structural_switch=True); structural_record=_run_record(generated,"structural-switch-controller",structural,oracle.score); records.append(structural_record); bundles.append(structural.bundle.model_dump(mode="json"))
        records.append(_oracle_record(generated,oracle))
        if structural_record.sequence_regret>0:
            if not oracle.resolved: attributions["insufficient_action_horizon"]+=1
            if generated.metadata.alternate_path_present: attributions["hidden_alternate_path"]+=1
            if any(not item.action_applied_fully for item in structural.hidden_outcomes): attributions["execution_failure"]+=1
            if structural_record.actions!=tuple(action for action,_ in oracle.actions): attributions["wrong_sequence"]+=1
            if structural_record.escalation and oracle.resolved: attributions["unnecessary_escalation"]+=1
            if generated.metadata.sequence_pattern in ("session-persistence","true-escalation") and not oracle.resolved: attributions["missing_action"]+=1
            first=structural.bundle.adaptive_resolution.steps[0] if structural.bundle.adaptive_resolution.steps else None
            if first and first.state_estimate and bool(first.state_estimate.estimated_residual_attack_paths)!=(structural.hidden_outcomes[0].residual_attack_paths>0): attributions["bad_state_estimate"]+=1
            if any(not plan.policy_compliant and plan.score>oracle.score for plan in plans): attributions["policy_restriction"]+=1
    return test,records,_summary(records,benchmark),dict(attributions),bundles,oracle_details


def write_v5_artifacts(output:Path,v1:ControllerConfig,v4:ControllerV4Config,v5:ControllerV5Config,benchmark:BenchmarkV5Config):
    output.mkdir(parents=True,exist_ok=True); test,records,summary,failures,bundles,oracle=run_v5(v1,v4,v5,benchmark)
    files={name:output/name for name in ("manifest.json","scenario-metadata.json","per-scenario-results.json","aggregate-metrics.json","sequence-oracle.json","failure-attribution.json","decision-bundles.json")}
    manifest={"benchmark_version":benchmark.version,"generator_version":benchmark.generator_version,"controller_v5_sha256":sha256_file(Path(benchmark.controller_v5_config)),"benchmark_config_sha256":sha256_file(Path("configs/sealed-benchmark-v5.json")),"test_count":len(test),"test_seed_start":benchmark.test_seed_start,"test_scenario_hash":canonical_hash([item.metadata.model_dump(mode="json") for item in test]),"controller_v5_tuned_after_sealed_view":False}
    payloads={"manifest.json":manifest,"scenario-metadata.json":[item.metadata.model_dump(mode="json") for item in test],"per-scenario-results.json":[asdict(item) for item in records],"aggregate-metrics.json":summary,"sequence-oracle.json":oracle,"failure-attribution.json":failures,"decision-bundles.json":bundles}
    for name,value in payloads.items(): files[name].write_text(json.dumps(value,indent=2)+"\n")
    return files
