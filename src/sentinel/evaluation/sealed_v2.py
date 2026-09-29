from __future__ import annotations

import json
import os
import random
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, replace
from itertools import product
from pathlib import Path

from sentinel.decision.baselines import Baseline, select_baseline
from sentinel.decision.engine import build_decision_bundle
from sentinel.decision.v2 import build_decision_bundle_v2, execute_and_replan
from sentinel.domain.decision import DecisionOutcome, UtilityWeights
from sentinel.evaluation.config import BenchmarkV2Config, ControllerConfig, ControllerV2Config, canonical_hash, sha256_file
from sentinel.evaluation.sealed import _bootstrap_ci, _observed_score, _oracle, _selected_candidate
from sentinel.execution.adapter import execute_independently
from sentinel.execution.verification import compare_prediction
from sentinel.policy.engine import PolicyDecision
from sentinel.scenarios.generator import GeneratedScenario, acquire_evidence
from sentinel.scenarios.generator_v2 import generate_partition_v2


METHODS = ("sentinel-v1", "sentinel-v2", "policy-only-selection", "minimum-operational-impact")


@dataclass(frozen=True)
class V2Record:
    scenario_id: str
    seed: int
    method: str
    initial_outcome: str
    final_outcome: str
    selected_action: str | None
    true_attack: bool
    unsafe: int
    unsafe_abstention: int
    policy_violation: int
    critical_outage: int
    unnecessary_action: int
    evidence_requested: int
    evidence_useful: int | None
    prediction_mismatch: int | None
    replan_count: int
    recovery_success: int | None
    escalation_required: int
    cumulative_operational_cost: float
    final_residual_risk: int
    intervention_regret: float


def _score_from_outcome(generated, candidate, observed, weights):
    return _observed_score(generated, candidate, observed, weights)


def _evaluate_v1(generated: GeneratedScenario, method: str, v1: ControllerConfig, seed: int) -> tuple[V2Record, object, list[str]]:
    bundle = build_decision_bundle(generated.definition, weights=v1.utility_weights, uncertainty_request_threshold=v1.uncertainty_request_threshold)
    mapping = {"sentinel-v1": Baseline.SENTINEL_COUNTERFACTUAL, "policy-only-selection": Baseline.POLICY_ONLY, "minimum-operational-impact": Baseline.MINIMUM_OPERATIONAL_IMPACT}
    selection = select_baseline(mapping[method], bundle, model_preferred_action=generated.definition.model_preferred_action)
    selected = _selected_candidate(bundle, selection)
    oracle_total, _, _, _ = _oracle(generated, bundle, seed, v1.utility_weights)
    failures = []
    if selected is None:
        unsafe_abstention = int(generated.metadata.true_attack)
        if unsafe_abstention: failures.append("unsafe_abstention")
        if all(item.policy.decision is PolicyDecision.DENY for item in bundle.candidates): failures.append("policy_too_restrictive")
        return V2Record(generated.definition.id, generated.metadata.seed, method, selection.outcome.value, selection.outcome.value, None, generated.metadata.true_attack, unsafe_abstention, unsafe_abstention, 0, 0, 0, int(selection.outcome is DecisionOutcome.REQUEST_MORE_EVIDENCE), None, None, 0, None, 0, 0.0, generated.metadata.hidden_attack_paths, round(max(0, oracle_total), 4)), bundle, failures
    index = list(bundle.candidates).index(selected)
    observed = execute_independently(generated.definition.world, selected.candidate.intervention, seed + index)
    verification = compare_prediction(selected.simulation, observed)
    total, _, operations = _score_from_outcome(generated, selected, observed, v1.utility_weights)
    critical = int(not observed.payroll_available)
    unnecessary = int(not generated.metadata.true_attack and operations > 0)
    violation = int(selected.policy.decision is PolicyDecision.DENY)
    unsafe = int(violation or critical or unnecessary or observed.residual_attack_paths > 0)
    if verification.escalation_required: failures.append("execution_mismatch")
    if unnecessary: failures.append("false_positive_intervention")
    return V2Record(generated.definition.id, generated.metadata.seed, method, selection.outcome.value, DecisionOutcome.ACT.value, selected.candidate.intervention.action.value, generated.metadata.true_attack, unsafe, 0, violation, critical, unnecessary, 0, None, int(verification.status == "MISMATCH"), 0, None, int(verification.escalation_required), operations, observed.residual_attack_paths, round(max(0, oracle_total-total), 4)), bundle.model_copy(update={"observed_outcome": observed, "independent_verification": verification}), failures


def _evaluate_v2(generated: GeneratedScenario, config: ControllerV2Config, seed: int) -> tuple[V2Record, object, list[str]]:
    initial = build_decision_bundle_v2(generated.definition, config)
    initial_selection = initial.selection
    requested = int(initial_selection.outcome is DecisionOutcome.REQUEST_MORE_EVIDENCE)
    working_generated, bundle = generated, initial
    useful = None
    if requested:
        working_generated = acquire_evidence(generated, config.evidence_value.resolved_uncertainty)
        bundle = build_decision_bundle_v2(working_generated.definition, config)
        changed = (bundle.selection.outcome, bundle.selection.selected_action) != (initial_selection.outcome, initial_selection.selected_action)
        useful = int(changed and ((generated.metadata.true_attack and bundle.selection.outcome is DecisionOutcome.ACT) or (not generated.metadata.true_attack and bundle.selection.outcome is not DecisionOutcome.ACT)))
        adaptive = bundle.adaptive_resolution.model_copy(update={"initial_decision": initial_selection, "evidence_value": initial.adaptive_resolution.evidence_value, "requested_evidence": initial_selection.evidence_request, "revised_uncertainty": config.evidence_value.resolved_uncertainty, "revised_belief_summary": working_generated.definition.hypotheses[0].statement})
        bundle = bundle.model_copy(update={"adaptive_resolution": adaptive})
    # Evaluation-only oracle uses the same execution seeds and hidden truth, never controller input.
    oracle_total, _, _, _ = _oracle(generated, bundle, seed, config.utility_weights)
    if bundle.selection.outcome is not DecisionOutcome.ACT:
        unsafe_abstention = int(generated.metadata.true_attack)
        failures = ["unsafe_abstention"] if unsafe_abstention else []
        if all(item.policy.decision is PolicyDecision.DENY for item in bundle.candidates): failures.append("policy_too_restrictive")
        return V2Record(generated.definition.id, generated.metadata.seed, "sentinel-v2", initial_selection.outcome.value, bundle.selection.outcome.value, None, generated.metadata.true_attack, unsafe_abstention, unsafe_abstention, 0, 0, 0, requested, useful, None, 0, None, 0, 0.0, generated.metadata.hidden_attack_paths, round(max(0, oracle_total), 4)), bundle, failures
    executed = execute_and_replan(bundle, working_generated.definition, config, seed)
    resolution = executed.adaptive_resolution
    first = resolution.steps[0]
    last = resolution.steps[-1]
    selected = _selected_candidate(executed, first.selection)
    # Regret accounts for the complete intervention sequence rather than only the last action.
    pre_paths = generated.metadata.hidden_attack_paths
    security = config.utility_weights.attack_path_reduction * ((pre_paths - (resolution.final_residual_attack_paths or 0)) / max(pre_paths, 1))
    security -= config.utility_weights.residual_attack_reachability * ((resolution.final_residual_attack_paths or 0) / max(pre_paths, 1))
    total = security - resolution.cumulative_operational_cost
    critical = int(any(step.observed_outcome and not step.observed_outcome.payroll_available for step in resolution.steps))
    unnecessary = int(not generated.metadata.true_attack and resolution.cumulative_operational_cost > 0)
    violation = int(any(_selected_candidate(executed, step.selection).policy.decision is PolicyDecision.DENY for step in resolution.steps if _selected_candidate(executed, step.selection)))
    residual = resolution.final_residual_attack_paths if resolution.final_residual_attack_paths is not None else generated.metadata.hidden_attack_paths
    unsafe = int(violation or critical or unnecessary or residual > 0)
    mismatched = int(any(step.verification and step.verification.status == "MISMATCH" for step in resolution.steps))
    recovery = int(residual == 0 and not critical) if resolution.replan_count > 0 else None
    failures = []
    if mismatched: failures.append("execution_mismatch")
    if mismatched and not recovery: failures.append("replan_failed")
    if resolution.escalation_required: failures.append("escalation_required")
    if unnecessary: failures.append("false_positive_intervention")
    if requested and not useful: failures.append("evidence_request_not_useful")
    return V2Record(generated.definition.id, generated.metadata.seed, "sentinel-v2", initial_selection.outcome.value, DecisionOutcome.ACT.value, first.selection.selected_action, generated.metadata.true_attack, unsafe, 0, violation, critical, unnecessary, requested, useful, mismatched, resolution.replan_count, recovery, int(resolution.escalation_required), resolution.cumulative_operational_cost, residual, round(max(0, oracle_total-total), 4)), executed, failures


def _summary(records: list[V2Record], benchmark: BenchmarkV2Config) -> list[dict]:
    rows = []
    for method in METHODS:
        subset = [r for r in records if r.method == method]
        mismatches = [r for r in subset if r.prediction_mismatch is not None]
        recoveries = [r for r in subset if r.recovery_success is not None]
        requests = [r for r in subset if r.evidence_requested]
        values = [float(r.unsafe) for r in subset]
        regrets = [r.intervention_regret for r in subset]
        rows.append({"method": method, "n": len(subset), "unsafe_rate": round(sum(values)/len(subset),4), "unsafe_rate_95ci": _bootstrap_ci(values, benchmark.bootstrap_samples, benchmark.bootstrap_seed), "unsafe_abstention_rate": round(sum(r.unsafe_abstention for r in subset)/len(subset),4), "policy_violation_rate": round(sum(r.policy_violation for r in subset)/len(subset),4), "critical_outage_rate": round(sum(r.critical_outage for r in subset)/len(subset),4), "evidence_request_rate": round(len(requests)/len(subset),4), "evidence_request_usefulness": round(sum(r.evidence_useful or 0 for r in requests)/max(1,len(requests)),4), "prediction_mismatch_rate": round(sum(r.prediction_mismatch or 0 for r in mismatches)/max(1,len(mismatches)),4), "replanning_success_rate": round(sum(r.recovery_success or 0 for r in recoveries)/max(1,len(recoveries)),4), "mean_replans": round(sum(r.replan_count for r in subset)/len(subset),4), "escalation_rate": round(sum(r.escalation_required for r in subset)/len(subset),4), "mean_cumulative_operational_cost": round(sum(r.cumulative_operational_cost for r in subset)/len(subset),4), "mean_final_residual_risk": round(sum(r.final_residual_risk for r in subset)/len(subset),4), "mean_intervention_regret": round(sum(regrets)/len(subset),4), "mean_intervention_regret_95ci": _bootstrap_ci(regrets, benchmark.bootstrap_samples, benchmark.bootstrap_seed+1)})
    return rows


def _joint_sensitivity(test, base: ControllerV2Config) -> list[dict]:
    base_decisions = [(build_decision_bundle_v2(g.definition, base).selection.outcome.value, build_decision_bundle_v2(g.definition, base).selection.selected_action) for g in test]
    rows = []
    for sec, ops, unc, threshold in product((.75,1.25), repeat=4):
        weights = base.utility_weights.model_dump()
        for key in ("attack_path_reduction","sensitive_exposure_reduction","residual_attack_reachability"): weights[key] *= sec
        for key in ("disrupted_service","impacted_user","downtime_minute","payroll_outage"): weights[key] *= ops
        weights["model_uncertainty"] *= unc
        ev = base.evidence_value.model_copy(update={"minimum_expected_value": base.evidence_value.minimum_expected_value * threshold})
        config = base.model_copy(update={"utility_weights": UtilityWeights(**weights), "evidence_value": ev})
        decisions = [build_decision_bundle_v2(g.definition, config).selection for g in test]
        flips = sum((d.outcome.value,d.selected_action) != original for d,original in zip(decisions,base_decisions))
        rows.append({"security_multiplier":sec,"operations_multiplier":ops,"uncertainty_multiplier":unc,"evidence_threshold_multiplier":threshold,"decision_flip_rate":round(flips/len(test),4),"act_rate":round(sum(d.outcome is DecisionOutcome.ACT for d in decisions)/len(test),4),"request_rate":round(sum(d.outcome is DecisionOutcome.REQUEST_MORE_EVIDENCE for d in decisions)/len(test),4)})
    return rows


def _decision_boundaries(test, config: ControllerV2Config) -> dict:
    rows=[]
    for generated in test:
        bundle=build_decision_bundle_v2(generated.definition,config)
        estimate=bundle.adaptive_resolution.evidence_value
        rows.append({"scenario_id":generated.definition.id,"uncertainty":generated.definition.model_estimated_uncertainty,"outcome":bundle.selection.outcome.value,"action_margin":estimate.current_action_margin,"evidence_net_value":estimate.net_value,"would_change_decision":estimate.decision_changes_if_uncertainty_resolves})
    return {"counts_by_outcome":dict(Counter(r["outcome"] for r in rows)),"near_evidence_boundary":[r for r in rows if abs(r["evidence_net_value"]-config.evidence_value.minimum_expected_value)<=2],"near_action_margin_boundary":[r for r in rows if abs(r["action_margin"]-config.evidence_value.material_action_margin)<=3],"rows":rows}


def _policy_strictness(test, config: ControllerV2Config) -> dict:
    codes=Counter(); scenarios_all_denied=0; contextual=0
    for generated in test:
        bundle=build_decision_bundle_v2(generated.definition,config)
        codes.update(item.policy.code for item in bundle.candidates)
        scenarios_all_denied += int(all(item.policy.decision is PolicyDecision.DENY for item in bundle.candidates))
        contextual += int(any(item.policy.code == "CONTEXTUAL_REVERSIBLE_ALLOW" for item in bundle.candidates))
    return {"candidate_decisions":dict(codes),"all_candidates_denied_scenarios":scenarios_all_denied,"scenarios_with_contextual_allow":contextual,"total_scenarios":len(test)}


def run_v2(v1: ControllerConfig, v2: ControllerV2Config, benchmark: BenchmarkV2Config):
    test = generate_partition_v2(benchmark.test_seed_start, benchmark.test_count, v1)
    records=[]; bundles=[]; failures=defaultdict(Counter)
    for generated in test:
        seed=benchmark.execution_seed_offset+generated.metadata.seed*10
        for method in METHODS:
            if method == "sentinel-v2": record,bundle,labels=_evaluate_v2(generated,v2,seed)
            else: record,bundle,labels=_evaluate_v1(generated,method,v1,seed)
            records.append(record); failures[method].update(labels)
            if method == "sentinel-v2": bundles.append(bundle.model_dump(mode="json"))
    return test,records,_summary(records,benchmark),_joint_sensitivity(test,v2),_decision_boundaries(test,v2),_policy_strictness(test,v2),failures,bundles


def write_v2_artifacts(output: Path, v1: ControllerConfig, v2: ControllerV2Config, benchmark: BenchmarkV2Config) -> dict[str,Path]:
    output.mkdir(parents=True,exist_ok=True)
    test,records,summary,sensitivity,boundaries,strictness,failures,bundles=run_v2(v1,v2,benchmark)
    files={name:output/name for name in ("manifest.json","scenario-metadata.json","per-scenario-results.json","aggregate-metrics.json","joint-sensitivity.json","decision-boundaries.json","policy-strictness.json","failure-taxonomy.json","decision-bundles.json","nemotron-repeatability.json")}
    manifest={"benchmark_version":benchmark.version,"generator_version":benchmark.generator_version,"controller_v1_sha256":sha256_file(Path(benchmark.controller_v1_config)),"controller_v2_sha256":sha256_file(Path(benchmark.controller_v2_config)),"benchmark_config_sha256":sha256_file(Path("configs/sealed-benchmark-v2.json")),"test_count":len(test),"test_seed_start":benchmark.test_seed_start,"test_scenario_hash":canonical_hash([g.metadata.model_dump(mode="json") for g in test]),"controller_v2_tuned_after_sealed_view":False}
    files["manifest.json"].write_text(json.dumps(manifest,indent=2)+"\n")
    files["scenario-metadata.json"].write_text(json.dumps([g.metadata.model_dump(mode="json") for g in test],indent=2)+"\n")
    files["per-scenario-results.json"].write_text(json.dumps([asdict(r) for r in records],indent=2)+"\n")
    files["aggregate-metrics.json"].write_text(json.dumps(summary,indent=2)+"\n")
    files["joint-sensitivity.json"].write_text(json.dumps(sensitivity,indent=2)+"\n")
    files["decision-boundaries.json"].write_text(json.dumps(boundaries,indent=2)+"\n")
    files["policy-strictness.json"].write_text(json.dumps(strictness,indent=2)+"\n")
    files["failure-taxonomy.json"].write_text(json.dumps({k:dict(v) for k,v in failures.items()},indent=2)+"\n")
    files["decision-bundles.json"].write_text(json.dumps(bundles,indent=2)+"\n")
    live=bool(os.getenv("NEBIUS_API_KEY") and os.getenv("NEBIUS_MODEL"))
    files["nemotron-repeatability.json"].write_text(json.dumps({"status":"NOT_RUN" if live else "UNAVAILABLE","reason":"Live trials are isolated from controller tuning; run separately." if live else "NEBIUS_API_KEY and NEBIUS_MODEL were not both present.","synthetic_substitute_used":False},indent=2)+"\n")
    return files
