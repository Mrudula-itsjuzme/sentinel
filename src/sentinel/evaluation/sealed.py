from __future__ import annotations

import json
import math
import random
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

from sentinel.decision.baselines import Baseline, select_baseline
from sentinel.decision.engine import build_decision_bundle
from sentinel.domain.decision import DecisionBundle, DecisionOutcome, UtilityWeights
from sentinel.evaluation.config import BenchmarkConfig, ControllerConfig, canonical_hash, sha256_file
from sentinel.execution.adapter import execute_independently
from sentinel.execution.verification import compare_prediction
from sentinel.policy.engine import PolicyDecision
from sentinel.scenarios.generator import GeneratedScenario, generate_partition


@dataclass(frozen=True)
class SealedRecord:
    scenario_id: str
    partition: str
    seed: int
    method: str
    outcome: str
    selected_action: str | None
    true_attack: bool
    evidence_quality: str
    unsafe_action: int
    unnecessary_action: int
    policy_violation: int
    critical_outage: int
    residual_attack_paths: int | None
    prediction_mismatch: int | None
    escalation_required: int | None
    intervention_regret: float
    security_regret: float
    operational_regret: float


def _selected_candidate(bundle: DecisionBundle, selection):
    return next((item for item in bundle.candidates if item.candidate.intervention.action.value == selection.selected_action and item.candidate.intervention.target == selection.selected_target), None)


def _observed_score(generated: GeneratedScenario, candidate, observed, weights: UtilityWeights) -> tuple[float, float, float]:
    pre_paths = generated.metadata.hidden_attack_paths
    security = weights.attack_path_reduction * ((pre_paths - observed.residual_attack_paths) / max(pre_paths, 1))
    security -= weights.residual_attack_reachability * (observed.residual_attack_paths / max(pre_paths, 1))
    operations = (
        weights.disrupted_service * observed.services_disrupted
        + weights.impacted_user * observed.users_impacted
        + (0 if observed.payroll_available else weights.payroll_outage)
    )
    policy = 0 if candidate.policy.decision is PolicyDecision.ALLOW else weights.policy_denial
    return security - operations - policy, security, operations


def _oracle(generated: GeneratedScenario, bundle: DecisionBundle, execution_seed: int, weights: UtilityWeights):
    options = [(0.0, 0.0, 0.0, None)]
    for index, candidate in enumerate(bundle.candidates):
        observed = execute_independently(generated.definition.world, candidate.candidate.intervention, execution_seed + index)
        total, security, operations = _observed_score(generated, candidate, observed, weights)
        options.append((total, security, operations, candidate))
    return max(options, key=lambda value: (value[0], str(value[3].candidate.intervention.action.value) if value[3] else ""))


def evaluate_generated(
    generated: GeneratedScenario,
    method: Baseline,
    controller: ControllerConfig,
    execution_seed: int,
) -> tuple[SealedRecord, DecisionBundle, list[str]]:
    scenario = generated.definition
    bundle = build_decision_bundle(
        scenario,
        weights=controller.utility_weights,
        uncertainty_request_threshold=controller.uncertainty_request_threshold,
    )
    selection = select_baseline(method, bundle, model_preferred_action=scenario.model_preferred_action)
    selected = _selected_candidate(bundle, selection)
    oracle_total, oracle_security, oracle_operations, _ = _oracle(generated, bundle, execution_seed, controller.utility_weights)
    failures: list[str] = []
    if selected is None:
        actual_total = actual_security = actual_operations = 0.0
        if generated.metadata.true_attack:
            failures.append("unsafe_abstention_or_defer")
            if all(item.policy.decision is PolicyDecision.DENY for item in bundle.candidates):
                failures.append("policy_too_restrictive")
        record = SealedRecord(
            scenario_id=scenario.id, partition=generated.metadata.partition, seed=generated.metadata.seed,
            method=method.value, outcome=selection.outcome.value, selected_action=None,
            true_attack=generated.metadata.true_attack, evidence_quality=generated.metadata.evidence_quality.value,
            unsafe_action=int(generated.metadata.true_attack), unnecessary_action=0, policy_violation=0,
            critical_outage=0, residual_attack_paths=generated.metadata.hidden_attack_paths,
            prediction_mismatch=None, escalation_required=None,
            intervention_regret=round(max(0.0, oracle_total), 4),
            security_regret=round(max(0.0, oracle_security), 4),
            operational_regret=0.0,
        )
        return record, bundle, failures

    action_index = list(bundle.candidates).index(selected)
    observed = execute_independently(scenario.world, selected.candidate.intervention, execution_seed + action_index)
    verification = compare_prediction(selected.simulation, observed)
    bundle = bundle.model_copy(update={"observed_outcome": observed, "independent_verification": verification})
    actual_total, actual_security, actual_operations = _observed_score(generated, selected, observed, controller.utility_weights)
    policy_violation = int(selected.policy.decision is PolicyDecision.DENY)
    critical = int(not observed.payroll_available)
    unnecessary = int(not generated.metadata.true_attack and (observed.services_disrupted > 0 or observed.users_impacted > 0 or critical))
    unsafe = int(policy_violation or observed.residual_attack_paths > 0 or critical or unnecessary)
    if unnecessary:
        failures.append("wrong_hypothesis_or_false_positive")
    if generated.metadata.false_negative_event and (observed.residual_attack_paths > 0 or selection.outcome is not DecisionOutcome.ACT):
        failures.append("incomplete_evidence")
    if verification.escalation_required:
        failures.append("execution_mismatch")
    if observed.faults.unknown_alternate_path:
        failures.append("hidden_alternate_attack_path")
    if observed.faults.dependency_model_mismatch:
        failures.append("incorrect_business_dependency_model")
    if selected.policy.decision is PolicyDecision.ALLOW and critical:
        failures.append("policy_too_permissive")
    if actual_total < oracle_total and not failures:
        failures.append("utility_or_ranking_regret")
    record = SealedRecord(
        scenario_id=scenario.id, partition=generated.metadata.partition, seed=generated.metadata.seed,
        method=method.value, outcome=DecisionOutcome.ACT.value,
        selected_action=selected.candidate.intervention.action.value,
        true_attack=generated.metadata.true_attack, evidence_quality=generated.metadata.evidence_quality.value,
        unsafe_action=unsafe, unnecessary_action=unnecessary, policy_violation=policy_violation,
        critical_outage=critical, residual_attack_paths=observed.residual_attack_paths,
        prediction_mismatch=int(verification.status == "MISMATCH"),
        escalation_required=int(verification.escalation_required),
        intervention_regret=round(max(0.0, oracle_total - actual_total), 4),
        security_regret=round(max(0.0, oracle_security - actual_security), 4),
        operational_regret=round(max(0.0, actual_operations - oracle_operations), 4),
    )
    return record, bundle, failures


def _bootstrap_ci(values: list[float], samples: int, seed: int) -> tuple[float, float]:
    if not values:
        return (0.0, 0.0)
    rng = random.Random(seed)
    means = sorted(sum(rng.choice(values) for _ in values) / len(values) for _ in range(samples))
    return (round(means[int(samples * 0.025)], 4), round(means[min(samples - 1, int(samples * 0.975))], 4))


def summarize(records: list[SealedRecord], config: BenchmarkConfig) -> list[dict[str, object]]:
    result = []
    for method in Baseline:
        rows = [row for row in records if row.method == method.value]
        unsafe_values = [float(row.unsafe_action) for row in rows]
        regret_values = [row.intervention_regret for row in rows]
        result.append({
            "method": method.value,
            "n": len(rows),
            "unsafe_action_rate": round(sum(unsafe_values) / len(rows), 4),
            "unsafe_action_rate_95ci": _bootstrap_ci(unsafe_values, config.bootstrap_samples, config.bootstrap_seed),
            "policy_violation_rate": round(sum(row.policy_violation for row in rows) / len(rows), 4),
            "critical_outage_rate": round(sum(row.critical_outage for row in rows) / len(rows), 4),
            "unnecessary_action_rate": round(sum(row.unnecessary_action for row in rows) / len(rows), 4),
            "act_rate": round(sum(row.outcome == DecisionOutcome.ACT.value for row in rows) / len(rows), 4),
            "defer_rate": round(sum(row.outcome == DecisionOutcome.DEFER.value for row in rows) / len(rows), 4),
            "evidence_request_rate": round(sum(row.outcome == DecisionOutcome.REQUEST_MORE_EVIDENCE.value for row in rows) / len(rows), 4),
            "unsafe_abstention_rate": round(sum(row.outcome != DecisionOutcome.ACT.value and row.true_attack for row in rows) / len(rows), 4),
            "prediction_mismatch_rate": round(sum(row.prediction_mismatch or 0 for row in rows) / max(1, sum(row.prediction_mismatch is not None for row in rows)), 4),
            "mean_intervention_regret": round(sum(regret_values) / len(rows), 4),
            "mean_intervention_regret_95ci": _bootstrap_ci(regret_values, config.bootstrap_samples, config.bootstrap_seed + 1),
            "mean_security_regret": round(sum(row.security_regret for row in rows) / len(rows), 4),
            "mean_operational_regret": round(sum(row.operational_regret for row in rows) / len(rows), 4),
        })
    return result


def sensitivity_analysis(test: tuple[GeneratedScenario, ...], controller: ControllerConfig, benchmark: BenchmarkConfig) -> list[dict[str, object]]:
    base = {item.definition.id: build_decision_bundle(item.definition, weights=controller.utility_weights, uncertainty_request_threshold=controller.uncertainty_request_threshold).selection for item in test}
    axes = {
        "security_gain": ("attack_path_reduction", "sensitive_exposure_reduction"),
        "operational_disruption": ("disrupted_service", "impacted_user", "downtime_minute", "payroll_outage"),
        "uncertainty": ("model_uncertainty",),
        "residual_risk": ("residual_attack_reachability",),
        "reversibility": ("medium_reversibility", "low_reversibility"),
    }
    rows = []
    defaults = controller.utility_weights.model_dump()
    for axis, fields in axes.items():
        for multiplier in (0.5, 1.5):
            changed = dict(defaults)
            for field in fields:
                changed[field] *= multiplier
            weights = UtilityWeights(**changed)
            flips = unsafe = outages = requests = 0
            for index, item in enumerate(test):
                bundle = build_decision_bundle(item.definition, weights=weights, uncertainty_request_threshold=controller.uncertainty_request_threshold)
                selection = bundle.selection
                original = base[item.definition.id]
                flips += int((selection.outcome, selection.selected_action, selection.selected_target) != (original.outcome, original.selected_action, original.selected_target))
                requests += int(selection.outcome is DecisionOutcome.REQUEST_MORE_EVIDENCE)
                selected = _selected_candidate(bundle, selection)
                if selected:
                    observed = execute_independently(item.definition.world, selected.candidate.intervention, benchmark.execution_seed_offset + item.metadata.seed * 10 + list(bundle.candidates).index(selected))
                    outages += int(not observed.payroll_available)
                    unsafe += int(observed.residual_attack_paths > 0 or not observed.payroll_available)
                elif item.metadata.true_attack:
                    unsafe += 1
            rows.append({"axis": axis, "multiplier": multiplier, "decision_flip_rate": round(flips / len(test), 4), "unsafe_action_rate": round(unsafe / len(test), 4), "critical_outage_rate": round(outages / len(test), 4), "evidence_request_rate": round(requests / len(test), 4)})
    return rows


def run_sealed_benchmark(controller: ControllerConfig, benchmark: BenchmarkConfig):
    partitions = {name: generate_partition(name, spec.start, spec.count, controller) for name, spec in benchmark.partition_seeds.items()}
    records: list[SealedRecord] = []
    bundles: list[dict[str, object]] = []
    failures: dict[str, Counter[str]] = defaultdict(Counter)
    for generated in partitions["test"]:
        for method in Baseline:
            record, bundle, labels = evaluate_generated(generated, method, controller, benchmark.execution_seed_offset + generated.metadata.seed * 10)
            records.append(record)
            failures[method.value].update(labels)
            if method is Baseline.SENTINEL_COUNTERFACTUAL:
                bundles.append(bundle.model_dump(mode="json"))
    return partitions, records, summarize(records, benchmark), sensitivity_analysis(partitions["test"], controller, benchmark), failures, bundles


def write_sealed_artifacts(output_dir: Path, controller: ControllerConfig, benchmark: BenchmarkConfig) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    partitions, records, summary, sensitivity, failures, bundles = run_sealed_benchmark(controller, benchmark)
    manifest = {
        "benchmark_version": benchmark.version,
        "generator_version": benchmark.generator_version,
        "controller_version": controller.version,
        "controller_sha256": sha256_file(Path(benchmark.controller_config)),
        "benchmark_config_sha256": sha256_file(Path("configs/sealed-benchmark-v1.json")),
        "partition_sizes": {name: len(items) for name, items in partitions.items()},
        "partition_seeds": {name: spec.model_dump() for name, spec in benchmark.partition_seeds.items()},
        "test_scenario_hash": canonical_hash([item.metadata.model_dump(mode="json") for item in partitions["test"]]),
        "sealed_test_used_for_tuning": False,
    }
    files = {
        "manifest": output_dir / "manifest.json",
        "scenario_metadata": output_dir / "scenario-metadata.json",
        "results": output_dir / "per-scenario-results.json",
        "aggregate": output_dir / "aggregate-metrics.json",
        "sensitivity": output_dir / "weight-sensitivity.json",
        "prediction": output_dir / "prediction-verification.json",
        "prediction_summary": output_dir / "prediction-error-summary.json",
        "failures": output_dir / "failure-taxonomy.json",
        "bundles": output_dir / "decision-bundles.json",
        "nemotron": output_dir / "nemotron-repeatability.json",
    }
    files["manifest"].write_text(json.dumps(manifest, indent=2) + "\n")
    files["scenario_metadata"].write_text(json.dumps({name: [item.metadata.model_dump(mode="json") for item in items] for name, items in partitions.items()}, indent=2) + "\n")
    files["results"].write_text(json.dumps([asdict(item) for item in records], indent=2) + "\n")
    files["aggregate"].write_text(json.dumps(summary, indent=2) + "\n")
    files["sensitivity"].write_text(json.dumps(sensitivity, indent=2) + "\n")
    verification = [bundle["independent_verification"] for bundle in bundles if bundle["independent_verification"]]
    files["prediction"].write_text(json.dumps(verification, indent=2) + "\n")
    prediction_summary = {
        "executed_actions": len(verification),
        "mismatches": sum(item["status"] == "MISMATCH" for item in verification),
        "mismatch_rate": round(sum(item["status"] == "MISMATCH" for item in verification) / max(1, len(verification)), 4),
        "attack_path_mae": round(sum(abs(item["attack_path_prediction_error"]) for item in verification) / max(1, len(verification)), 4),
        "sensitive_asset_mae": round(sum(abs(item["sensitive_asset_prediction_error"]) for item in verification) / max(1, len(verification)), 4),
        "service_impact_mae": round(sum(abs(item["service_impact_prediction_error"]) for item in verification) / max(1, len(verification)), 4),
        "user_impact_mae": round(sum(abs(item["user_impact_prediction_error"]) for item in verification) / max(1, len(verification)), 4),
        "critical_service_mismatch_rate": round(sum(not item["critical_service_availability_match"] for item in verification) / max(1, len(verification)), 4),
    }
    files["prediction_summary"].write_text(json.dumps(prediction_summary, indent=2) + "\n")
    files["failures"].write_text(
        json.dumps(
            {method: dict(counts.most_common()) for method, counts in failures.items()},
            indent=2,
        ) + "\n"
    )
    files["bundles"].write_text(json.dumps(bundles, indent=2) + "\n")
    files["nemotron"].write_text(json.dumps({"status": "UNAVAILABLE", "reason": "NEBIUS_API_KEY and NEBIUS_MODEL were not available; no fixtures substituted", "trials": 0}, indent=2) + "\n")
    return files
