import inspect

from sentinel.decision.engine import build_decision_bundle
from sentinel.evaluation.config import load_controller_config
from sentinel.execution import adapter
from sentinel.execution.adapter import execute_independently
from sentinel.execution.verification import compare_prediction
from sentinel.scenarios.generator import generate_scenario


def test_execution_adapter_does_not_import_prediction_simulator() -> None:
    source = inspect.getsource(adapter)
    assert "sentinel.simulator" not in source
    assert "simulate_intervention" not in source


def test_execution_is_deterministic_by_seed() -> None:
    generated = generate_scenario(3002, "test", load_controller_config())
    intervention = generated.definition.candidates[0].intervention
    assert execute_independently(generated.definition.world, intervention, 733002) == execute_independently(generated.definition.world, intervention, 733002)


def test_verification_detects_seeded_mismatch() -> None:
    generated = generate_scenario(3000, "test", load_controller_config())
    bundle = build_decision_bundle(generated.definition)
    candidate = bundle.candidates[0]
    reports = []
    for seed in range(20):
        observed = execute_independently(generated.definition.world, candidate.candidate.intervention, seed)
        reports.append(compare_prediction(candidate.simulation, observed))
    assert any(report.escalation_required for report in reports)
    assert any(report.status == "VERIFIED" for report in reports)

