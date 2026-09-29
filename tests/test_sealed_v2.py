from sentinel.evaluation.config import load_benchmark_v2_config, load_controller_config, load_controller_v2_config
from sentinel.evaluation.sealed_v2 import METHODS, run_v2, write_v2_artifacts


def test_sealed_v2_small_run_has_all_methods_and_adaptive_bundle():
    benchmark = load_benchmark_v2_config().model_copy(update={"test_count": 3, "bootstrap_samples": 20})
    test, records, summary, sensitivity, boundaries, strictness, failures, bundles = run_v2(load_controller_config(), load_controller_v2_config(), benchmark)
    assert len(test) == 3
    assert {row.method for row in records} == set(METHODS)
    assert len(records) == 12
    assert len(summary) == 4
    assert len(sensitivity) == 16
    assert len(boundaries["rows"]) == 3
    assert strictness["total_scenarios"] == 3
    assert all(bundle["adaptive_resolution"] for bundle in bundles)


def test_sealed_v2_artifacts_are_reproducible(tmp_path):
    benchmark = load_benchmark_v2_config().model_copy(update={"test_count": 2, "bootstrap_samples": 20})
    first = write_v2_artifacts(tmp_path / "a", load_controller_config(), load_controller_v2_config(), benchmark)
    second = write_v2_artifacts(tmp_path / "b", load_controller_config(), load_controller_v2_config(), benchmark)
    assert first["aggregate-metrics.json"].read_text() == second["aggregate-metrics.json"].read_text()
    assert first["manifest.json"].read_text() == second["manifest.json"].read_text()
