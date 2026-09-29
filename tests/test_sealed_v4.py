from sentinel.evaluation.config import load_benchmark_v4_config,load_controller_config,load_controller_v4_config
from sentinel.evaluation.sealed_v4 import METHODS,run_v4,write_v4_artifacts


def test_sealed_v4_small_run_and_artifacts(tmp_path):
    benchmark=load_benchmark_v4_config().model_copy(update={"test_count":4,"bootstrap_samples":20})
    test,records,summary,bundles=run_v4(load_controller_config(),load_controller_v4_config(),benchmark)
    assert len(test)==4
    assert len(records)==4*len(METHODS)
    assert {row.method for row in records}==set(METHODS)
    assert len(summary)==len(METHODS)
    files=write_v4_artifacts(tmp_path,load_controller_config(),load_controller_v4_config(),benchmark)
    assert files["regret-decomposition.json"].exists()
    assert files["development-recovery-analysis.json"].exists()
