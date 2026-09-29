from sentinel.evaluation.config import load_benchmark_v5_config,load_controller_config,load_controller_v4_config,load_controller_v5_config
from sentinel.evaluation.sealed_v5 import METHODS,run_v5,write_v5_artifacts


def test_sealed_v5_small_run_and_artifacts(tmp_path):
    benchmark=load_benchmark_v5_config().model_copy(update={"test_count":3,"bootstrap_samples":20})
    test,records,summary,failures,bundles,oracle=run_v5(load_controller_config(),load_controller_v4_config(),load_controller_v5_config(),benchmark)
    assert len(test)==3
    assert len(records)==3*len(METHODS)
    assert len(summary)==len(METHODS)
    assert len(oracle)==3
    files=write_v5_artifacts(tmp_path,load_controller_config(),load_controller_v4_config(),load_controller_v5_config(),benchmark)
    assert files["sequence-oracle.json"].exists()
    assert files["failure-attribution.json"].exists()
