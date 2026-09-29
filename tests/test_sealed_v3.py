from sentinel.evaluation.config import load_benchmark_v3_config, load_controller_config, load_controller_v3_config
from sentinel.evaluation.sealed_v3 import METHODS, run_v3, write_v3_artifacts


def test_v3_benchmark_small_run(tmp_path):
    benchmark=load_benchmark_v3_config().model_copy(update={"test_count":3,"bootstrap_samples":20})
    test,records,summary,bundles=run_v3(load_controller_config(),load_controller_v3_config(),benchmark)
    assert len(test)==3
    assert len(records)==3*len(METHODS)
    assert {row.method for row in records}==set(METHODS)
    assert len(summary)==len(METHODS)
    assert len(bundles)==3
    files=write_v3_artifacts(tmp_path,load_controller_config(),load_controller_v3_config(),benchmark)
    assert files["manifest.json"].exists()
    assert files["calibration-corpus.json"].exists()
