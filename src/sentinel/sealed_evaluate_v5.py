from pathlib import Path
from sentinel.evaluation.config import load_benchmark_v5_config,load_controller_config,load_controller_v4_config,load_controller_v5_config
from sentinel.evaluation.sealed_v5 import write_v5_artifacts
def main():
    for path in write_v5_artifacts(Path("artifacts/sealed-v5"),load_controller_config(),load_controller_v4_config(),load_controller_v5_config(),load_benchmark_v5_config()).values(): print(path)
if __name__=="__main__": main()
