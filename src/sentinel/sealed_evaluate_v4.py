from pathlib import Path
from sentinel.evaluation.config import load_benchmark_v4_config,load_controller_config,load_controller_v4_config
from sentinel.evaluation.sealed_v4 import write_v4_artifacts
def main():
    for path in write_v4_artifacts(Path("artifacts/sealed-v4"),load_controller_config(),load_controller_v4_config(),load_benchmark_v4_config()).values(): print(path)
if __name__=="__main__": main()
