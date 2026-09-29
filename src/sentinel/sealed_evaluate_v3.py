from pathlib import Path
from sentinel.evaluation.config import load_benchmark_v3_config,load_controller_config,load_controller_v3_config
from sentinel.evaluation.sealed_v3 import write_v3_artifacts

def main():
    for path in write_v3_artifacts(Path("artifacts/sealed-v3"),load_controller_config(),load_controller_v3_config(),load_benchmark_v3_config()).values(): print(path)

if __name__=="__main__": main()
