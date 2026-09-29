from pathlib import Path

from sentinel.evaluation.config import load_benchmark_v2_config, load_controller_config, load_controller_v2_config
from sentinel.evaluation.sealed_v2 import write_v2_artifacts


def main() -> None:
    files = write_v2_artifacts(Path("artifacts/sealed-v2"), load_controller_config(), load_controller_v2_config(), load_benchmark_v2_config())
    for path in files.values():
        print(path)


if __name__ == "__main__":
    main()
