import argparse
from pathlib import Path

from sentinel.evaluation.config import load_benchmark_config, load_controller_config
from sentinel.evaluation.sealed import write_sealed_artifacts


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Sentinel sealed benchmark v1")
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/sealed-v1"))
    args = parser.parse_args()
    controller = load_controller_config()
    benchmark = load_benchmark_config()
    for name, path in write_sealed_artifacts(args.output_dir, controller, benchmark).items():
        print(f"{name}: {path}")


if __name__ == "__main__":
    main()

