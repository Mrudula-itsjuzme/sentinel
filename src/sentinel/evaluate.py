import argparse
from pathlib import Path

from sentinel.evaluation.runner import write_results


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Sentinel's controlled decision evaluation")
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/evaluation"))
    args = parser.parse_args()
    for name, path in write_results(args.output_dir).items():
        print(f"{name}: {path}")


if __name__ == "__main__":
    main()

