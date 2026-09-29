from pathlib import Path

from sentinel.evaluation.config import load_benchmark_config, load_controller_config, sha256_file
from sentinel.evaluation.sealed import run_sealed_benchmark


def test_frozen_controller_hash_is_stable() -> None:
    assert sha256_file(Path("configs/controller-v1.json")) == "32e0496f027d4845f99094644e20c56f81b6956a3d871c57d93b8b2f800b9b3b"


def test_sealed_benchmark_is_reproducible() -> None:
    controller = load_controller_config()
    benchmark = load_benchmark_config()
    first = run_sealed_benchmark(controller, benchmark)
    second = run_sealed_benchmark(controller, benchmark)
    assert first[1] == second[1]
    assert first[2] == second[2]
    assert first[3] == second[3]


def test_partitions_are_disjoint() -> None:
    partitions, *_ = run_sealed_benchmark(load_controller_config(), load_benchmark_config())
    seed_sets = {name: {item.metadata.seed for item in items} for name, items in partitions.items()}
    assert seed_sets["train"].isdisjoint(seed_sets["dev"])
    assert seed_sets["train"].isdisjoint(seed_sets["test"])
    assert seed_sets["dev"].isdisjoint(seed_sets["test"])

