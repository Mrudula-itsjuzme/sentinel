from sentinel.scenarios.lateral_movement import build_evidence, build_world
from sentinel.simulator.reachability import attack_paths
from sentinel.simulator.world import dependency_available


def test_initial_attack_reaches_sensitive_database() -> None:
    world = build_world()
    assert attack_paths(world) == [["workstation_a", "internal_host", "web_server", "database"]]
    assert dependency_available(world, "payroll")


def test_evidence_is_separate_from_ground_truth() -> None:
    evidence = build_evidence()
    world = build_world()
    assert len(evidence.observations) == 4
    assert not hasattr(world, "observations")

