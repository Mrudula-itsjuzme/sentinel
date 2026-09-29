from sentinel.scenarios.lateral_movement import build_world


def test_world_clone_does_not_mutate_original() -> None:
    original = build_world()
    clone = original.clone()
    clone.compromised_hosts.clear()
    clone.hosts["workstation_a"] = clone.hosts["workstation_a"].model_copy(update={"isolated": True})

    assert original.compromised_hosts == {"workstation_a"}
    assert original.hosts["workstation_a"].isolated is False


def test_fresh_worlds_are_equal_but_independent() -> None:
    first = build_world()
    second = build_world()
    assert first == second
    assert first is not second

