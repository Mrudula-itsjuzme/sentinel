from sentinel.evaluation.config import load_controller_config
from sentinel.scenarios.generator import generate_partition, generate_scenario


def test_generator_is_seed_reproducible() -> None:
    controller = load_controller_config()
    first = generate_scenario(3007, "test", controller)
    second = generate_scenario(3007, "test", controller)
    assert first.metadata == second.metadata
    assert first.definition.world == second.definition.world
    assert first.definition.evidence == second.definition.evidence


def test_generator_varies_topology_and_noise() -> None:
    generated = generate_partition("test", 3000, 30, load_controller_config())
    assert len({item.metadata.host_count for item in generated}) > 1
    assert {item.metadata.true_attack for item in generated} == {True, False}
    assert any(item.metadata.alternate_path_present for item in generated)
    assert any(item.metadata.false_negative_event for item in generated)
    assert any(item.metadata.conflicting_evidence for item in generated)


def test_controller_visible_evidence_excludes_hidden_labels() -> None:
    generated = generate_scenario(3011, "test", load_controller_config())
    payload = generated.definition.evidence.model_dump(mode="json")
    assert "true_attack" not in str(payload)
    assert "hidden_attack_paths" not in str(payload)

