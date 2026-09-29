from sentinel.decision.v2 import build_decision_bundle_v2, execute_and_replan
from sentinel.domain.decision import DecisionOutcome
from sentinel.evaluation.config import load_controller_config, load_controller_v2_config
from sentinel.policy.engine import PolicyDecision
from sentinel.scenarios.generator import acquire_evidence, generate_partition
from sentinel.scenarios.generator_v2 import generate_scenario_v2


def test_v2_evidence_requests_are_selective_on_development_data():
    v1 = load_controller_config()
    v2 = load_controller_v2_config()
    development = (*generate_partition("train", 1000, 30, v1), *generate_partition("dev", 2000, 30, v1))
    outcomes = [build_decision_bundle_v2(item.definition, v2).selection.outcome for item in development]
    assert DecisionOutcome.REQUEST_MORE_EVIDENCE in outcomes
    assert DecisionOutcome.ACT in outcomes
    assert outcomes.count(DecisionOutcome.REQUEST_MORE_EVIDENCE) < len(outcomes) / 2


def test_acquired_evidence_updates_belief_without_exposing_metadata():
    generated = generate_partition("dev", 2000, 1, load_controller_config())[0]
    updated = acquire_evidence(generated)
    assert updated.definition.model_estimated_uncertainty == 0.12
    assert updated.definition.evidence_request is None
    assert "true_attack" not in updated.definition.model_dump() if hasattr(updated.definition, "model_dump") else True


def test_policy_v2_has_contextual_allows_and_keeps_denials():
    v1 = load_controller_config()
    v2 = load_controller_v2_config()
    development = generate_partition("dev", 2000, 30, v1)
    decisions = [candidate.policy for item in development for candidate in build_decision_bundle_v2(item.definition, v2).candidates]
    assert any(item.code == "CONTEXTUAL_REVERSIBLE_ALLOW" for item in decisions)
    assert any(item.decision is PolicyDecision.DENY for item in decisions)


def test_replanning_is_bounded_and_never_repeats_action():
    generated = generate_partition("dev", 2000, 30, load_controller_config())
    v2 = load_controller_v2_config()
    for item in generated:
        bundle = build_decision_bundle_v2(item.definition, v2)
        if bundle.selection.outcome is DecisionOutcome.ACT:
            executed = execute_and_replan(bundle, item.definition, v2, 900000 + item.metadata.seed * 10)
            steps = executed.adaptive_resolution.steps
            keys = [(step.selection.selected_action, step.selection.selected_target) for step in steps]
            assert len(keys) == len(set(keys))
            assert executed.adaptive_resolution.replan_count <= v2.replanning.maximum_replans


def test_generator_v2_is_reproducible_and_structurally_distinct():
    v1 = load_controller_config()
    left = generate_scenario_v2(17, v1)
    right = generate_scenario_v2(17, v1)
    assert left.metadata == right.metadata
    assert left.definition.world == right.definition.world
    assert left.metadata.observation_process == "service-trace-and-token-lineage"
    assert "worker" in left.definition.world.hosts
    assert "gateway_worker" in left.definition.world.connections
    assert left.metadata.topology_pattern in {"hub-and-spoke", "dual-tier", "service-mesh"}
