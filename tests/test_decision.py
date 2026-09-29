from sentinel.decision.engine import build_decision_bundle
from sentinel.domain.decision import DecisionOutcome
from sentinel.scenarios.suite import build_scenario_suite, scenario_a, scenario_d, scenario_e


def test_scenario_suite_is_reproducible() -> None:
    first = build_scenario_suite()
    second = build_scenario_suite()
    assert [item.id for item in first] == [item.id for item in second]
    assert [item.world.model_dump(mode="json") for item in first] == [item.world.model_dump(mode="json") for item in second]


def test_full_selection_prefers_low_impact_containment() -> None:
    bundle = build_decision_bundle(scenario_a())
    assert bundle.selection.outcome is DecisionOutcome.ACT
    assert bundle.selection.selected_action == "DISABLE_ACCOUNT"
    by_action = {item.candidate.intervention.action.value: item for item in bundle.candidates}
    assert by_action["DISABLE_ACCOUNT"].utility.total_utility > by_action["ISOLATE_HOST"].utility.total_utility
    assert by_action["ISOLATE_HOST"].utility.policy_penalty == 0
    assert by_action["ISOLATE_HOST"].utility.operational_cost > by_action["DISABLE_ACCOUNT"].utility.operational_cost


def test_two_path_scenario_penalizes_partial_remediation() -> None:
    bundle = build_decision_bundle(scenario_e())
    by_action = {item.candidate.intervention.action.value: item for item in bundle.candidates}
    assert by_action["BLOCK_SMB"].simulation.security.remaining_attack_paths == 1
    assert by_action["DISABLE_ACCOUNT"].simulation.security.remaining_attack_paths == 0
    assert bundle.selection.selected_action == "DISABLE_ACCOUNT"


def test_high_uncertainty_requests_evidence_then_defers() -> None:
    initial = scenario_d()
    before = build_decision_bundle(initial)
    after = build_decision_bundle(initial.follow_up)
    assert before.selection.outcome is DecisionOutcome.REQUEST_MORE_EVIDENCE
    assert before.selection.evidence_request.request_id == "collect-endpoint-telemetry"
    assert after.selection.outcome is DecisionOutcome.DEFER
    assert after.model_estimated_uncertainty < before.model_estimated_uncertainty


def test_decision_bundle_does_not_leak_hidden_world() -> None:
    payload = build_decision_bundle(scenario_a()).model_dump(mode="json")
    assert "world" not in payload
    assert "compromised_hosts" not in str(payload)
    assert "fixture_note" not in payload


def test_decision_build_preserves_source_world() -> None:
    scenario = scenario_a()
    snapshot = scenario.world.model_dump(mode="json")
    build_decision_bundle(scenario)
    assert scenario.world.model_dump(mode="json") == snapshot


def test_simulated_prediction_matches_observation() -> None:
    bundle = build_decision_bundle(scenario_a())
    assert all(item.verification_result.passed for item in bundle.candidates)
    assert all(item.verification_result.attack_path_prediction_error == 0 for item in bundle.candidates)
    assert all(item.pre_action_attack_paths == 1 for item in bundle.candidates)
    assert all(item.pre_action_sensitive_assets_reachable == 1 for item in bundle.candidates)
