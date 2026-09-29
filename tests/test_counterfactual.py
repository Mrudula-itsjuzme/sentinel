from sentinel.scenarios.lateral_movement import build_world
from sentinel.services.counterfactual import simulate_all


def test_same_state_produces_identical_results() -> None:
    assert simulate_all(build_world()) == simulate_all(build_world())


def test_all_three_actions_stop_attack() -> None:
    results = simulate_all(build_world())
    assert [result.action for result in results] == ["ISOLATE_HOST", "BLOCK_SMB", "DISABLE_ACCOUNT"]
    assert all(result.security.attack_stopped for result in results)
    assert all(result.security.remaining_attack_paths == 0 for result in results)
    assert all(result.security.sensitive_assets_reachable == 0 for result in results)


def test_business_impacts_are_reproducible_and_explainable() -> None:
    by_action = {result.action: result for result in simulate_all(build_world())}
    assert by_action["ISOLATE_HOST"].operations.impacted_user_ids == ["alice", "payroll_service"]
    assert by_action["ISOLATE_HOST"].operations.disrupted_service_ids == ["employee_endpoint"]
    assert by_action["ISOLATE_HOST"].operations.payroll_available is False
    assert by_action["BLOCK_SMB"].operations.impacted_user_ids == ["alice", "payroll_service"]
    assert by_action["BLOCK_SMB"].operations.payroll_available is False
    assert by_action["DISABLE_ACCOUNT"].operations.impacted_user_ids == ["alice"]
    assert by_action["DISABLE_ACCOUNT"].operations.payroll_available is True
