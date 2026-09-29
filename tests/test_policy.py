from sentinel.domain.actions import ActionType
from sentinel.policy.engine import PolicyDecision, evaluate_policy
from sentinel.policy.rules import PolicyConfig
from sentinel.scenarios.lateral_movement import build_world
from sentinel.services.counterfactual import simulate_all


def _results():
    return {result.action: result for result in simulate_all(build_world())}


def test_allows_low_impact_successful_action() -> None:
    result = evaluate_policy(_results()["DISABLE_ACCOUNT"])
    assert result.decision is PolicyDecision.ALLOW
    assert result.code == "POLICY_SATISFIED"


def test_denies_critical_service_disruption() -> None:
    result = evaluate_policy(
        _results()["BLOCK_SMB"],
        PolicyConfig(maximum_users_impacted=10),
    )
    assert result.decision is PolicyDecision.DENY
    assert result.code == "CRITICAL_SERVICE_DISRUPTED"


def test_denies_high_user_impact() -> None:
    result = evaluate_policy(_results()["BLOCK_SMB"])
    assert result.code == "USER_IMPACT_EXCEEDED"


def test_denies_action_excluded_from_allowlist() -> None:
    config = PolicyConfig(allowed_actions=frozenset({ActionType.ISOLATE_HOST}))
    result = evaluate_policy(_results()["DISABLE_ACCOUNT"], config)
    assert result.code == "ACTION_NOT_ALLOWLISTED"


def test_denies_failed_simulation() -> None:
    failed = _results()["DISABLE_ACCOUNT"].model_copy(update={"simulation_succeeded": False})
    assert evaluate_policy(failed).code == "SIMULATION_REQUIRED"


def test_denies_destructive_action() -> None:
    assert evaluate_policy(_results()["DISABLE_ACCOUNT"], destructive=True).code == "DESTRUCTIVE_ACTION_FORBIDDEN"

