from enum import StrEnum

from pydantic import BaseModel

from sentinel.domain.actions import ActionType
from sentinel.domain.models import SimulationResult
from sentinel.policy.rules import PolicyConfig


class PolicyDecision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class PolicyResult(BaseModel):
    decision: PolicyDecision
    code: str
    reason: str


def evaluate_policy(
    result: SimulationResult,
    config: PolicyConfig | None = None,
    *,
    destructive: bool = False,
) -> PolicyResult:
    policy = config or PolicyConfig()
    try:
        action = ActionType(result.action)
    except ValueError:
        return PolicyResult(decision=PolicyDecision.DENY, code="ACTION_NOT_ALLOWLISTED", reason="Action is outside the explicit allowlist")

    if action not in policy.allowed_actions:
        return PolicyResult(decision=PolicyDecision.DENY, code="ACTION_NOT_ALLOWLISTED", reason="Action is outside the explicit allowlist")
    if destructive and policy.destructive_actions_forbidden:
        return PolicyResult(decision=PolicyDecision.DENY, code="DESTRUCTIVE_ACTION_FORBIDDEN", reason="Destructive actions are forbidden")
    if not result.simulation_succeeded:
        return PolicyResult(decision=PolicyDecision.DENY, code="SIMULATION_REQUIRED", reason="A successful simulation is required")
    if result.operations.users_impacted > policy.maximum_users_impacted:
        return PolicyResult(decision=PolicyDecision.DENY, code="USER_IMPACT_EXCEEDED", reason="User impact exceeds the configured maximum")
    if result.operations.estimated_downtime_minutes > policy.maximum_downtime_minutes:
        return PolicyResult(decision=PolicyDecision.DENY, code="DOWNTIME_EXCEEDED", reason="Estimated downtime exceeds the configured maximum")
    if "payroll" in policy.critical_services and not result.operations.payroll_available:
        return PolicyResult(decision=PolicyDecision.DENY, code="CRITICAL_SERVICE_DISRUPTED", reason="Payroll must remain available")
    return PolicyResult(decision=PolicyDecision.ALLOW, code="POLICY_SATISFIED", reason="All deterministic policy rules passed")

