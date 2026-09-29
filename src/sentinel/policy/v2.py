from sentinel.domain.actions import Reversibility
from sentinel.domain.decision import CandidateIntervention
from sentinel.domain.models import SimulationResult
from sentinel.evaluation.config import ControllerV2Config
from sentinel.policy.engine import PolicyDecision, PolicyResult


def evaluate_policy_v2(
    result: SimulationResult,
    candidate: CandidateIntervention,
    *,
    pre_attack_paths: int,
    verification_available: bool,
    config: ControllerV2Config,
) -> PolicyResult:
    policy = config.policy
    if candidate.intervention.destructive and policy.destructive_actions_forbidden:
        return PolicyResult(decision=PolicyDecision.DENY, code="DESTRUCTIVE_ACTION_FORBIDDEN", reason="Destructive actions remain forbidden")
    if not result.simulation_succeeded:
        return PolicyResult(decision=PolicyDecision.DENY, code="SIMULATION_REQUIRED", reason="A successful simulation is required")
    if result.operations.estimated_downtime_minutes > policy.maximum_downtime_minutes:
        return PolicyResult(decision=PolicyDecision.DENY, code="DOWNTIME_EXCEEDED", reason="Estimated downtime exceeds the frozen maximum")

    reversible_context = (
        policy.allow_reversible_context_override
        and candidate.intervention.reversibility is Reversibility.HIGH
        and (not policy.override_requires_attack_stopped or result.security.attack_stopped)
        and (not policy.override_requires_verification or verification_available)
    )
    if not result.operations.payroll_available:
        urgent_override = reversible_context and pre_attack_paths >= policy.critical_outage_override_minimum_pre_paths
        if not urgent_override:
            return PolicyResult(decision=PolicyDecision.DENY, code="CRITICAL_SERVICE_DISRUPTED", reason="Critical payroll availability is protected unless a multi-path reversible verified override applies")
    if result.operations.users_impacted > policy.maximum_users_impacted:
        contextual_override = reversible_context and result.operations.users_impacted <= policy.contextual_maximum_users_impacted
        if not contextual_override:
            return PolicyResult(decision=PolicyDecision.DENY, code="USER_IMPACT_EXCEEDED", reason="User impact exceeds both base and contextual limits")
    code = "CONTEXTUAL_REVERSIBLE_ALLOW" if (
        result.operations.users_impacted > policy.maximum_users_impacted or not result.operations.payroll_available
    ) else "POLICY_SATISFIED"
    return PolicyResult(decision=PolicyDecision.ALLOW, code=code, reason="Deterministic policy v2 conditions passed")

