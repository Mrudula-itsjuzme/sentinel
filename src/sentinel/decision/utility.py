from sentinel.domain.actions import Reversibility
from sentinel.domain.decision import CandidateIntervention, UtilityBreakdown, UtilityWeights
from sentinel.domain.models import SimulationResult
from sentinel.policy.engine import PolicyDecision, PolicyResult


def calculate_utility(
    *,
    pre_attack_paths: int,
    pre_sensitive_assets: int,
    candidate: CandidateIntervention,
    simulation: SimulationResult,
    policy: PolicyResult,
    weights: UtilityWeights | None = None,
    ignore_policy: bool = False,
    ignore_uncertainty: bool = False,
    ignore_operations: bool = False,
) -> UtilityBreakdown:
    w = weights or UtilityWeights()
    path_denominator = max(pre_attack_paths, 1)
    sensitive_denominator = max(pre_sensitive_assets, 1)
    path_gain = w.attack_path_reduction * (
        (pre_attack_paths - simulation.security.remaining_attack_paths) / path_denominator
    )
    sensitive_gain = w.sensitive_exposure_reduction * (
        (pre_sensitive_assets - simulation.security.sensitive_assets_reachable) / sensitive_denominator
    )
    residual = w.residual_attack_reachability * (
        simulation.security.remaining_attack_paths / path_denominator
    )
    operations = 0.0
    if not ignore_operations:
        operations = (
            w.disrupted_service * simulation.operations.services_disrupted
            + w.impacted_user * simulation.operations.users_impacted
            + w.downtime_minute * simulation.operations.estimated_downtime_minutes
            + (0 if simulation.operations.payroll_available else w.payroll_outage)
        )
    policy_penalty = 0.0 if ignore_policy or policy.decision is PolicyDecision.ALLOW else w.policy_denial
    reversibility_penalty = {
        Reversibility.HIGH: 0.0,
        Reversibility.MEDIUM: w.medium_reversibility,
        Reversibility.LOW: w.low_reversibility,
    }[candidate.intervention.reversibility]
    uncertainty_penalty = 0.0 if ignore_uncertainty else (
        w.model_uncertainty * candidate.model_estimated_uncertainty
    )
    total = path_gain + sensitive_gain - residual - operations - policy_penalty - reversibility_penalty - uncertainty_penalty
    return UtilityBreakdown(
        attack_path_reduction_gain=round(path_gain, 4),
        sensitive_exposure_reduction_gain=round(sensitive_gain, 4),
        residual_reachability_penalty=round(residual, 4),
        operational_cost=round(operations, 4),
        policy_penalty=round(policy_penalty, 4),
        reversibility_penalty=round(reversibility_penalty, 4),
        uncertainty_penalty=round(uncertainty_penalty, 4),
        total_utility=round(total, 4),
    )
