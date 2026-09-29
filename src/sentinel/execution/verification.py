from sentinel.domain.execution import IndependentVerificationReport, ObservedExecutionOutcome
from sentinel.domain.models import SimulationResult


def compare_prediction(predicted: SimulationResult, observed: ObservedExecutionOutcome) -> IndependentVerificationReport:
    reasons: list[str] = []
    action_mismatch = predicted.simulation_succeeded != observed.action_applied_fully
    path_error = observed.residual_attack_paths - predicted.security.remaining_attack_paths
    sensitive_error = observed.sensitive_assets_reachable - predicted.security.sensitive_assets_reachable
    service_error = observed.services_disrupted - predicted.operations.services_disrupted
    user_error = observed.users_impacted - predicted.operations.users_impacted
    payroll_match = observed.payroll_available == predicted.operations.payroll_available
    if action_mismatch:
        reasons.append("Action completion did not match prediction.")
    if path_error or sensitive_error:
        reasons.append("Observed residual attack reachability differs from prediction.")
    if service_error or user_error or not payroll_match:
        reasons.append("Observed business impact differs from prediction.")
    escalation = bool(reasons)
    return IndependentVerificationReport(
        status="MISMATCH" if escalation else "VERIFIED",
        predicted_action_success=predicted.simulation_succeeded,
        observed_action_success=observed.action_applied_fully,
        action_success_mismatch=action_mismatch,
        attack_path_prediction_error=path_error,
        sensitive_asset_prediction_error=sensitive_error,
        service_impact_prediction_error=service_error,
        user_impact_prediction_error=user_error,
        critical_service_availability_match=payroll_match,
        residual_risk_error=path_error + sensitive_error,
        escalation_required=escalation,
        reasons=tuple(reasons),
    )

