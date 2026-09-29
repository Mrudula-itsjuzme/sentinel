from sentinel.domain.decision import VerificationCheck, VerificationPlan, VerificationResult
from sentinel.domain.models import SimulationResult, WorldState
from sentinel.domain.actions import Intervention
from sentinel.simulator.engine import simulate_intervention


def build_verification_plan(intervention: Intervention, prediction: SimulationResult) -> VerificationPlan:
    return VerificationPlan(
        predicted_state_change=f"{intervention.action.value} applied to {intervention.target}",
        expected_security_effect=(
            f"{prediction.security.remaining_attack_paths} attack paths and "
            f"{prediction.security.sensitive_assets_reachable} reachable sensitive assets"
        ),
        expected_business_effect=(
            f"{prediction.operations.services_disrupted} services disrupted, "
            f"{prediction.operations.users_impacted} users impacted, "
            f"payroll_available={str(prediction.operations.payroll_available).lower()}"
        ),
        checks=(
            VerificationCheck(id="verify-action-state", description="Confirm the requested state transition is present.", expected_value=f"{intervention.action.value}:{intervention.target}"),
            VerificationCheck(id="verify-attack-paths", description="Recompute attack reachability from observed post-action state.", expected_value=str(prediction.security.remaining_attack_paths)),
            VerificationCheck(id="verify-sensitive-assets", description="Recompute reachable sensitive assets.", expected_value=str(prediction.security.sensitive_assets_reachable)),
            VerificationCheck(id="verify-business-impact", description="Recompute service, user, and payroll availability.", expected_value=prediction.operations.model_dump_json()),
        ),
    )


def verify_simulated_execution(
    world: WorldState,
    intervention: Intervention,
    prediction: SimulationResult,
) -> VerificationResult:
    observed = simulate_intervention(world, intervention)
    path_error = observed.security.remaining_attack_paths - prediction.security.remaining_attack_paths
    sensitive_error = observed.security.sensitive_assets_reachable - prediction.security.sensitive_assets_reachable
    service_error = observed.operations.services_disrupted - prediction.operations.services_disrupted
    user_error = observed.operations.users_impacted - prediction.operations.users_impacted
    payroll_match = observed.operations.payroll_available == prediction.operations.payroll_available
    return VerificationResult(
        passed=all((path_error == 0, sensitive_error == 0, service_error == 0, user_error == 0, payroll_match)),
        attack_path_prediction_error=path_error,
        sensitive_asset_prediction_error=sensitive_error,
        service_disruption_prediction_error=service_error,
        user_impact_prediction_error=user_error,
        payroll_prediction_match=payroll_match,
    )

