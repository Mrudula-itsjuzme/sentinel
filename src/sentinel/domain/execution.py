from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class ExecutionFaults(BaseModel):
    model_config = ConfigDict(frozen=True)

    partial_action: bool
    delayed_isolation: bool
    incomplete_firewall_propagation: bool
    credential_rotation_failure: bool
    unexpected_service_restart: bool
    unknown_alternate_path: bool
    dependency_model_mismatch: bool


class ObservedExecutionOutcome(BaseModel):
    model_config = ConfigDict(frozen=True)

    action_applied_fully: bool
    residual_attack_paths: int
    sensitive_assets_reachable: int
    services_disrupted: int
    users_impacted: int
    payroll_available: bool
    faults: ExecutionFaults


class IndependentVerificationReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: str
    predicted_action_success: bool
    observed_action_success: bool
    action_success_mismatch: bool
    attack_path_prediction_error: int
    sensitive_asset_prediction_error: int
    service_impact_prediction_error: int
    user_impact_prediction_error: int
    critical_service_availability_match: bool
    residual_risk_error: int
    escalation_required: bool
    reasons: tuple[str, ...]


class ObservationKind(StrEnum):
    ACTION_RECEIPT = "ACTION_RECEIPT"
    CONNECTIVITY_PROBE = "CONNECTIVITY_PROBE"
    SERVICE_HEALTH = "SERVICE_HEALTH"
    AUTHENTICATION_PROBE = "AUTHENTICATION_PROBE"
    ENDPOINT_TELEMETRY = "ENDPOINT_TELEMETRY"
    DEPENDENCY_STATUS = "DEPENDENCY_STATUS"
    ATTACK_PATH_INDICATOR = "ATTACK_PATH_INDICATOR"


class PostExecutionObservation(BaseModel):
    model_config = ConfigDict(frozen=True)
    id: str
    kind: ObservationKind
    subject: str
    value: str
    confidence: float = Field(ge=0, le=1)
    collection_step: int = 0


class ChangeAssessment(StrEnum):
    CONFIRMED = "CONFIRMED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"
    CONTRADICTED = "CONTRADICTED"


class ExecutionStateEstimate(BaseModel):
    model_config = ConfigDict(frozen=True)
    action_applied_probability: float = Field(ge=0, le=1)
    estimated_residual_attack_paths: int
    residual_risk_confidence: float = Field(ge=0, le=1)
    critical_service_available_probability: float = Field(ge=0, le=1)
    network_contained_probability: float = Field(ge=0, le=1)
    credential_invalid_probability: float = Field(ge=0, le=1)
    service_healthy_probability: float = Field(ge=0, le=1)
    alternate_path_probability: float = Field(ge=0, le=1)
    business_dependency_available_probability: float = Field(ge=0, le=1)
    confirmed_changes: tuple[str, ...]
    inferred_changes: tuple[str, ...]
    unknown_changes: tuple[str, ...]
    contradicted_predictions: tuple[str, ...]
    assessment: ChangeAssessment
    observation_ids: tuple[str, ...]


class RecoveryOutcome(StrEnum):
    ACCEPT = "ACCEPT"
    RETRY = "RETRY"
    COMPENSATE = "COMPENSATE"
    SWITCH_ACTION = "SWITCH_ACTION"
    REQUEST_MORE_EVIDENCE = "REQUEST_MORE_EVIDENCE"
    ESCALATE = "ESCALATE"


class RecoveryDecision(BaseModel):
    model_config = ConfigDict(frozen=True)
    outcome: RecoveryOutcome
    selected_action: str | None = None
    selected_target: str | None = None
    rationale: tuple[str, ...]
    rejected_retry_reason: str | None = None
    structural_switch_evidence: tuple[str, ...] = ()
