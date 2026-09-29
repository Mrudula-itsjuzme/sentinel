from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from sentinel.domain.actions import Intervention
from sentinel.domain.evidence import IncidentEvidence
from sentinel.domain.execution import ExecutionStateEstimate, IndependentVerificationReport, ObservedExecutionOutcome, PostExecutionObservation, RecoveryDecision
from sentinel.domain.models import SimulationResult
from sentinel.policy.engine import PolicyResult
from sentinel.reasoning.models import Hypothesis


class DecisionOutcome(StrEnum):
    ACT = "ACT"
    DEFER = "DEFER"
    REQUEST_MORE_EVIDENCE = "REQUEST_MORE_EVIDENCE"


class CandidateIntervention(BaseModel):
    model_config = ConfigDict(frozen=True)

    intervention: Intervention
    evidence_ids: tuple[str, ...]
    model_estimated_uncertainty: float = Field(ge=0, le=1)


class UtilityWeights(BaseModel):
    model_config = ConfigDict(frozen=True)

    attack_path_reduction: float = 35
    sensitive_exposure_reduction: float = 25
    residual_attack_reachability: float = 30
    disrupted_service: float = 12
    impacted_user: float = 3
    downtime_minute: float = 0.2
    payroll_outage: float = 25
    policy_denial: float = 100
    medium_reversibility: float = 5
    low_reversibility: float = 12
    model_uncertainty: float = 20


class UtilityBreakdown(BaseModel):
    model_config = ConfigDict(frozen=True)

    attack_path_reduction_gain: float
    sensitive_exposure_reduction_gain: float
    residual_reachability_penalty: float
    operational_cost: float
    policy_penalty: float
    reversibility_penalty: float
    uncertainty_penalty: float
    total_utility: float


class VerificationCheck(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    description: str
    expected_value: str


class VerificationPlan(BaseModel):
    model_config = ConfigDict(frozen=True)

    predicted_state_change: str
    expected_security_effect: str
    expected_business_effect: str
    checks: tuple[VerificationCheck, ...]


class VerificationResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    passed: bool
    attack_path_prediction_error: int
    sensitive_asset_prediction_error: int
    service_disruption_prediction_error: int
    user_impact_prediction_error: int
    payroll_prediction_match: bool


class CandidateDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    candidate: CandidateIntervention
    pre_action_attack_paths: int
    pre_action_sensitive_assets_reachable: int
    simulation: SimulationResult
    policy: PolicyResult
    utility: UtilityBreakdown
    verification_plan: VerificationPlan
    verification_result: VerificationResult


class EvidenceRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    request_id: str
    description: str
    expected_information_gain: str


class DecisionSelection(BaseModel):
    model_config = ConfigDict(frozen=True)

    outcome: DecisionOutcome
    selected_action: str | None = None
    selected_target: str | None = None
    rationale: tuple[str, ...]
    evidence_request: EvidenceRequest | None = None


class EvidenceValueEstimate(BaseModel):
    model_config = ConfigDict(frozen=True)
    current_action_margin: float
    decision_changes_if_uncertainty_resolves: bool
    expected_decision_improvement: float
    acquisition_cost: float
    delay_cost: float
    net_value: float
    request_worthwhile: bool
    explanation: tuple[str, ...]


class AdaptiveDecisionStep(BaseModel):
    model_config = ConfigDict(frozen=True)
    step: int
    phase: str
    selection: DecisionSelection
    observed_outcome: ObservedExecutionOutcome | None = None
    verification: IndependentVerificationReport | None = None
    execution_receipt: PostExecutionObservation | None = None
    post_execution_observations: tuple[PostExecutionObservation, ...] = ()
    state_estimate: ExecutionStateEstimate | None = None
    recovery_decision: RecoveryDecision | None = None


class AdaptiveResolution(BaseModel):
    model_config = ConfigDict(frozen=True)
    initial_decision: DecisionSelection
    evidence_value: EvidenceValueEstimate | None = None
    requested_evidence: EvidenceRequest | None = None
    revised_uncertainty: float | None = None
    revised_belief_summary: str | None = None
    steps: tuple[AdaptiveDecisionStep, ...]
    replan_count: int
    cumulative_operational_cost: float
    final_residual_attack_paths: int | None
    final_resolution: str
    escalation_required: bool


class AuditMetadata(BaseModel):
    model_config = ConfigDict(frozen=True)

    generated_at: datetime
    engine_version: str
    scenario_id: str
    uncertainty_source: str


class DecisionBundle(BaseModel):
    model_config = ConfigDict(frozen=True)

    incident_summary: str
    evidence: IncidentEvidence
    hypotheses: tuple[Hypothesis, ...]
    model_estimated_uncertainty: float = Field(ge=0, le=1)
    candidates: tuple[CandidateDecision, ...]
    selection: DecisionSelection
    audit: AuditMetadata
    observed_outcome: ObservedExecutionOutcome | None = None
    independent_verification: IndependentVerificationReport | None = None
    adaptive_resolution: AdaptiveResolution | None = None
