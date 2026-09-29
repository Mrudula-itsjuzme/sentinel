from __future__ import annotations

from sentinel.domain.actions import ActionType, Intervention
from sentinel.domain.execution import ChangeAssessment, ExecutionStateEstimate, ObservationKind, PostExecutionObservation
from sentinel.domain.models import SimulationResult
from sentinel.evaluation.config import EstimatorConfig


POSITIVE = {"ISOLATED", "BLOCKED", "REJECTED"}
NEGATIVE = {"MANAGEMENT_REACHABLE", "REACHABLE", "PARTIALLY_REACHABLE", "CACHED_TOKEN_VALID"}


def estimate_execution_state(intervention: Intervention, prediction: SimulationResult, observations: tuple[PostExecutionObservation, ...], config: EstimatorConfig) -> ExecutionStateEstimate:
    success_weight = failure_weight = 0.0
    confirmed=[]; inferred=[]; unknown=[]; contradicted=[]
    path_votes=[]; critical_votes=[]
    network_votes=[]; credential_votes=[]; service_votes=[]
    for obs in observations:
        reliability = config.signal_reliability.get(obs.kind.value, .5) * obs.confidence
        if obs.value in POSITIVE:
            success_weight += reliability
        elif obs.value in NEGATIVE:
            failure_weight += reliability
        if obs.kind is ObservationKind.ATTACK_PATH_INDICATOR:
            path_votes.append((obs.value == "CLEAR", reliability))
        if obs.kind is ObservationKind.CONNECTIVITY_PROBE:
            network_votes.append((obs.value == "BLOCKED", reliability))
        if obs.kind is ObservationKind.AUTHENTICATION_PROBE:
            credential_votes.append((obs.value == "REJECTED", reliability))
        if obs.kind is ObservationKind.SERVICE_HEALTH:
            service_votes.append((obs.value == "HEALTHY", reliability))
        if obs.kind is ObservationKind.DEPENDENCY_STATUS:
            critical_votes.append((obs.value == "AVAILABLE", reliability))
    denominator=max(.001,success_weight+failure_weight)
    applied=success_weight/denominator if denominator else .5
    path_clear_conf=max((weight for clear,weight in path_votes if clear),default=0)
    path_detect_conf=max((weight for clear,weight in path_votes if not clear),default=0)
    residual=0 if path_clear_conf >= path_detect_conf else max(1,prediction.security.remaining_attack_paths+1)
    residual_conf=max(path_clear_conf,path_detect_conf)
    available_weight=sum(weight for available,weight in critical_votes if available)
    unavailable_weight=sum(weight for available,weight in critical_votes if not available)
    critical_probability=available_weight/max(.001,available_weight+unavailable_weight) if critical_votes else .5
    def probability(votes: list[tuple[bool,float]]) -> float:
        positive=sum(weight for value,weight in votes if value); negative=sum(weight for value,weight in votes if not value)
        return positive/max(.001,positive+negative) if votes else .5
    network_probability=probability(network_votes)
    credential_probability=probability(credential_votes)
    service_probability=probability(service_votes)
    alternate_probability=round(1-(path_clear_conf/max(.001,path_clear_conf+path_detect_conf)),4) if path_votes else .5
    change=f"{intervention.action.value}:{intervention.target}"
    if applied >= config.confirmed_threshold:
        confirmed.append(change); assessment=ChangeAssessment.CONFIRMED
    elif applied <= config.contradicted_threshold:
        contradicted.append(f"Predicted successful application of {change}"); assessment=ChangeAssessment.CONTRADICTED
    elif success_weight or failure_weight:
        inferred.append(change); assessment=ChangeAssessment.INFERRED
    else:
        unknown.append(change); assessment=ChangeAssessment.UNKNOWN
    if residual_conf < config.minimum_residual_confidence:
        unknown.append("residual attack reachability")
    if prediction.security.remaining_attack_paths == 0 and residual > 0:
        contradicted.append("Predicted attack-path elimination")
    if prediction.operations.payroll_available and critical_probability < .5:
        contradicted.append("Predicted critical-service availability")
    return ExecutionStateEstimate(action_applied_probability=round(applied,4), estimated_residual_attack_paths=residual, residual_risk_confidence=round(residual_conf,4), critical_service_available_probability=round(critical_probability,4), network_contained_probability=round(network_probability,4), credential_invalid_probability=round(credential_probability,4), service_healthy_probability=round(service_probability,4), alternate_path_probability=alternate_probability, business_dependency_available_probability=round(critical_probability,4), confirmed_changes=tuple(confirmed), inferred_changes=tuple(inferred), unknown_changes=tuple(unknown), contradicted_predictions=tuple(contradicted), assessment=assessment, observation_ids=tuple(item.id for item in observations))
