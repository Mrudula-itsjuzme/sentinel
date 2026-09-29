from __future__ import annotations

import random

from sentinel.domain.actions import ActionType, Intervention
from sentinel.domain.execution import ObservationKind, ObservedExecutionOutcome, PostExecutionObservation


def observe_execution(intervention: Intervention, hidden: ObservedExecutionOutcome, seed: int, *, collection_step: int = 0) -> tuple[PostExecutionObservation, ...]:
    """Translate hidden execution truth into noisy controller-visible telemetry."""
    rng = random.Random(seed + collection_step * 1009)
    observations = [PostExecutionObservation(id=f"receipt-{seed}-{collection_step}", kind=ObservationKind.ACTION_RECEIPT, subject=intervention.target, value="ACCEPTED", confidence=.99, collection_step=collection_step)]

    def noisy(truth: bool, reliability: float) -> bool:
        return truth if rng.random() < reliability else not truth

    applied_signal = noisy(hidden.action_applied_fully, .82)
    if intervention.action is ActionType.ISOLATE_HOST:
        observations.append(PostExecutionObservation(id=f"endpoint-{seed}-{collection_step}", kind=ObservationKind.ENDPOINT_TELEMETRY, subject=intervention.target, value="ISOLATED" if applied_signal else "MANAGEMENT_REACHABLE", confidence=.78, collection_step=collection_step))
        observations.append(PostExecutionObservation(id=f"connect-{seed}-{collection_step}", kind=ObservationKind.CONNECTIVITY_PROBE, subject=intervention.target, value="BLOCKED" if noisy(hidden.action_applied_fully, .86) else "REACHABLE", confidence=.82, collection_step=collection_step))
    elif intervention.action in (ActionType.BLOCK_SMB, ActionType.RESTRICT_CONNECTION):
        observations.append(PostExecutionObservation(id=f"connect-{seed}-{collection_step}", kind=ObservationKind.CONNECTIVITY_PROBE, subject="SMB", value="BLOCKED" if applied_signal else "PARTIALLY_REACHABLE", confidence=.82, collection_step=collection_step))
    else:
        observations.append(PostExecutionObservation(id=f"auth-{seed}-{collection_step}", kind=ObservationKind.AUTHENTICATION_PROBE, subject=intervention.target, value="REJECTED" if applied_signal else "CACHED_TOKEN_VALID", confidence=.84, collection_step=collection_step))
    residual_clear = noisy(hidden.residual_attack_paths == 0, .80)
    observations.append(PostExecutionObservation(id=f"path-{seed}-{collection_step}", kind=ObservationKind.ATTACK_PATH_INDICATOR, subject="sensitive-assets", value="CLEAR" if residual_clear else "DETECTED", confidence=.80, collection_step=collection_step))
    service_ok = noisy(hidden.services_disrupted == 0, .86)
    observations.append(PostExecutionObservation(id=f"service-{seed}-{collection_step}", kind=ObservationKind.SERVICE_HEALTH, subject="critical-services", value="HEALTHY" if service_ok else "DEGRADED", confidence=.86, collection_step=collection_step))
    dependency_ok = noisy(hidden.payroll_available, .88)
    observations.append(PostExecutionObservation(id=f"dependency-{seed}-{collection_step}", kind=ObservationKind.DEPENDENCY_STATUS, subject="payroll", value="AVAILABLE" if dependency_ok else "UNAVAILABLE", confidence=.88, collection_step=collection_step))
    return tuple(observations)
