from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import StrEnum
import os
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, field_validator

from sentinel.domain.actions import INTERVENTIONS, ActionType, Intervention, apply_intervention
from sentinel.domain.evidence import IncidentEvidence
from sentinel.domain.models import SimulationResult
from sentinel.policy.engine import PolicyDecision, PolicyResult, evaluate_policy
from sentinel.providers.base import ProviderError
from sentinel.providers.nebius import NebiusConfig, NebiusReasoningClient
from sentinel.reasoning.models import ReasoningResponse
from sentinel.reasoning.service import IncidentReasoner, UnsafeModelOutput
from sentinel.scenarios.lateral_movement import build_evidence, build_world
from sentinel.services.counterfactual import simulate_all
from sentinel.simulator.reachability import attack_paths
from sentinel.simulator.world import dependency_available


class IncidentStatus(StrEnum):
    DEGRADED = "DEGRADED"
    POLICY_BLOCKED = "POLICY_BLOCKED"
    RECOVERED = "RECOVERED"
    ESCALATED = "ESCALATED"


class TimelineState(StrEnum):
    DETECTED = "DETECTED"
    OBSERVED = "OBSERVED"
    REASONED = "REASONED"
    PROPOSED = "PROPOSED"
    POLICY_APPROVED = "POLICY_APPROVED"
    POLICY_REJECTED = "POLICY_REJECTED"
    EXECUTING = "EXECUTING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    VERIFIED = "VERIFIED"
    ESCALATED = "ESCALATED"


class IncidentRunRequest(BaseModel):
    use_live_reasoning: bool = False
    proposed_action: ActionType | None = None

    @field_validator("proposed_action")
    @classmethod
    def supported_demo_action(cls, value: ActionType | None) -> ActionType | None:
        if value is not None and value not in {item.action for item in INTERVENTIONS}:
            raise ValueError("the product demo accepts only actions supported by the frozen MVP scenario")
        return value


class ModelCallMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    requested: bool
    available: bool
    provider: str | None = None
    model: str | None = None
    latency_ms: float | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    total_tokens: int | None = None
    success: bool = False
    error_code: str | None = None
    fallback_used: bool = False


class TimelineEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    timestamp: datetime
    incident_id: str
    state: TimelineState
    component: str
    summary: str
    evidence_ids: tuple[str, ...] = ()
    action: str | None = None
    target: str | None = None
    policy: PolicyResult | None = None
    execution_result: str | None = None
    deterministic: bool = True


class IncidentReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    incident_id: str
    scenario_id: str
    status: IncidentStatus
    diagnosis: str
    diagnosis_confidence: float
    evidence: IncidentEvidence
    model_call: ModelCallMetadata
    proposed_action: str
    proposed_target: str
    selected_action: str | None
    selected_target: str | None
    policy_result: PolicyResult
    candidate_results: tuple[SimulationResult, ...]
    execution_mode: str
    action_result: str
    verification: dict[str, Any]
    timeline: tuple[TimelineEvent, ...]


_INCIDENTS: dict[str, IncidentReport] = {}


def _target_for(action: ActionType) -> str:
    return next(item.target for item in INTERVENTIONS if item.action is action)


def _event_time(index: int) -> datetime:
    return datetime(2026, 9, 25, 4, 0, tzinfo=timezone.utc) + timedelta(seconds=index)


def _model_metadata(response: ReasoningResponse | None, requested: bool, error: str | None) -> ModelCallMetadata:
    configured_model = os.getenv("NEBIUS_MODEL", "").strip() or None
    return ModelCallMetadata(
        requested=requested,
        available=bool(os.getenv("NEBIUS_API_KEY", "").strip() and configured_model),
        provider=response.provider if response else ("nebius-token-factory" if requested else None),
        model=response.model if response else configured_model,
        latency_ms=response.latency_ms if response else None,
        input_tokens=response.input_tokens if response else None,
        output_tokens=response.output_tokens if response else None,
        total_tokens=response.total_tokens if response else None,
        success=response is not None,
        error_code=error,
        fallback_used=response is None,
    )


async def run_incident(request: IncidentRunRequest) -> IncidentReport:
    world = build_world()
    evidence = build_evidence()
    incident_id = f"sentinel-{uuid4().hex[:12]}"
    candidates = tuple(simulate_all(world))
    timeline: list[TimelineEvent] = []

    def add(state: TimelineState, component: str, summary: str, **kwargs: Any) -> None:
        timeline.append(TimelineEvent(timestamp=_event_time(len(timeline)), incident_id=incident_id, state=state, component=component, summary=summary, **kwargs))

    add(TimelineState.DETECTED, "observer", "Lateral-movement incident detected from endpoint and network evidence.", evidence_ids=tuple(item.id for item in evidence.observations))
    add(TimelineState.OBSERVED, "simulator", "Collected four observations; hidden simulator state remains outside the reasoning boundary.", evidence_ids=tuple(item.id for item in evidence.observations))

    reasoning: ReasoningResponse | None = None
    reasoning_error: str | None = None
    if request.use_live_reasoning:
        try:
            reasoner = IncidentReasoner(NebiusReasoningClient(NebiusConfig.from_env()))
            reasoning = await reasoner.reason(evidence)
        except (ProviderError, UnsafeModelOutput) as exc:
            reasoning_error = exc.code

    if reasoning:
        top_hypothesis = max(reasoning.proposal.hypotheses, key=lambda item: item.confidence)
        diagnosis = top_hypothesis.statement
        confidence = top_hypothesis.confidence
        add(TimelineState.REASONED, "nebius-nemotron", "Nemotron returned a schema-valid, evidence-grounded proposal.", evidence_ids=top_hypothesis.evidence_ids, deterministic=False)
    else:
        diagnosis = "Compromised workstation and account activity indicate credential-backed lateral movement over SMB."
        confidence = max(item.confidence for item in evidence.observations)
        message = "Live reasoning was unavailable; used the explicit deterministic diagnosis fallback." if request.use_live_reasoning else "Used deterministic local diagnosis; live model reasoning was not requested."
        add(TimelineState.REASONED, "deterministic-fallback", message, evidence_ids=("obs-002", "obs-004"))

    proposed_action = request.proposed_action
    if proposed_action is None and reasoning and reasoning.proposal.interventions:
        proposed_action = reasoning.proposal.interventions[0].action
    proposed_action = proposed_action or ActionType.DISABLE_ACCOUNT
    proposed_target = _target_for(proposed_action)
    add(TimelineState.PROPOSED, "controller", "Candidate action proposed; proposal is not authorization.", action=proposed_action.value, target=proposed_target, deterministic=reasoning is None or request.proposed_action is not None)

    by_action = {ActionType(item.action): item for item in candidates}
    proposed_policy = evaluate_policy(by_action[proposed_action])
    selected_action: ActionType | None = proposed_action if proposed_policy.decision is PolicyDecision.ALLOW else None
    policy_result = proposed_policy
    if selected_action:
        add(TimelineState.POLICY_APPROVED, "policy", proposed_policy.reason, action=selected_action.value, target=proposed_target, policy=proposed_policy)
    else:
        add(TimelineState.POLICY_REJECTED, "policy", proposed_policy.reason, action=proposed_action.value, target=proposed_target, policy=proposed_policy)
        for fallback in (ActionType.DISABLE_ACCOUNT, ActionType.RESTRICT_CONNECTION, ActionType.REVOKE_SESSION):
            if fallback not in by_action:
                continue
            fallback_policy = evaluate_policy(by_action[fallback])
            if fallback_policy.decision is PolicyDecision.ALLOW:
                selected_action = fallback
                policy_result = fallback_policy
                add(TimelineState.PROPOSED, "controller", "Selected the lowest-impact supported fallback after policy rejection.", action=fallback.value, target=_target_for(fallback))
                add(TimelineState.POLICY_APPROVED, "policy", fallback_policy.reason, action=fallback.value, target=_target_for(fallback), policy=fallback_policy)
                break

    if selected_action is None:
        add(TimelineState.ESCALATED, "controller", "No policy-authorized simulated action remained; human escalation required.")
        status = IncidentStatus.ESCALATED
        action_result = "NO_ACTION_EXECUTED"
        verification = {"recovered": False, "attack_paths_remaining": len(attack_paths(world)), "payroll_available": dependency_available(world, "payroll")}
        selected_target = None
    else:
        selected_target = _target_for(selected_action)
        add(TimelineState.EXECUTING, "simulated-executor", "Applying the authorized action to an isolated deterministic world clone.", action=selected_action.value, target=selected_target)
        changed = world.clone()
        apply_intervention(changed, Intervention(action=selected_action, target=selected_target))
        remaining = len(attack_paths(changed))
        payroll_available = dependency_available(changed, "payroll")
        recovered = remaining == 0 and payroll_available
        action_result = "SIMULATED_SUCCESS" if recovered else "SIMULATED_INCOMPLETE"
        add(TimelineState.SUCCEEDED if recovered else TimelineState.FAILED, "simulated-executor", "Simulation applied the action." if recovered else "Simulation applied the action but recovery criteria were not met.", action=selected_action.value, target=selected_target, execution_result=action_result)
        verification = {"recovered": recovered, "attack_paths_remaining": remaining, "payroll_available": payroll_available, "criteria": "zero attack paths and payroll available"}
        add(TimelineState.VERIFIED, "verifier", "Recovery verified from recomputed reachability and dependency state." if recovered else "Post-action verification failed; escalation required.", action=selected_action.value, target=selected_target, execution_result=action_result)
        status = IncidentStatus.RECOVERED if recovered else IncidentStatus.ESCALATED

    report = IncidentReport(
        incident_id=incident_id,
        scenario_id=world.scenario_id,
        status=status,
        diagnosis=diagnosis,
        diagnosis_confidence=confidence,
        evidence=evidence,
        model_call=_model_metadata(reasoning, request.use_live_reasoning, reasoning_error),
        proposed_action=proposed_action.value,
        proposed_target=proposed_target,
        selected_action=selected_action.value if selected_action else None,
        selected_target=selected_target,
        policy_result=policy_result,
        candidate_results=candidates,
        execution_mode="DETERMINISTIC_SIMULATION",
        action_result=action_result,
        verification=verification,
        timeline=tuple(timeline),
    )
    _INCIDENTS[incident_id] = report
    return report


def list_incidents() -> tuple[IncidentReport, ...]:
    return tuple(reversed(tuple(_INCIDENTS.values())))


def get_incident(incident_id: str) -> IncidentReport | None:
    return _INCIDENTS.get(incident_id)


def model_config_status() -> dict[str, Any]:
    model = os.getenv("NEBIUS_MODEL", "").strip()
    error_code = None
    try:
        NebiusConfig.from_env()
        configured = True
    except ProviderError as exc:
        configured = False
        error_code = exc.code
    return {
        "provider": "Nebius Token Factory",
        "configured": configured,
        "model": model or None,
        "required_model_family": "NVIDIA Nemotron",
        "error_code": error_code,
        "credentials_exposed": False,
    }


def experiment_results() -> Any:
    artifact = Path(__file__).resolve().parents[3] / "artifacts" / "sealed-v5" / "aggregate-metrics.json"
    if not artifact.exists():
        return []
    import json

    return json.loads(artifact.read_text())
