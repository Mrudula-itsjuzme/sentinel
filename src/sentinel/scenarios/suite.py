from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone

from sentinel.domain.actions import ActionType, Intervention, Reversibility
from sentinel.domain.decision import CandidateIntervention, EvidenceRequest
from sentinel.domain.evidence import IncidentEvidence, IncidentObservation
from sentinel.domain.models import NetworkConnection, Protocol, WorldState
from sentinel.policy.rules import PolicyConfig
from sentinel.reasoning.models import Hypothesis
from sentinel.scenarios.lateral_movement import build_evidence, build_world


@dataclass(frozen=True)
class ScenarioDefinition:
    id: str
    title: str
    incident_summary: str
    world: WorldState
    evidence: IncidentEvidence
    hypotheses: tuple[Hypothesis, ...]
    candidates: tuple[CandidateIntervention, ...]
    model_estimated_uncertainty: float
    model_preferred_action: ActionType | None
    policy: PolicyConfig = PolicyConfig()
    evidence_request: EvidenceRequest | None = None
    follow_up: "ScenarioDefinition | None" = None
    fixture_note: str = "Controlled scenario fixture; not a live Nemotron measurement"


def _candidate(action: ActionType, target: str, evidence_ids: tuple[str, ...], uncertainty: float) -> CandidateIntervention:
    reversibility = {
        ActionType.ISOLATE_HOST: Reversibility.HIGH,
        ActionType.BLOCK_SMB: Reversibility.HIGH,
        ActionType.DISABLE_ACCOUNT: Reversibility.MEDIUM,
        ActionType.REVOKE_SESSION: Reversibility.HIGH,
        ActionType.RESTRICT_CONNECTION: Reversibility.HIGH,
    }[action]
    return CandidateIntervention(
        intervention=Intervention(action=action, target=target, reversibility=reversibility),
        evidence_ids=evidence_ids,
        model_estimated_uncertainty=uncertainty,
    )


def _observation(id: str, kind: str, subject: str, detail: str, confidence: float) -> IncidentObservation:
    return IncidentObservation(
        id=id,
        observed_at=datetime(2026, 9, 25, 4, 0, tzinfo=timezone.utc),
        source="CONTROLLED_FIXTURE",
        kind=kind,
        subject=subject,
        detail=detail,
        confidence=confidence,
    )


def scenario_a() -> ScenarioDefinition:
    evidence = build_evidence()
    hypothesis = Hypothesis(
        id="hyp-lateral-movement",
        statement="Alice's credential may be enabling SMB lateral movement from Workstation A.",
        evidence_ids=("obs-002", "obs-004"),
        confidence=0.82,
        uncertainty="The downstream host compromise has not been directly observed.",
    )
    return ScenarioDefinition(
        id="scenario-a-payroll-lateral",
        title="Lateral movement with payroll dependency",
        incident_summary="Workstation A shows credential access and outbound SMB activity.",
        world=build_world(),
        evidence=evidence,
        hypotheses=(hypothesis,),
        candidates=(
            _candidate(ActionType.ISOLATE_HOST, "workstation_a", ("obs-001", "obs-002"), 0.18),
            _candidate(ActionType.BLOCK_SMB, "SMB", ("obs-004",), 0.22),
            _candidate(ActionType.DISABLE_ACCOUNT, "alice", ("obs-002", "obs-004"), 0.15),
        ),
        model_estimated_uncertainty=0.2,
        model_preferred_action=ActionType.ISOLATE_HOST,
        policy=PolicyConfig(maximum_users_impacted=10, critical_services=frozenset()),
    )


def scenario_b() -> ScenarioDefinition:
    world = build_world()
    world.compromised_accounts = {"payroll_service"}
    connection = world.connections["workstation_internal_smb"]
    world.connections[connection.id] = connection.model_copy(update={"required_account_id": "payroll_service"})
    evidence = IncidentEvidence(
        incident_id="incident-critical-credential",
        observations=(
            _observation("obs-b1", "credential_access", "payroll_service", "Payroll service credential used interactively", 0.92),
            _observation("obs-b2", "network", "workstation_a", "SMB session used the payroll service identity", 0.9),
        ),
    )
    return ScenarioDefinition(
        id="scenario-b-critical-credential",
        title="Critical service credential compromise",
        incident_summary="A critical payroll identity appears in an interactive SMB session.",
        world=world,
        evidence=evidence,
        hypotheses=(Hypothesis(id="hyp-critical-credential", statement="The payroll service credential may be compromised.", evidence_ids=("obs-b1", "obs-b2"), confidence=0.86, uncertainty="Credential replay has not been independently confirmed."),),
        candidates=(
            _candidate(ActionType.ISOLATE_HOST, "workstation_a", ("obs-b2",), 0.2),
            _candidate(ActionType.BLOCK_SMB, "SMB", ("obs-b2",), 0.16),
            _candidate(ActionType.DISABLE_ACCOUNT, "payroll_service", ("obs-b1",), 0.14),
        ),
        model_estimated_uncertainty=0.24,
        model_preferred_action=ActionType.DISABLE_ACCOUNT,
    )


def scenario_c() -> ScenarioDefinition:
    world = build_world()
    world.compromised_hosts = {"web_server"}
    world.compromised_accounts = set()
    evidence = IncidentEvidence(
        incident_id="incident-public-web",
        observations=(
            _observation("obs-c1", "exploit", "web_server", "Web worker spawned an unexpected shell", 0.96),
            _observation("obs-c2", "network", "web_server", "Database connection followed the shell event", 0.88),
        ),
    )
    return ScenarioDefinition(
        id="scenario-c-public-web",
        title="Public web service compromise",
        incident_summary="A public web server shows shell execution followed by database access.",
        world=world,
        evidence=evidence,
        hypotheses=(Hypothesis(id="hyp-web-compromise", statement="The public web service is likely compromised.", evidence_ids=("obs-c1", "obs-c2"), confidence=0.9, uncertainty="The exploit mechanism is not yet known."),),
        candidates=(
            _candidate(ActionType.ISOLATE_HOST, "web_server", ("obs-c1", "obs-c2"), 0.1),
            _candidate(ActionType.BLOCK_SMB, "SMB", ("obs-c1",), 0.7),
            _candidate(ActionType.DISABLE_ACCOUNT, "alice", ("obs-c1",), 0.8),
        ),
        model_estimated_uncertainty=0.16,
        model_preferred_action=ActionType.ISOLATE_HOST,
    )


def scenario_d_follow_up() -> ScenarioDefinition:
    world = build_world()
    world.compromised_hosts = set()
    world.compromised_accounts = set()
    evidence = IncidentEvidence(
        incident_id="incident-ambiguous",
        observations=(
            _observation("obs-d1", "process", "workstation_a", "Encoded administrative PowerShell observed", 0.52),
            _observation("obs-d2", "network", "workstation_a", "Rare DNS query observed", 0.48),
            _observation("obs-d3", "endpoint_telemetry", "workstation_a", "Signed maintenance job and clean memory scan confirmed", 0.98),
        ),
    )
    return ScenarioDefinition(
        id="scenario-d-ambiguous-follow-up",
        title="Ambiguous telemetry after endpoint collection",
        incident_summary="Endpoint telemetry attributes the activity to an approved maintenance job.",
        world=world,
        evidence=evidence,
        hypotheses=(Hypothesis(id="hyp-benign-maintenance", statement="The activity is consistent with approved maintenance.", evidence_ids=("obs-d3",), confidence=0.94, uncertainty="No material uncertainty remains in the bounded scenario."),),
        candidates=(
            _candidate(ActionType.ISOLATE_HOST, "workstation_a", ("obs-d1",), 0.75),
            _candidate(ActionType.BLOCK_SMB, "SMB", ("obs-d2",), 0.8),
            _candidate(ActionType.DISABLE_ACCOUNT, "alice", ("obs-d1",), 0.78),
        ),
        model_estimated_uncertainty=0.08,
        model_preferred_action=None,
    )


def scenario_d() -> ScenarioDefinition:
    follow_up = scenario_d_follow_up()
    return replace(
        follow_up,
        id="scenario-d-ambiguous",
        title="Ambiguous telemetry",
        incident_summary="Weak PowerShell and DNS signals may be benign maintenance.",
        evidence=IncidentEvidence(
            incident_id="incident-ambiguous",
            observations=follow_up.evidence.observations[:2],
        ),
        hypotheses=(Hypothesis(id="hyp-ambiguous", statement="The workstation activity may be malicious or approved administration.", evidence_ids=("obs-d1", "obs-d2"), confidence=0.5, uncertainty="Endpoint provenance and memory state are missing."),),
        model_estimated_uncertainty=0.86,
        model_preferred_action=ActionType.ISOLATE_HOST,
        evidence_request=EvidenceRequest(request_id="collect-endpoint-telemetry", description="Collect process-signing, job provenance, and volatile endpoint telemetry.", expected_information_gain="Distinguish approved maintenance from active compromise."),
        follow_up=follow_up,
    )


def scenario_e() -> ScenarioDefinition:
    world = build_world()
    world.connections["workstation_web_https"] = NetworkConnection(
        id="workstation_web_https",
        source="workstation_a",
        target="web_server",
        protocol=Protocol.HTTPS,
        required_account_id="alice",
    )
    evidence = build_evidence().model_copy(update={"incident_id": "incident-two-paths"})
    return ScenarioDefinition(
        id="scenario-e-two-paths",
        title="Two viable attack paths",
        incident_summary="The compromised workstation has SMB and HTTPS routes toward the database.",
        world=world,
        evidence=evidence,
        hypotheses=(Hypothesis(id="hyp-two-paths", statement="The stolen account may support more than the obvious SMB path.", evidence_ids=("obs-002", "obs-004"), confidence=0.74, uncertainty="The HTTPS route is not directly present in observed telemetry."),),
        candidates=(
            _candidate(ActionType.ISOLATE_HOST, "workstation_a", ("obs-001",), 0.2),
            _candidate(ActionType.BLOCK_SMB, "SMB", ("obs-004",), 0.18),
            _candidate(ActionType.DISABLE_ACCOUNT, "alice", ("obs-002",), 0.24),
        ),
        model_estimated_uncertainty=0.3,
        model_preferred_action=ActionType.BLOCK_SMB,
    )


def build_scenario_suite() -> tuple[ScenarioDefinition, ...]:
    return (scenario_a(), scenario_b(), scenario_c(), scenario_d(), scenario_e())
