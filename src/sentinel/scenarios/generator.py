from __future__ import annotations

import random
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from sentinel.domain.actions import ActionType
from sentinel.domain.decision import EvidenceRequest
from sentinel.domain.evidence import IncidentEvidence, IncidentObservation
from sentinel.domain.models import Host, NetworkConnection, Protocol, Service
from sentinel.evaluation.config import ControllerConfig
from sentinel.reasoning.models import Hypothesis
from sentinel.scenarios.lateral_movement import build_world
from sentinel.scenarios.suite import ScenarioDefinition, _candidate
from sentinel.simulator.reachability import attack_paths


class EvidenceQuality(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class GeneratedMetadata(BaseModel):
    model_config = ConfigDict(frozen=True)

    seed: int
    partition: str
    evidence_quality: EvidenceQuality
    true_attack: bool
    hidden_attack_paths: int
    alternate_path_present: bool
    missing_telemetry: bool
    false_positive_event: bool
    false_negative_event: bool
    conflicting_evidence: bool
    stale_vulnerability_data: bool
    host_count: int
    service_count: int


@dataclass(frozen=True)
class GeneratedScenario:
    definition: ScenarioDefinition
    metadata: GeneratedMetadata


def _obs(seed: int, suffix: str, kind: str, subject: str, detail: str, confidence: float) -> IncidentObservation:
    return IncidentObservation(
        id=f"obs-{seed}-{suffix}",
        observed_at=datetime(2026, 9, 25, 5, seed % 60, tzinfo=timezone.utc),
        source="SEALED_GENERATOR",
        kind=kind,
        subject=subject,
        detail=detail,
        confidence=confidence,
    )


def generate_scenario(seed: int, partition: str, controller: ControllerConfig) -> GeneratedScenario:
    rng = random.Random(seed)
    world = build_world()
    world.scenario_id = f"sealed-{partition}-{seed}"
    extra_hosts = rng.randint(0, 4)
    previous = "internal_host"
    for index in range(extra_hosts):
        host_id = f"pivot_{index}"
        world.hosts[host_id] = Host(id=host_id, name=f"Generated Pivot {index}")
        world.services[f"service_{index}"] = Service(id=f"service_{index}", name=f"Generated Service {index}", host_id=host_id, critical=rng.random() < 0.2)
        world.connections[f"pivot_edge_{index}"] = NetworkConnection(id=f"pivot_edge_{index}", source=previous, target=host_id, protocol=rng.choice((Protocol.SSH, Protocol.HTTPS)))
        previous = host_id
    if extra_hosts:
        world.connections["pivot_to_web"] = NetworkConnection(id="pivot_to_web", source=previous, target="web_server", protocol=Protocol.HTTPS)

    true_attack = rng.random() >= 0.25
    alternate_path = true_attack and rng.random() < 0.45
    compromised_account = rng.choice(("alice", "payroll_service"))
    world.compromised_hosts = {"workstation_a"} if true_attack else set()
    world.compromised_accounts = {compromised_account} if true_attack else set()
    attack_edge = world.connections["workstation_internal_smb"]
    world.connections[attack_edge.id] = attack_edge.model_copy(update={"required_account_id": compromised_account})
    if alternate_path:
        world.connections["alternate_https"] = NetworkConnection(
            id="alternate_https",
            source="workstation_a",
            target="web_server",
            protocol=Protocol.HTTPS,
            required_account_id=compromised_account,
        )

    quality = rng.choices((EvidenceQuality.HIGH, EvidenceQuality.MEDIUM, EvidenceQuality.LOW), weights=(3, 4, 3), k=1)[0]
    missing = quality is EvidenceQuality.LOW or rng.random() < 0.15
    false_positive = (not true_attack and rng.random() < 0.8) or rng.random() < 0.12
    false_negative = true_attack and missing
    conflicting = rng.random() < (0.4 if quality is EvidenceQuality.LOW else 0.15)
    stale_vuln = rng.random() < 0.2
    observations: list[IncidentObservation] = []
    if true_attack and not false_negative:
        observations.append(_obs(seed, "cred", "credential_access", compromised_account, "Credential material accessed by an unusual process", 0.9 if quality is EvidenceQuality.HIGH else 0.68))
        observations.append(_obs(seed, "network", "network", "workstation_a", "Outbound SMB session to an internal host", 0.88 if quality is EvidenceQuality.HIGH else 0.64))
    if false_positive:
        observations.append(_obs(seed, "fp", "process", "workstation_a", "Encoded administrative PowerShell event", 0.45))
    if stale_vuln:
        observations.append(_obs(seed, "stale", "vulnerability", "web_server", "Scanner reports a possibly stale web vulnerability", 0.4))
    if conflicting:
        observations.append(_obs(seed, "conflict", "allowlist", "workstation_a", "Activity overlaps an approved maintenance window", 0.65))
    if not observations:
        observations.append(_obs(seed, "weak", "network", "workstation_a", "Single low-confidence anomalous DNS query", 0.3))

    uncertainty = {EvidenceQuality.HIGH: 0.18, EvidenceQuality.MEDIUM: 0.46, EvidenceQuality.LOW: 0.79}[quality]
    if conflicting:
        uncertainty = min(0.95, uncertainty + 0.12)
    evidence_ids = tuple(item.id for item in observations)
    incident_id = f"incident-{partition}-{seed}"
    evidence = IncidentEvidence(incident_id=incident_id, observations=tuple(observations))
    hypothesis = Hypothesis(
        id=f"hyp-{seed}",
        statement="Observed activity may represent credential-enabled lateral movement.",
        evidence_ids=evidence_ids,
        confidence=round(1 - uncertainty, 2),
        uncertainty="Telemetry is generated with explicit missing, stale, false-positive, and conflicting-event controls.",
    )
    evidence_request = None
    if uncertainty >= controller.uncertainty_request_threshold:
        evidence_request = EvidenceRequest(
            request_id=f"collect-endpoint-{seed}",
            description="Collect fresh endpoint, identity, and network telemetry.",
            expected_information_gain="Resolve ambiguous account activity and partially observed paths.",
        )
    if any(item.kind == "credential_access" for item in observations):
        preferred = ActionType.DISABLE_ACCOUNT
    elif any(item.kind == "network" and "SMB" in item.detail for item in observations):
        preferred = ActionType.BLOCK_SMB
    else:
        preferred = ActionType.ISOLATE_HOST

    definition = ScenarioDefinition(
        id=f"sealed-{partition}-{seed}",
        title=f"Generated sealed scenario {seed}",
        incident_summary="Generated enterprise incident with controller-visible noisy observations.",
        world=world,
        evidence=evidence,
        hypotheses=(hypothesis,),
        candidates=(
            _candidate(ActionType.ISOLATE_HOST, "workstation_a", evidence_ids, min(0.95, uncertainty + 0.02)),
            _candidate(ActionType.BLOCK_SMB, "SMB", evidence_ids, uncertainty),
            _candidate(ActionType.DISABLE_ACCOUNT, compromised_account, evidence_ids, max(0.0, uncertainty - 0.03)),
        ),
        model_estimated_uncertainty=uncertainty,
        model_preferred_action=preferred,
        policy=controller.policy_config(),
        evidence_request=evidence_request,
        fixture_note="Seeded observation-derived estimate; not live Nemotron",
    )
    metadata = GeneratedMetadata(
        seed=seed,
        partition=partition,
        evidence_quality=quality,
        true_attack=true_attack,
        hidden_attack_paths=len(attack_paths(world)),
        alternate_path_present=alternate_path,
        missing_telemetry=missing,
        false_positive_event=false_positive,
        false_negative_event=false_negative,
        conflicting_evidence=conflicting,
        stale_vulnerability_data=stale_vuln,
        host_count=len(world.hosts),
        service_count=len(world.services),
    )
    return GeneratedScenario(definition=definition, metadata=metadata)


def generate_partition(partition: str, start: int, count: int, controller: ControllerConfig) -> tuple[GeneratedScenario, ...]:
    return tuple(generate_scenario(seed, partition, controller) for seed in range(start, start + count))


def acquire_evidence(generated: GeneratedScenario, resolved_uncertainty: float = 0.12) -> GeneratedScenario:
    """Reveal a bounded telemetry result for evaluation; hidden truth never enters the controller directly."""
    scenario = generated.definition
    metadata = generated.metadata
    if metadata.true_attack:
        detail = "Fresh endpoint and identity telemetry confirms credential-enabled lateral movement."
        kind, confidence = "corroboration", 0.97
        preferred = ActionType.DISABLE_ACCOUNT
        statement = "Fresh telemetry corroborates active credential-enabled lateral movement."
    else:
        detail = "Fresh telemetry attributes the activity to an approved maintenance workflow."
        kind, confidence = "benign_provenance", 0.98
        preferred = None
        statement = "Fresh telemetry supports a benign maintenance explanation."
    observation = _obs(metadata.seed, "fresh", kind, "workstation_a", detail, confidence)
    evidence = scenario.evidence.model_copy(update={"observations": (*scenario.evidence.observations, observation)})
    evidence_ids = tuple(item.id for item in evidence.observations)
    candidates = tuple(item.model_copy(update={
        "evidence_ids": evidence_ids,
        "model_estimated_uncertainty": resolved_uncertainty,
    }) for item in scenario.candidates)
    hypothesis = Hypothesis(
        id=f"hyp-{metadata.seed}-fresh",
        statement=statement,
        evidence_ids=(observation.id,),
        confidence=round(1 - resolved_uncertainty, 2),
        uncertainty="Bounded follow-up telemetry was acquired.",
    )
    definition = replace(
        scenario,
        evidence=evidence,
        hypotheses=(hypothesis,),
        candidates=candidates,
        model_estimated_uncertainty=resolved_uncertainty,
        model_preferred_action=preferred,
        evidence_request=None,
        fixture_note="Seeded acquired telemetry; not live Nemotron",
    )
    return GeneratedScenario(definition=definition, metadata=metadata)
