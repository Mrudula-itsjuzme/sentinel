from __future__ import annotations

import random
from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict

from sentinel.domain.actions import ActionType
from sentinel.domain.decision import EvidenceRequest
from sentinel.domain.evidence import IncidentEvidence, IncidentObservation
from sentinel.domain.models import BusinessDependency, Credential, FirewallRule, Host, NetworkConnection, Protocol, Service, UserAccount, Vulnerability, WorldState
from sentinel.evaluation.config import ControllerConfig
from sentinel.reasoning.models import Hypothesis
from sentinel.scenarios.generator import EvidenceQuality, GeneratedScenario, GeneratedMetadata
from sentinel.scenarios.suite import ScenarioDefinition, _candidate
from sentinel.simulator.reachability import attack_paths


class GeneratorV2Metadata(GeneratedMetadata):
    model_config = ConfigDict(frozen=True)
    topology_pattern: str
    credential_chain_length: int
    observation_process: str
    execution_failure_profile: str


def _ob(seed: int, suffix: str, kind: str, subject: str, detail: str, confidence: float) -> IncidentObservation:
    return IncidentObservation(id=f"svc-{seed}-{suffix}", observed_at=datetime(2026, 9, 25, 6, seed % 60, tzinfo=timezone.utc), source="SERVICE_TELEMETRY", kind=kind, subject=subject, detail=detail, confidence=confidence)


def generate_scenario_v2(seed: int, controller: ControllerConfig) -> GeneratedScenario:
    """A service-centric family with fan-out tiers and chained service identities."""
    rng = random.Random(seed)
    pattern = rng.choice(("hub-and-spoke", "dual-tier", "service-mesh"))
    hosts = {h.id: h for h in (
        Host(id="workstation_a", name="Operations Console", assigned_users=("operator",)),
        Host(id="internal_host", name="Identity Broker"),
        Host(id="web_server", name="Application Gateway"),
        Host(id="worker", name="Payment Worker"),
        Host(id="database", name="Ledger Store", sensitive=True),
    )}
    services = {s.id: s for s in (
        Service(id="console", name="Operations Console", host_id="workstation_a"),
        Service(id="identity", name="Identity Broker", host_id="internal_host", critical=True),
        Service(id="gateway", name="Application Gateway", host_id="web_server"),
        Service(id="payments", name="Payment Processing", host_id="worker", critical=True),
        Service(id="ledger", name="Ledger Store", host_id="database", critical=True),
    )}
    users = {u.id: u for u in (UserAccount(id="operator", display_name="Operations User"), UserAccount(id="payroll_service", display_name="Payment Orchestrator"), UserAccount(id="worker_service", display_name="Payment Worker"))}
    connections = {c.id: c for c in (
        NetworkConnection(id="console_identity", source="workstation_a", target="internal_host", protocol=Protocol.HTTPS, required_account_id="operator", legitimate_users=("operator",)),
        NetworkConnection(id="identity_gateway", source="internal_host", target="web_server", protocol=Protocol.SMB, required_account_id="payroll_service", legitimate_users=("payroll_service",)),
        NetworkConnection(id="gateway_worker", source="web_server", target="worker", protocol=Protocol.HTTPS, required_account_id="worker_service"),
        NetworkConnection(id="worker_ledger", source="worker", target="database", protocol=Protocol.POSTGRESQL, required_account_id="worker_service"),
        # Kept as a business dependency identifier used by the independent adapter.
        NetworkConnection(id="internal_workstation", source="internal_host", target="workstation_a", protocol=Protocol.HTTPS, required_account_id="payroll_service"),
    )}
    if pattern != "hub-and-spoke":
        connections["identity_worker"] = NetworkConnection(id="identity_worker", source="internal_host", target="worker", protocol=Protocol.SSH, required_account_id="payroll_service")
    if pattern == "service-mesh":
        connections["console_gateway"] = NetworkConnection(id="console_gateway", source="workstation_a", target="web_server", protocol=Protocol.HTTPS, required_account_id="operator")
    true_attack = rng.random() < 0.72
    chain_length = rng.choice((2, 3))
    compromised_accounts = {"operator", "payroll_service", "worker_service"} if true_attack else set()
    world = WorldState(
        scenario_id=f"sealed-v2-{seed}", hosts=hosts, services=services, users=users,
        credentials={"operator-token": Credential(id="operator-token", account_id="operator", accessible_from_hosts=("workstation_a",)), "broker-token": Credential(id="broker-token", account_id="payroll_service", accessible_from_hosts=("internal_host",))},
        connections=connections, firewall_rules={"service-smb": FirewallRule(id="service-smb", protocol=Protocol.SMB, allow=True)},
        vulnerabilities={"gateway-api": Vulnerability(id="gateway-api", host_id="web_server", description="Synthetic service-token relay flaw")},
        business_dependencies={"payroll": BusinessDependency(id="payroll", name="Payment Settlement", critical=True, required_service_ids=("identity", "payments", "ledger"), required_connection_ids=("internal_workstation", "gateway_worker", "worker_ledger"), required_account_ids=("payroll_service", "worker_service"))},
        compromised_hosts={"workstation_a"} if true_attack else set(), compromised_accounts=compromised_accounts,
    )
    quality = rng.choices((EvidenceQuality.HIGH, EvidenceQuality.MEDIUM, EvidenceQuality.LOW), weights=(2, 5, 3), k=1)[0]
    missing = quality is EvidenceQuality.LOW or rng.random() < .2
    false_positive = not true_attack and rng.random() < .75
    false_negative = true_attack and missing
    conflicting = rng.random() < (.35 if quality is EvidenceQuality.LOW else .12)
    observations = []
    if true_attack and not false_negative:
        observations += [_ob(seed, "auth", "service_auth", "payroll_service", "Broker issued an anomalous chained service token", .9), _ob(seed, "trace", "application_trace", "gateway", "Cross-tier request reached the payment worker", .84)]
    if false_positive:
        observations.append(_ob(seed, "batch", "scheduled_job", "operator", "Unusual batch settlement activity", .46))
    if conflicting:
        observations.append(_ob(seed, "change", "change_record", "gateway", "A deployment overlaps the anomaly window", .61))
    if not observations:
        observations.append(_ob(seed, "latency", "service_metric", "identity", "Short authentication latency spike", .31))
    uncertainty = {EvidenceQuality.HIGH: .2, EvidenceQuality.MEDIUM: .5, EvidenceQuality.LOW: .82}[quality] + (.1 if conflicting else 0)
    uncertainty = min(.95, uncertainty)
    ids = tuple(o.id for o in observations)
    request = EvidenceRequest(request_id=f"trace-service-chain-{seed}", description="Collect identity token lineage and distributed service traces.", expected_information_gain="Confirm whether the observed service calls form a credential chain.") if uncertainty >= controller.uncertainty_request_threshold else None
    evidence = IncidentEvidence(incident_id=f"incident-v2-{seed}", observations=tuple(observations))
    definition = ScenarioDefinition(
        id=f"sealed-v2-{seed}", title=f"Service-centric sealed scenario {seed}", incident_summary="A service identity may be moving through an application dependency chain.", world=world, evidence=evidence,
        hypotheses=(Hypothesis(id=f"hyp-svc-{seed}", statement="A chained service identity may be traversing application tiers.", evidence_ids=ids, confidence=round(1-uncertainty, 2), uncertainty="Service traces and token lineage may be incomplete."),),
        candidates=(_candidate(ActionType.ISOLATE_HOST, "workstation_a", ids, uncertainty), _candidate(ActionType.BLOCK_SMB, "SMB", ids, min(.95, uncertainty+.03)), _candidate(ActionType.DISABLE_ACCOUNT, "payroll_service", ids, max(0, uncertainty-.03))),
        model_estimated_uncertainty=uncertainty, model_preferred_action=ActionType.DISABLE_ACCOUNT if any(o.kind == "service_auth" for o in observations) else ActionType.ISOLATE_HOST,
        policy=controller.policy_config(), evidence_request=request, fixture_note="Generator-v2 service telemetry fixture; not live Nemotron",
    )
    metadata = GeneratorV2Metadata(seed=seed, partition="test", evidence_quality=quality, true_attack=true_attack, hidden_attack_paths=len(attack_paths(world)), alternate_path_present=pattern != "hub-and-spoke", missing_telemetry=missing, false_positive_event=false_positive, false_negative_event=false_negative, conflicting_evidence=conflicting, stale_vulnerability_data=False, host_count=len(hosts), service_count=len(services), topology_pattern=pattern, credential_chain_length=chain_length, observation_process="service-trace-and-token-lineage", execution_failure_profile="service-control-plane")
    return GeneratedScenario(definition=definition, metadata=metadata)


def generate_partition_v2(start: int, count: int, controller: ControllerConfig) -> tuple[GeneratedScenario, ...]:
    return tuple(generate_scenario_v2(seed, controller) for seed in range(start, start + count))
