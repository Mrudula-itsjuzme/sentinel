from __future__ import annotations

import random
from dataclasses import dataclass
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


class RecoveryMetadata(GeneratedMetadata):
    model_config = ConfigDict(frozen=True)
    recovery_pattern: str
    ambiguity_level: str


def generate_recovery_scenario(seed: int, partition: str, controller: ControllerConfig) -> GeneratedScenario:
    rng=random.Random(seed)
    pattern=rng.choice(("parallel-paths","credential-cache","partial-firewall","benign-ambiguity"))
    hosts={h.id:h for h in (Host(id="workstation_a",name="Analyst Endpoint",assigned_users=("operator",)),Host(id="internal_host",name="Identity Gateway"),Host(id="web_server",name="Application Tier"),Host(id="database",name="Sensitive Store",sensitive=True))}
    services={s.id:s for s in (Service(id="endpoint",name="Endpoint",host_id="workstation_a"),Service(id="identity",name="Identity",host_id="internal_host",critical=True),Service(id="app",name="Application",host_id="web_server"),Service(id="data",name="Data",host_id="database",critical=True))}
    users={u.id:u for u in (UserAccount(id="operator",display_name="Operator"),UserAccount(id="payroll_service",display_name="Critical Service"))}
    connections={c.id:c for c in (
        NetworkConnection(id="workstation_internal_smb",source="workstation_a",target="internal_host",protocol=Protocol.SMB,required_account_id="operator",legitimate_users=("operator",)),
        NetworkConnection(id="internal_web",source="internal_host",target="web_server",protocol=Protocol.HTTPS,required_account_id="operator"),
        NetworkConnection(id="web_database",source="web_server",target="database",protocol=Protocol.POSTGRESQL,required_account_id="operator"),
        NetworkConnection(id="internal_workstation",source="internal_host",target="workstation_a",protocol=Protocol.HTTPS,required_account_id="payroll_service"),
    )}
    if pattern in ("parallel-paths","partial-firewall"):
        connections["alternate_https"]=NetworkConnection(id="alternate_https",source="workstation_a",target="web_server",protocol=Protocol.HTTPS,required_account_id="operator")
    true_attack=pattern != "benign-ambiguity" or rng.random()<.35
    world=WorldState(scenario_id=f"recovery-{partition}-{seed}",hosts=hosts,services=services,users=users,credentials={"operator-token":Credential(id="operator-token",account_id="operator",accessible_from_hosts=("workstation_a",))},connections=connections,firewall_rules={"allow-smb":FirewallRule(id="allow-smb",protocol=Protocol.SMB,allow=True)},vulnerabilities={"app":Vulnerability(id="app",host_id="web_server",description="Synthetic application flaw")},business_dependencies={"payroll":BusinessDependency(id="payroll",name="Critical Identity",critical=True,required_service_ids=("identity",),required_connection_ids=("internal_workstation",),required_account_ids=("payroll_service",))},compromised_hosts={"workstation_a"} if true_attack else set(),compromised_accounts={"operator"} if true_attack else set())
    quality=rng.choice((EvidenceQuality.MEDIUM,EvidenceQuality.LOW,EvidenceQuality.HIGH))
    uncertainty={EvidenceQuality.HIGH:.2,EvidenceQuality.MEDIUM:.48,EvidenceQuality.LOW:.76}[quality]
    obs=IncidentObservation(id=f"obs-rec-{seed}",observed_at=datetime(2026,9,25,7,seed%60,tzinfo=timezone.utc),source="RECOVERY_CORPUS",kind="attack_path_indicator",subject="workstation_a",detail="Observed cross-tier authentication and connectivity anomaly",confidence=1-uncertainty)
    ids=(obs.id,)
    request=EvidenceRequest(request_id=f"preflight-{seed}",description="Collect fresh path and identity telemetry.",expected_information_gain="Resolve pre-intervention ambiguity.") if uncertainty>=controller.uncertainty_request_threshold else None
    definition=ScenarioDefinition(id=f"recovery-{partition}-{seed}",title=f"Recovery scenario {seed}",incident_summary="A potentially recoverable lateral path is present.",world=world,evidence=IncidentEvidence(incident_id=f"incident-rec-{seed}",observations=(obs,)),hypotheses=(Hypothesis(id=f"hyp-rec-{seed}",statement="An endpoint identity may be traversing application dependencies.",evidence_ids=ids,confidence=round(1-uncertainty,2),uncertainty="Post-action behavior may be partially observable."),),candidates=(_candidate(ActionType.ISOLATE_HOST,"workstation_a",ids,uncertainty),_candidate(ActionType.BLOCK_SMB,"SMB",ids,uncertainty),_candidate(ActionType.DISABLE_ACCOUNT,"operator",ids,uncertainty)),model_estimated_uncertainty=uncertainty,model_preferred_action=rng.choice(tuple(ActionType)),policy=controller.policy_config(),evidence_request=request,fixture_note="Synthetic recovery corpus; not live telemetry")
    metadata=RecoveryMetadata(seed=seed,partition=partition,evidence_quality=quality,true_attack=true_attack,hidden_attack_paths=len(attack_paths(world)),alternate_path_present="alternate_https" in connections,missing_telemetry=quality is EvidenceQuality.LOW,false_positive_event=not true_attack,false_negative_event=False,conflicting_evidence=quality is EvidenceQuality.LOW,stale_vulnerability_data=False,host_count=len(hosts),service_count=len(services),recovery_pattern=pattern,ambiguity_level=quality.value)
    return GeneratedScenario(definition=definition,metadata=metadata)


def generate_recovery_partition(partition: str,start: int,count: int,controller: ControllerConfig)->tuple[GeneratedScenario,...]:
    return tuple(generate_recovery_scenario(seed,partition,controller) for seed in range(start,start+count))
