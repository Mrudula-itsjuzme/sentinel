from __future__ import annotations

import random
from datetime import datetime,timezone

from pydantic import BaseModel,ConfigDict

from sentinel.domain.actions import ActionType
from sentinel.domain.evidence import IncidentEvidence,IncidentObservation
from sentinel.domain.models import AttackPathKind,BusinessDependency,Credential,FirewallRule,Host,NetworkConnection,Protocol,Service,UserAccount,Vulnerability,WorldState
from sentinel.evaluation.config import ControllerConfig
from sentinel.reasoning.models import Hypothesis
from sentinel.scenarios.generator import EvidenceQuality,GeneratedMetadata,GeneratedScenario
from sentinel.scenarios.suite import ScenarioDefinition,_candidate
from sentinel.simulator.reachability import attack_paths,typed_attack_paths


class SequenceMetadata(GeneratedMetadata):
    model_config=ConfigDict(frozen=True)
    sequence_pattern:str
    path_types:tuple[str,...]
    retry_profile:str
    escalation_truth:bool


def generate_sequence_scenario(seed:int,partition:str,controller:ControllerConfig)->GeneratedScenario:
    rng=random.Random(seed); pattern=rng.choice(("session-persistence","alternate-protocol","independent-paths","retry-best","retry-harm","switch-required","true-escalation"))
    hosts={h.id:h for h in (Host(id="workstation_a",name="Shared Source Endpoint",assigned_users=("operator","analyst-a","analyst-b","analyst-c")),Host(id="internal_host",name="Identity Service"),Host(id="web_server",name="Application Service"),Host(id="database",name="Protected Data",sensitive=True))}
    services={s.id:s for s in (Service(id="endpoint",name="Endpoint",host_id="workstation_a"),Service(id="identity",name="Identity",host_id="internal_host",critical=True),Service(id="application",name="Application",host_id="web_server"),Service(id="data",name="Data",host_id="database",critical=True))}
    users={u.id:u for u in (UserAccount(id="operator",display_name="Operator"),UserAccount(id="payroll_service",display_name="Critical Service"))}
    connections={c.id:c for c in (
        NetworkConnection(id="smb_lateral",source="workstation_a",target="internal_host",protocol=Protocol.SMB,required_account_id="operator",path_kind=AttackPathKind.CREDENTIAL,legitimate_users=("operator",)),
        NetworkConnection(id="identity_data",source="internal_host",target="database",protocol=Protocol.POSTGRESQL,required_account_id="operator",path_kind=AttackPathKind.CREDENTIAL),
        NetworkConnection(id="internal_workstation",source="internal_host",target="workstation_a",protocol=Protocol.HTTPS,required_account_id="payroll_service"),
    )}
    if pattern in ("session-persistence","independent-paths","retry-harm","switch-required","true-escalation"):
        connections["cached_https"]=NetworkConnection(id="cached_https",source="workstation_a",target="web_server",protocol=Protocol.HTTPS,cached_session_account_id="operator",path_kind=AttackPathKind.SESSION)
        connections["web_data"]=NetworkConnection(id="web_data",source="web_server",target="database",protocol=Protocol.HTTPS,cached_session_account_id="operator",path_kind=AttackPathKind.SERVICE_TRUST)
    if pattern in ("alternate-protocol","independent-paths","switch-required","true-escalation"):
        connections["alternate_ssh"]=NetworkConnection(id="alternate_ssh",source="workstation_a",target="database",protocol=Protocol.SSH,required_account_id="operator",path_kind=AttackPathKind.NETWORK)
    true_attack=rng.random()>.15; compromised={"operator"} if true_attack else set()
    world=WorldState(scenario_id=f"sequence-{partition}-{seed}",hosts=hosts,services=services,users=users,credentials={"operator":Credential(id="operator",account_id="operator",accessible_from_hosts=("workstation_a",))},connections=connections,firewall_rules={"smb":FirewallRule(id="smb",protocol=Protocol.SMB,allow=True)},vulnerabilities={"app":Vulnerability(id="app",host_id="web_server",description="Synthetic trust flaw")},business_dependencies={"payroll":BusinessDependency(id="payroll",name="Identity Availability",critical=True,required_service_ids=("identity",),required_connection_ids=("internal_workstation",),required_account_ids=("payroll_service",))},compromised_hosts={"workstation_a"} if true_attack else set(),compromised_accounts=compromised)
    quality=rng.choice(tuple(EvidenceQuality)); uncertainty={EvidenceQuality.HIGH:.2,EvidenceQuality.MEDIUM:.48,EvidenceQuality.LOW:.75}[quality]
    observation=IncidentObservation(id=f"obs-seq-{seed}",observed_at=datetime(2026,9,25,8,seed%60,tzinfo=timezone.utc),source="SEQUENCE_CORPUS",kind="multi_path_indicator",subject="workstation_a",detail="Observed identity, session, and network indicators across services",confidence=1-uncertainty); ids=(observation.id,)
    candidate_uncertainty=.05
    candidates=[_candidate(ActionType.ISOLATE_HOST,"workstation_a",ids,candidate_uncertainty),_candidate(ActionType.BLOCK_SMB,"SMB",ids,candidate_uncertainty),_candidate(ActionType.DISABLE_ACCOUNT,"operator",ids,candidate_uncertainty),_candidate(ActionType.REVOKE_SESSION,"operator",ids,candidate_uncertainty)]
    if "cached_https" in connections: candidates.append(_candidate(ActionType.RESTRICT_CONNECTION,"cached_https",ids,candidate_uncertainty))
    elif "alternate_ssh" in connections: candidates.append(_candidate(ActionType.RESTRICT_CONNECTION,"alternate_ssh",ids,candidate_uncertainty))
    definition=ScenarioDefinition(id=f"sequence-{partition}-{seed}",title=f"Bounded sequence scenario {seed}",incident_summary="Multiple network, credential, session, or service-trust paths may persist after containment.",world=world,evidence=IncidentEvidence(incident_id=f"incident-seq-{seed}",observations=(observation,)),hypotheses=(Hypothesis(id=f"hyp-seq-{seed}",statement="One or more structurally distinct attack paths may be active.",evidence_ids=ids,confidence=round(1-uncertainty,2),uncertainty="Path type and action completion require post-action verification."),),candidates=tuple(candidates),model_estimated_uncertainty=uncertainty,model_preferred_action=ActionType.BLOCK_SMB,policy=controller.policy_config(),fixture_note="Synthetic bounded-sequence corpus; not live telemetry")
    typed=typed_attack_paths(world); path_types=tuple(sorted({kind for path in typed for kind in path["path_kinds"]}))
    metadata=SequenceMetadata(seed=seed,partition=partition,evidence_quality=quality,true_attack=true_attack,hidden_attack_paths=len(attack_paths(world)),alternate_path_present=len(typed)>1,missing_telemetry=quality is EvidenceQuality.LOW,false_positive_event=not true_attack,false_negative_event=False,conflicting_evidence=quality is EvidenceQuality.LOW,stale_vulnerability_data=False,host_count=len(hosts),service_count=len(services),sequence_pattern=pattern,path_types=path_types,retry_profile="harmful" if pattern=="retry-harm" else ("beneficial" if pattern=="retry-best" else "mixed"),escalation_truth=pattern=="true-escalation")
    return GeneratedScenario(definition=definition,metadata=metadata)


def generate_sequence_partition(partition,start,count,controller):
    return tuple(generate_sequence_scenario(seed,partition,controller) for seed in range(start,start+count))
