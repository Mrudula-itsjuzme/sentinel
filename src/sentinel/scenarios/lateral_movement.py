from datetime import datetime, timezone

from sentinel.domain.evidence import IncidentEvidence, IncidentObservation
from sentinel.domain.models import (
    BusinessDependency,
    Credential,
    FirewallRule,
    Host,
    NetworkConnection,
    Protocol,
    Service,
    UserAccount,
    Vulnerability,
    WorldState,
)


def build_world() -> WorldState:
    """Build a fresh deterministic copy of the MVP world."""

    hosts = {
        item.id: item
        for item in (
            Host(id="internet", name="Internet"),
            Host(id="firewall", name="Edge Firewall"),
            Host(id="web_server", name="Web Server"),
            Host(id="database", name="Sensitive Database", sensitive=True),
            Host(id="internal_host", name="Internal File Host"),
            Host(
                id="workstation_a",
                name="Workstation A",
                assigned_users=("alice",),
            ),
        )
    }
    services = {
        item.id: item
        for item in (
            Service(id="web_app", name="Public Web Application", host_id="web_server"),
            Service(id="customer_db", name="Customer Database", host_id="database", critical=True),
            Service(id="payroll_files", name="Payroll File Share", host_id="internal_host", critical=True),
            Service(id="employee_endpoint", name="Employee Endpoint", host_id="workstation_a"),
        )
    }
    users = {
        item.id: item
        for item in (
            UserAccount(id="alice", display_name="Alice Analyst"),
            UserAccount(id="payroll_service", display_name="Payroll Service Account"),
        )
    }
    connections = {
        item.id: item
        for item in (
            NetworkConnection(id="internet_firewall", source="internet", target="firewall", protocol=Protocol.HTTPS),
            NetworkConnection(id="firewall_web", source="firewall", target="web_server", protocol=Protocol.HTTPS),
            NetworkConnection(id="web_database", source="web_server", target="database", protocol=Protocol.POSTGRESQL),
            NetworkConnection(id="firewall_internal", source="firewall", target="internal_host", protocol=Protocol.SSH),
            NetworkConnection(
                id="internal_workstation",
                source="internal_host",
                target="workstation_a",
                protocol=Protocol.SMB,
                required_account_id="payroll_service",
                legitimate_users=("payroll_service",),
            ),
            NetworkConnection(
                id="workstation_internal_smb",
                source="workstation_a",
                target="internal_host",
                protocol=Protocol.SMB,
                required_account_id="alice",
                legitimate_users=("alice",),
            ),
            NetworkConnection(id="internal_web", source="internal_host", target="web_server", protocol=Protocol.SSH),
        )
    }
    return WorldState(
        scenario_id="lateral-movement-v1",
        hosts=hosts,
        services=services,
        users=users,
        credentials={
            "alice_credential": Credential(
                id="alice_credential",
                account_id="alice",
                accessible_from_hosts=("workstation_a",),
            )
        },
        connections=connections,
        firewall_rules={
            "allow_smb": FirewallRule(id="allow_smb", protocol=Protocol.SMB, allow=True)
        },
        vulnerabilities={
            "cve_demo_web": Vulnerability(
                id="cve_demo_web",
                host_id="web_server",
                description="Scenario-only vulnerable web component",
            )
        },
        business_dependencies={
            "payroll": BusinessDependency(
                id="payroll",
                name="Payroll Processing",
                critical=True,
                required_service_ids=("payroll_files",),
                required_connection_ids=("internal_workstation",),
                required_account_ids=("payroll_service",),
            )
        },
        compromised_hosts={"workstation_a"},
        compromised_accounts={"alice"},
    )


def build_evidence() -> IncidentEvidence:
    observed_at = datetime(2026, 9, 25, 4, 0, tzinfo=timezone.utc)
    return IncidentEvidence(
        incident_id="incident-lateral-001",
        observations=(
            IncidentObservation(id="obs-001", observed_at=observed_at, source="EDR", kind="process", subject="workstation_a", detail="Suspicious encoded PowerShell activity", confidence=0.97),
            IncidentObservation(id="obs-002", observed_at=observed_at, source="EDR", kind="credential_access", subject="workstation_a", detail="Credential-store access detected", confidence=0.91),
            IncidentObservation(id="obs-003", observed_at=observed_at, source="DNS", kind="network", subject="workstation_a", detail="Unusual high-entropy DNS queries", confidence=0.83),
            IncidentObservation(id="obs-004", observed_at=observed_at, source="NETFLOW", kind="network", subject="alice", detail="Account initiated SMB traffic to internal host", confidence=0.94),
        ),
    )
