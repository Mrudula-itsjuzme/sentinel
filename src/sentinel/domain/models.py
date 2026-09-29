from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Protocol(StrEnum):
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    POSTGRESQL = "POSTGRESQL"
    SMB = "SMB"
    SSH = "SSH"


class AttackPathKind(StrEnum):
    NETWORK = "NETWORK"
    CREDENTIAL = "CREDENTIAL"
    SESSION = "SESSION"
    SERVICE_TRUST = "SERVICE_TRUST"


class Host(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    sensitive: bool = False
    isolated: bool = False
    assigned_users: tuple[str, ...] = ()


class Service(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    host_id: str
    critical: bool = False


class UserAccount(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    display_name: str
    enabled: bool = True


class Credential(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    account_id: str
    accessible_from_hosts: tuple[str, ...] = ()


class NetworkConnection(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    source: str
    target: str
    protocol: Protocol
    allowed: bool = True
    required_account_id: str | None = None
    legitimate_users: tuple[str, ...] = ()
    path_kind: AttackPathKind = AttackPathKind.NETWORK
    cached_session_account_id: str | None = None


class FirewallRule(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    protocol: Protocol
    allow: bool
    source: str = "*"
    target: str = "*"


class Vulnerability(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    host_id: str
    description: str
    exploitable: bool = True


class BusinessDependency(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    critical: bool = False
    required_service_ids: tuple[str, ...] = ()
    required_connection_ids: tuple[str, ...] = ()
    required_account_ids: tuple[str, ...] = ()


class WorldState(BaseModel):
    """Inspectible ground truth. Mutable copies are created per intervention."""

    scenario_id: str
    hosts: dict[str, Host]
    services: dict[str, Service]
    users: dict[str, UserAccount]
    credentials: dict[str, Credential]
    connections: dict[str, NetworkConnection]
    firewall_rules: dict[str, FirewallRule]
    vulnerabilities: dict[str, Vulnerability]
    business_dependencies: dict[str, BusinessDependency]
    compromised_hosts: set[str] = Field(default_factory=set)
    compromised_accounts: set[str] = Field(default_factory=set)
    revoked_session_accounts: set[str] = Field(default_factory=set)
    restricted_connection_ids: set[str] = Field(default_factory=set)

    def clone(self) -> WorldState:
        return self.model_copy(deep=True)


class SecurityOutcome(BaseModel):
    attack_stopped: bool
    remaining_attack_paths: int
    sensitive_assets_reachable: int
    reachable_sensitive_asset_ids: list[str]


class OperationsOutcome(BaseModel):
    services_disrupted: int
    disrupted_service_ids: list[str]
    users_impacted: int
    impacted_user_ids: list[str]
    estimated_downtime_minutes: int
    payroll_available: bool


class SimulationResult(BaseModel):
    action: str
    target: str
    simulation_succeeded: bool = True
    security: SecurityOutcome
    operations: OperationsOutcome
