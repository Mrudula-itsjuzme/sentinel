from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from sentinel.domain.models import FirewallRule, Protocol, WorldState


class ActionType(StrEnum):
    ISOLATE_HOST = "ISOLATE_HOST"
    BLOCK_SMB = "BLOCK_SMB"
    DISABLE_ACCOUNT = "DISABLE_ACCOUNT"
    REVOKE_SESSION = "REVOKE_SESSION"
    RESTRICT_CONNECTION = "RESTRICT_CONNECTION"


class Reversibility(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Intervention(BaseModel):
    model_config = ConfigDict(frozen=True)

    action: ActionType
    target: str
    destructive: bool = False
    reversibility: Reversibility = Reversibility.HIGH


INTERVENTIONS: tuple[Intervention, ...] = (
    Intervention(action=ActionType.ISOLATE_HOST, target="workstation_a"),
    Intervention(action=ActionType.BLOCK_SMB, target="SMB"),
    Intervention(action=ActionType.DISABLE_ACCOUNT, target="alice"),
)


def apply_intervention(world: WorldState, intervention: Intervention) -> None:
    """Apply a validated intervention to a counterfactual clone in place."""

    if intervention.action is ActionType.ISOLATE_HOST:
        host = world.hosts.get(intervention.target)
        if host is None:
            raise ValueError(f"unknown host: {intervention.target}")
        world.hosts[host.id] = host.model_copy(update={"isolated": True})
        return

    if intervention.action is ActionType.BLOCK_SMB:
        world.firewall_rules["response_block_smb"] = FirewallRule(
            id="response_block_smb", protocol=Protocol.SMB, allow=False
        )
        return

    if intervention.action is ActionType.DISABLE_ACCOUNT:
        account = world.users.get(intervention.target)
        if account is None:
            raise ValueError(f"unknown account: {intervention.target}")
        world.users[account.id] = account.model_copy(update={"enabled": False})
        return

    if intervention.action is ActionType.REVOKE_SESSION:
        if intervention.target not in world.users:
            raise ValueError(f"unknown account: {intervention.target}")
        world.revoked_session_accounts.add(intervention.target)
        return

    if intervention.action is ActionType.RESTRICT_CONNECTION:
        if intervention.target not in world.connections:
            raise ValueError(f"unknown connection: {intervention.target}")
        world.restricted_connection_ids.add(intervention.target)
        return

    raise ValueError(f"unsupported action: {intervention.action}")
