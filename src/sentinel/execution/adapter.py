from __future__ import annotations

import random

from sentinel.domain.actions import ActionType, Intervention
from sentinel.domain.execution import ExecutionFaults, ObservedExecutionOutcome
from sentinel.domain.models import WorldState


def _independent_paths(
    world: WorldState,
    active_connections: set[str],
    isolated_hosts: set[str],
    disabled_accounts: set[str],
    credential_bypass_connections: set[str],
    unknown_alternate_path: bool,
    revoked_sessions: set[str],
) -> list[list[str]]:
    adjacency: dict[str, list[str]] = {host: [] for host in world.hosts}
    for connection_id, connection in sorted(world.connections.items()):
        if connection_id not in active_connections:
            continue
        if connection.source in isolated_hosts or connection.target in isolated_hosts:
            continue
        if (
            connection.required_account_id
            and connection.required_account_id in disabled_accounts
            and connection_id not in credential_bypass_connections
        ):
            continue
        if connection.required_account_id and connection.required_account_id not in world.compromised_accounts:
            continue
        if connection.cached_session_account_id:
            if connection.cached_session_account_id not in world.compromised_accounts or connection.cached_session_account_id in revoked_sessions:
                continue
        adjacency[connection.source].append(connection.target)
    if unknown_alternate_path and "workstation_a" in adjacency and "database" in adjacency:
        adjacency["workstation_a"].append("database")
    sensitive = {host.id for host in world.hosts.values() if host.sensitive}
    results: list[list[str]] = []

    def walk(node: str, path: list[str], seen: set[str]) -> None:
        if node in sensitive and len(path) > 1:
            results.append(path)
            return
        for target in adjacency[node]:
            if target not in seen:
                walk(target, [*path, target], {*seen, target})

    for source in sorted(world.compromised_hosts):
        if source not in isolated_hosts:
            walk(source, [source], {source})
    return results


def execute_independently(world: WorldState, intervention: Intervention, seed: int) -> ObservedExecutionOutcome:
    rng = random.Random(seed)
    partial = rng.random() < 0.22
    delayed = intervention.action is ActionType.ISOLATE_HOST and rng.random() < 0.18
    firewall_incomplete = intervention.action in (ActionType.BLOCK_SMB, ActionType.RESTRICT_CONNECTION) and rng.random() < 0.25
    rotation_failed = intervention.action in (ActionType.DISABLE_ACCOUNT, ActionType.REVOKE_SESSION) and rng.random() < 0.2
    restart = rng.random() < 0.12
    unknown_path = rng.random() < 0.1
    dependency_mismatch = rng.random() < 0.1
    faults = ExecutionFaults(
        partial_action=partial,
        delayed_isolation=delayed,
        incomplete_firewall_propagation=firewall_incomplete,
        credential_rotation_failure=rotation_failed,
        unexpected_service_restart=restart,
        unknown_alternate_path=unknown_path,
        dependency_model_mismatch=dependency_mismatch,
    )
    active = set(world.connections)
    isolated: set[str] = set()
    disabled: set[str] = set()
    bypass: set[str] = set()
    fully = True
    if intervention.action is ActionType.ISOLATE_HOST:
        if partial or delayed:
            fully = False
        else:
            isolated.add(intervention.target)
    elif intervention.action is ActionType.BLOCK_SMB:
        smb = sorted(key for key, value in world.connections.items() if value.protocol.value == "SMB")
        if partial or firewall_incomplete:
            fully = False
            active.difference_update(smb[:-1])
        else:
            active.difference_update(smb)
    elif intervention.action is ActionType.DISABLE_ACCOUNT:
        disabled.add(intervention.target)
        if partial or rotation_failed:
            fully = False
            dependent = sorted(key for key, value in world.connections.items() if value.required_account_id == intervention.target)
            if dependent:
                bypass.add(dependent[0])

    revoked_sessions=set(world.revoked_session_accounts)
    if intervention.action is ActionType.REVOKE_SESSION:
        if partial or rotation_failed:
            fully=False
        else:
            revoked_sessions.add(intervention.target)
    elif intervention.action is ActionType.RESTRICT_CONNECTION:
        if partial or firewall_incomplete:
            fully=False
        else:
            active.discard(intervention.target)

    active.difference_update(world.restricted_connection_ids)
    paths = _independent_paths(world, active, isolated, disabled, bypass, unknown_path, revoked_sessions)
    disrupted_services = sum(service.host_id in isolated for service in world.services.values())
    if restart and world.services:
        disrupted_services += 1
    impacted_users = set()
    for host_id in isolated:
        impacted_users.update(world.hosts[host_id].assigned_users)
        for connection in world.connections.values():
            if connection.source == host_id or connection.target == host_id:
                impacted_users.update(connection.legitimate_users)
    impacted_users.update(disabled)
    if intervention.action is ActionType.BLOCK_SMB:
        for connection in world.connections.values():
            if connection.protocol.value == "SMB" and connection.id not in active:
                impacted_users.update(connection.legitimate_users)
    payroll_connection_active = "internal_workstation" in active
    payroll_host_available = "internal_host" not in isolated and not restart
    payroll_account_available = "payroll_service" not in disabled or "internal_workstation" in bypass
    payroll_available = payroll_connection_active and payroll_host_available and payroll_account_available
    if dependency_mismatch:
        payroll_available = not payroll_available
    return ObservedExecutionOutcome(
        action_applied_fully=fully,
        residual_attack_paths=len(paths),
        sensitive_assets_reachable=len({path[-1] for path in paths}),
        services_disrupted=disrupted_services,
        users_impacted=len(impacted_users),
        payroll_available=payroll_available,
        faults=faults,
    )
