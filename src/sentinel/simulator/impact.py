from sentinel.domain.actions import ActionType, Intervention
from sentinel.domain.models import OperationsOutcome, WorldState
from sentinel.simulator.world import connection_available, dependency_available, service_available


DOWNTIME_MINUTES = {
    ActionType.ISOLATE_HOST: 30,
    ActionType.BLOCK_SMB: 15,
    ActionType.DISABLE_ACCOUNT: 10,
    ActionType.REVOKE_SESSION: 5,
    ActionType.RESTRICT_CONNECTION: 8,
}


def calculate_operations_impact(
    initial: WorldState, changed: WorldState, intervention: Intervention
) -> OperationsOutcome:
    disrupted = sorted(
        service_id
        for service_id in initial.services
        if service_available(initial, service_id) and not service_available(changed, service_id)
    )
    impacted_users: set[str] = set()

    for host_id, host in changed.hosts.items():
        if host.isolated and not initial.hosts[host_id].isolated:
            impacted_users.update(host.assigned_users)

    for connection_id, connection in changed.connections.items():
        if connection_available(initial, connection_id) and not connection_available(changed, connection_id):
            impacted_users.update(connection.legitimate_users)

    for account_id, account in changed.users.items():
        if initial.users[account_id].enabled and not account.enabled:
            impacted_users.add(account_id)

    return OperationsOutcome(
        services_disrupted=len(disrupted),
        disrupted_service_ids=disrupted,
        users_impacted=len(impacted_users),
        impacted_user_ids=sorted(impacted_users),
        estimated_downtime_minutes=DOWNTIME_MINUTES[intervention.action],
        payroll_available=dependency_available(changed, "payroll"),
    )
