from sentinel.domain.models import Protocol, WorldState


def protocol_allowed(world: WorldState, protocol: Protocol) -> bool:
    matching = [rule for rule in world.firewall_rules.values() if rule.protocol == protocol]
    return all(rule.allow for rule in matching)


def connection_available(world: WorldState, connection_id: str) -> bool:
    connection = world.connections[connection_id]
    if connection_id in world.restricted_connection_ids:
        return False
    if not connection.allowed or not protocol_allowed(world, connection.protocol):
        return False
    if world.hosts[connection.source].isolated or world.hosts[connection.target].isolated:
        return False
    if connection.required_account_id:
        account = world.users[connection.required_account_id]
        if not account.enabled:
            return False
    if connection.cached_session_account_id in world.revoked_session_accounts:
        return False
    return True


def service_available(world: WorldState, service_id: str) -> bool:
    service = world.services[service_id]
    return not world.hosts[service.host_id].isolated


def dependency_available(world: WorldState, dependency_id: str) -> bool:
    dependency = world.business_dependencies[dependency_id]
    return (
        all(service_available(world, item) for item in dependency.required_service_ids)
        and all(connection_available(world, item) for item in dependency.required_connection_ids)
        and all(world.users[item].enabled for item in dependency.required_account_ids)
    )
