from sentinel.domain.models import AttackPathKind, WorldState
from sentinel.simulator.world import connection_available


def _attack_connection_available(world: WorldState, connection_id: str) -> bool:
    connection = world.connections[connection_id]
    if not connection_available(world, connection_id):
        return False
    if connection.required_account_id:
        return connection.required_account_id in world.compromised_accounts
    if connection.cached_session_account_id:
        return connection.cached_session_account_id in world.compromised_accounts and connection.cached_session_account_id not in world.revoked_session_accounts
    return True


def attack_paths(world: WorldState) -> list[list[str]]:
    """Return all simple paths from compromised hosts to sensitive assets."""

    adjacency: dict[str, list[tuple[str, str]]] = {host_id: [] for host_id in world.hosts}
    for connection_id, connection in sorted(world.connections.items()):
        if _attack_connection_available(world, connection_id):
            adjacency[connection.source].append((connection.target, connection_id))

    paths: list[list[str]] = []
    sensitive = {host.id for host in world.hosts.values() if host.sensitive}

    def visit(current: str, path: list[str], seen: set[str]) -> None:
        if current in sensitive and len(path) > 1:
            paths.append(path)
            return
        for target, _ in adjacency[current]:
            if target not in seen:
                visit(target, [*path, target], {*seen, target})

    for source in sorted(world.compromised_hosts):
        if not world.hosts[source].isolated:
            visit(source, [source], {source})
    return paths


def typed_attack_paths(world: WorldState) -> list[dict[str, object]]:
    """Inspectable multi-domain paths used by bounded recovery planning."""
    adjacency: dict[str,list[tuple[str,str]]]={host:[] for host in world.hosts}
    for connection_id,connection in sorted(world.connections.items()):
        if _attack_connection_available(world,connection_id): adjacency[connection.source].append((connection.target,connection_id))
    sensitive={host.id for host in world.hosts.values() if host.sensitive}; results=[]
    def visit(node,hosts,connections,seen):
        if node in sensitive and len(hosts)>1:
            edges=[world.connections[item] for item in connections]
            results.append({"hosts":tuple(hosts),"connection_ids":tuple(connections),"path_kinds":tuple(dict.fromkeys(edge.path_kind.value for edge in edges)),"accounts":tuple(dict.fromkeys(item for edge in edges for item in (edge.required_account_id,edge.cached_session_account_id) if item))})
            return
        for target,connection_id in adjacency[node]:
            if target not in seen: visit(target,[*hosts,target],[*connections,connection_id],{*seen,target})
    for source in sorted(world.compromised_hosts):
        if not world.hosts[source].isolated: visit(source,[source],[],{source})
    return results
