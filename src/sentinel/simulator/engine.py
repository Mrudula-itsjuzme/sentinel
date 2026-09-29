from sentinel.domain.actions import Intervention, apply_intervention
from sentinel.domain.models import SecurityOutcome, SimulationResult, WorldState
from sentinel.simulator.impact import calculate_operations_impact
from sentinel.simulator.reachability import attack_paths


def simulate_intervention(world: WorldState, intervention: Intervention) -> SimulationResult:
    changed = world.clone()
    apply_intervention(changed, intervention)
    paths = attack_paths(changed)
    reachable = sorted({path[-1] for path in paths})
    return SimulationResult(
        action=intervention.action.value,
        target=intervention.target,
        security=SecurityOutcome(
            attack_stopped=not paths,
            remaining_attack_paths=len(paths),
            sensitive_assets_reachable=len(reachable),
            reachable_sensitive_asset_ids=reachable,
        ),
        operations=calculate_operations_impact(world, changed, intervention),
    )

