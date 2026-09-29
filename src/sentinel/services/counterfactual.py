from sentinel.domain.actions import INTERVENTIONS
from sentinel.domain.models import SimulationResult, WorldState
from sentinel.simulator.engine import simulate_intervention


def simulate_all(world: WorldState) -> list[SimulationResult]:
    """Evaluate the three frozen MVP interventions in declared order."""

    return [simulate_intervention(world, intervention) for intervention in INTERVENTIONS]

