import inspect

from sentinel.decision.v3 import execute_with_recovery
from sentinel.evaluation.config import load_controller_config, load_controller_v3_config
from sentinel.execution import estimator
from sentinel.execution.adapter import execute_independently
from sentinel.execution.estimator import estimate_execution_state
from sentinel.execution.observation import observe_execution
from sentinel.scenarios.generator_v3 import generate_recovery_scenario
from sentinel.simulator.engine import simulate_intervention


def test_estimator_source_does_not_read_hidden_execution_outcome():
    source = inspect.getsource(estimator)
    assert "ObservedExecutionOutcome" not in source
    assert "faults" not in source


def test_observations_are_distinct_from_hidden_truth_and_estimate_is_typed():
    scenario = generate_recovery_scenario(7000, "train", load_controller_config()).definition
    candidate = scenario.candidates[0]
    hidden = execute_independently(scenario.world, candidate.intervention, 1070000)
    observations = observe_execution(candidate.intervention, hidden, 1070000)
    estimate = estimate_execution_state(candidate.intervention, simulate_intervention(scenario.world, candidate.intervention), observations, load_controller_v3_config().estimator)
    assert observations
    assert all(not hasattr(item, "residual_attack_paths") for item in observations)
    assert 0 <= estimate.action_applied_probability <= 1
    assert estimate.observation_ids == tuple(item.id for item in observations)


def test_recovery_timeline_omits_hidden_outcome_and_is_bounded():
    generated = generate_recovery_scenario(8001, "dev", load_controller_config())
    config = load_controller_v3_config()
    run = execute_with_recovery(generated.definition, config, 1280010)
    for step in run.bundle.adaptive_resolution.steps:
        assert step.observed_outcome is None
        assert step.state_estimate is not None
        assert step.post_execution_observations
        assert step.recovery_decision is not None
    assert run.bundle.adaptive_resolution.replan_count <= config.recovery.maximum_steps


def test_recovery_generator_is_reproducible_and_has_noncritical_fallbacks():
    controller = load_controller_config()
    left = generate_recovery_scenario(42, "train", controller)
    right = generate_recovery_scenario(42, "train", controller)
    assert left.definition.world == right.definition.world
    assert left.metadata == right.metadata
    assert left.definition.world.connections["internal_workstation"].protocol.value == "HTTPS"
