from sentinel.decision.v4 import execute_with_selective_recovery
from sentinel.evaluation.config import load_controller_config,load_controller_v4_config
from sentinel.evaluation.recovery_replay import analyze_recovery_partition
from sentinel.scenarios.generator_v3 import generate_recovery_partition,generate_recovery_scenario


def test_recovery_replay_decomposes_oracle_and_component_regret():
    scenarios=generate_recovery_partition("dev",11000,8,load_controller_config())
    report=analyze_recovery_partition(scenarios,load_controller_v4_config().controller_v3,1400000)
    assert "oracle_choices" in report
    assert "component_analysis" in report
    assert "targeted_observation_value" in report
    assert all("action_selection_regret" in case for case in report["cases"])


def test_v4_timeline_explains_why_retry_was_rejected():
    generated=generate_recovery_scenario(11001,"dev",load_controller_config())
    run=execute_with_selective_recovery(generated.definition,load_controller_v4_config(),1610010)
    for step in run.bundle.adaptive_resolution.steps:
        decision=step.recovery_decision
        assert decision.rationale
        if decision.outcome.value!="RETRY":
            assert decision.rejected_retry_reason is not None
        assert step.observed_outcome is None


def test_v4_recovery_is_bounded():
    config=load_controller_v4_config()
    for generated in generate_recovery_partition("train",10000,12,load_controller_config()):
        run=execute_with_selective_recovery(generated.definition,config,1600000+generated.metadata.seed*10)
        assert run.bundle.adaptive_resolution.replan_count<=config.recovery.maximum_steps
