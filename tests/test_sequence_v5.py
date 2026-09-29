from sentinel.decision.v5 import execute_default_sequence
from sentinel.decision.v2 import build_decision_bundle_v2
from sentinel.domain.actions import ActionType,Intervention,apply_intervention
from sentinel.evaluation.config import load_controller_config,load_controller_v4_config,load_controller_v5_config
from sentinel.evaluation.sequence_planner import bounded_sequence_oracle
from sentinel.execution.adapter import execute_independently
from sentinel.scenarios.generator_v5 import generate_sequence_partition,generate_sequence_scenario
from sentinel.simulator.engine import simulate_intervention
from sentinel.simulator.reachability import attack_paths,typed_attack_paths


def test_session_revoke_removes_cached_path_but_not_credential_path():
    generated=generate_sequence_scenario(13000,"train",load_controller_config())
    world=generated.definition.world
    if not generated.metadata.true_attack or not any(connection.cached_session_account_id for connection in world.connections.values()):
        generated=next(item for item in generate_sequence_partition("train",13000,30,load_controller_config()) if item.metadata.true_attack and any(connection.cached_session_account_id for connection in item.definition.world.connections.values()))
        world=generated.definition.world
    before=typed_attack_paths(world)
    changed=world.clone(); apply_intervention(changed,Intervention(action=ActionType.REVOKE_SESSION,target="operator"))
    after=typed_attack_paths(changed)
    assert any("SESSION" in path["path_kinds"] for path in before)
    assert all("SESSION" not in path["path_kinds"] for path in after)
    assert len(after)<=len(before)


def test_targeted_restriction_simulation_and_execution_contract():
    generated=next(item for item in generate_sequence_partition("train",13000,30,load_controller_config()) if item.metadata.true_attack and "cached_https" in item.definition.world.connections)
    intervention=Intervention(action=ActionType.RESTRICT_CONNECTION,target="cached_https")
    prediction=simulate_intervention(generated.definition.world,intervention)
    assert prediction.security.remaining_attack_paths < len(attack_paths(generated.definition.world))
    assert execute_independently(generated.definition.world,intervention,777)==execute_independently(generated.definition.world,intervention,777)


def test_new_actions_have_policy_and_verification_contracts():
    generated=next(item for item in generate_sequence_partition("train",13000,30,load_controller_config()) if item.metadata.true_attack and any(candidate.intervention.action is ActionType.REVOKE_SESSION for candidate in item.definition.candidates))
    bundle=build_decision_bundle_v2(generated.definition,load_controller_v4_config().controller_v3.controller_v2)
    for action in (ActionType.REVOKE_SESSION,ActionType.RESTRICT_CONNECTION):
        candidates=[item for item in bundle.candidates if item.candidate.intervention.action is action]
        if candidates:
            assert candidates[0].policy.code
            assert candidates[0].verification_plan.checks
            assert candidates[0].verification_result.passed


def test_sequence_oracle_is_bounded_and_policy_compliant():
    generated=generate_sequence_scenario(13001,"train",load_controller_config())
    best,plans=bounded_sequence_oracle(generated,load_controller_v4_config(),load_controller_v5_config(),1900000)
    assert best.steps<=3
    assert best.policy_compliant
    assert all(plan.steps<=3 for plan in plans)


def test_structural_switch_is_narrow_and_explained():
    switched=[]
    for generated in generate_sequence_partition("dev",14000,60,load_controller_config()):
        run=execute_default_sequence(generated.definition,load_controller_v4_config(),load_controller_v5_config(),1900000+generated.metadata.seed*10,enable_structural_switch=True)
        for step in run.bundle.adaptive_resolution.steps:
            if step.recovery_decision.structural_switch_evidence:
                switched.append(step)
                assert step.state_estimate.action_applied_probability>=load_controller_v5_config().confirmed_application_threshold
                assert step.recovery_decision.rejected_retry_reason=="confirmed distinct residual path"
    assert switched


def test_retry_then_fallback_is_default_without_switch_exception():
    generated=generate_sequence_scenario(14003,"dev",load_controller_config())
    run=execute_default_sequence(generated.definition,load_controller_v4_config(),load_controller_v5_config(),1940030,enable_structural_switch=False)
    outcomes=[step.recovery_decision.outcome.value for step in run.bundle.adaptive_resolution.steps]
    assert all(outcome in {"ACCEPT","RETRY","COMPENSATE","ESCALATE"} for outcome in outcomes)
    assert "SWITCH_ACTION" not in outcomes
