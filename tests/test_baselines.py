from sentinel.decision.baselines import Baseline, select_baseline
from sentinel.decision.engine import build_decision_bundle
from sentinel.domain.decision import DecisionOutcome
from sentinel.policy.engine import PolicyDecision
from sentinel.scenarios.suite import scenario_a, scenario_b, scenario_d, scenario_e


def test_baselines_make_distinct_decisions() -> None:
    scenario = scenario_a()
    bundle = build_decision_bundle(scenario)
    first = select_baseline(Baseline.FIRST_VALID_ACTION, bundle, model_preferred_action=scenario.model_preferred_action)
    sentinel = select_baseline(Baseline.SENTINEL_COUNTERFACTUAL, bundle, model_preferred_action=scenario.model_preferred_action)
    assert first.selected_action == "ISOLATE_HOST"
    assert sentinel.selected_action == "DISABLE_ACCOUNT"


def test_maximum_security_can_choose_policy_denied_action() -> None:
    scenario = scenario_b()
    bundle = build_decision_bundle(scenario)
    selection = select_baseline(Baseline.MAXIMUM_SECURITY_ACTION, bundle, model_preferred_action=scenario.model_preferred_action)
    selected = next(item for item in bundle.candidates if item.candidate.intervention.action.value == selection.selected_action and item.candidate.intervention.target == selection.selected_target)
    assert selected.policy.decision is PolicyDecision.DENY


def test_policy_only_uses_first_allowed_action() -> None:
    scenario = scenario_e()
    bundle = build_decision_bundle(scenario)
    selection = select_baseline(Baseline.POLICY_ONLY, bundle, model_preferred_action=scenario.model_preferred_action)
    assert selection.selected_action == "DISABLE_ACCOUNT"


def test_missing_model_preference_defers() -> None:
    scenario = scenario_d().follow_up
    bundle = build_decision_bundle(scenario)
    selection = select_baseline(Baseline.MODEL_PREFERRED_ACTION, bundle, model_preferred_action=None)
    assert selection.outcome is DecisionOutcome.DEFER
