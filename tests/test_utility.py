from sentinel.decision.engine import build_decision_bundle
from sentinel.scenarios.suite import scenario_a


def test_utility_components_sum_to_total() -> None:
    item = build_decision_bundle(scenario_a()).candidates[2]
    utility = item.utility
    expected = (
        utility.attack_path_reduction_gain
        + utility.sensitive_exposure_reduction_gain
        - utility.residual_reachability_penalty
        - utility.operational_cost
        - utility.policy_penalty
        - utility.reversibility_penalty
        - utility.uncertainty_penalty
    )
    assert utility.total_utility == round(expected, 4)


def test_uncertainty_ablation_changes_component_only() -> None:
    full = build_decision_bundle(scenario_a())
    ablated = build_decision_bundle(scenario_a(), ignore_uncertainty=True)
    for original, changed in zip(full.candidates, ablated.candidates, strict=True):
        assert changed.utility.uncertainty_penalty == 0
        assert changed.utility.total_utility == original.utility.total_utility + original.utility.uncertainty_penalty

