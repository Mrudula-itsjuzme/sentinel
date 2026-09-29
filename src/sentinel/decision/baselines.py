from enum import StrEnum

from sentinel.domain.actions import ActionType
from sentinel.domain.decision import CandidateDecision, DecisionBundle, DecisionOutcome, DecisionSelection
from sentinel.policy.engine import PolicyDecision


class Baseline(StrEnum):
    FIRST_VALID_ACTION = "first-valid-action"
    MAXIMUM_SECURITY_ACTION = "maximum-security-action"
    MINIMUM_OPERATIONAL_IMPACT = "minimum-operational-impact"
    POLICY_ONLY = "policy-only-selection"
    MODEL_PREFERRED_ACTION = "nemotron-preferred-action-fixture"
    SENTINEL_COUNTERFACTUAL = "sentinel-counterfactual-selection"


def _act(item: CandidateDecision, reason: str) -> DecisionSelection:
    return DecisionSelection(
        outcome=DecisionOutcome.ACT,
        selected_action=item.candidate.intervention.action.value,
        selected_target=item.candidate.intervention.target,
        rationale=(reason,),
    )


def select_baseline(
    baseline: Baseline,
    bundle: DecisionBundle,
    *,
    model_preferred_action: ActionType | None,
) -> DecisionSelection:
    candidates = list(bundle.candidates)
    if baseline is Baseline.SENTINEL_COUNTERFACTUAL:
        return bundle.selection
    if baseline is Baseline.FIRST_VALID_ACTION:
        valid = next((item for item in candidates if item.simulation.simulation_succeeded), None)
        return _act(valid, "First simulation-successful action in declared order.") if valid else DecisionSelection(outcome=DecisionOutcome.DEFER, rationale=("No valid action.",))
    if baseline is Baseline.MAXIMUM_SECURITY_ACTION:
        winner = min(candidates, key=lambda item: (item.simulation.security.remaining_attack_paths, item.simulation.security.sensitive_assets_reachable, item.candidate.intervention.action.value))
        return _act(winner, "Minimum residual reachability without business or policy weighting.")
    if baseline is Baseline.MINIMUM_OPERATIONAL_IMPACT:
        winner = min(candidates, key=lambda item: (item.utility.operational_cost, item.simulation.operations.estimated_downtime_minutes, item.candidate.intervention.action.value))
        return _act(winner, "Minimum modeled operational cost without security weighting.")
    if baseline is Baseline.POLICY_ONLY:
        allowed = next((item for item in candidates if item.policy.decision is PolicyDecision.ALLOW), None)
        return _act(allowed, "First policy-allowed action in declared order.") if allowed else DecisionSelection(outcome=DecisionOutcome.DEFER, rationale=("Policy allowed no action.",))
    if baseline is Baseline.MODEL_PREFERRED_ACTION:
        preferred = next((item for item in candidates if item.candidate.intervention.action is model_preferred_action), None)
        return _act(preferred, "Controlled model-preference fixture; not live Nemotron inference.") if preferred else DecisionSelection(outcome=DecisionOutcome.DEFER, rationale=("No model-preference fixture is available.",))
    raise ValueError(f"unsupported baseline: {baseline}")

