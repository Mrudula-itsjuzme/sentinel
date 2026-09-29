# Controlled evaluation summary

These results use deterministic scenario fixtures, including model preferences and uncertainty estimates. They are not live Nemotron benchmark results.

| method | scenarios | actions | unsafe_action_rate | policy_violation_rate | critical_service_outage_rate | unnecessary_disruption_rate | mean_regret | safe_abstentions | useful_evidence_requests | prediction_error_rate |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| first-valid-action | 5 | 5 | 0.8 | 0.6 | 0.8 | 0.2 | 81.84 | 0 | 0 | 0.0 |
| maximum-security-action | 5 | 5 | 0.6 | 0.4 | 0.6 | 0.2 | 45.4 | 0 | 0 | 0.0 |
| minimum-operational-impact | 5 | 5 | 0.4 | 0.2 | 0.2 | 0.2 | 35.36 | 0 | 0 | 0.0 |
| policy-only-selection | 5 | 4 | 0.2 | 0.0 | 0.2 | 0.2 | 7.92 | 0 | 0 | 0.0 |
| nemotron-preferred-action-fixture | 5 | 5 | 0.8 | 0.6 | 0.8 | 0.2 | 87.82 | 0 | 0 | 0.0 |
| sentinel-counterfactual-selection | 5 | 3 | 0.0 | 0.0 | 0.0 | 0.0 | 0.0 | 1 | 1 | 0.0 |
