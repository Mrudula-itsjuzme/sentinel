# Failure analysis

Failure counts are generated in `artifacts/sealed-v1/failure-taxonomy.json` separately for every decision method.

## Taxonomy

- `wrong_hypothesis_or_false_positive`: an action created operational impact when hidden truth contained no attack.
- `incomplete_evidence`: missing or false-negative telemetry contributed to residual risk or abstention.
- `policy_too_permissive`: policy allowed an action whose observed result caused a critical outage.
- `policy_too_restrictive`: a true attack was deferred because every candidate was denied.
- `execution_mismatch`: independent observed execution differed from the predicted contract.
- `hidden_alternate_attack_path`: execution exposed an attack path absent from prediction.
- `incorrect_business_dependency_model`: observed critical-service availability differed because the modeled dependency was wrong.
- `utility_or_ranking_regret`: selection was below the benchmark-only oracle without another classified failure.
- `unsafe_abstention_or_defer`: a true attack received no immediate action.

## Interpretation rules

Counts are events, not mutually exclusive incident totals. A single decision can have multiple causes. The taxonomy is diagnostic and deterministic, but causal attribution remains limited because the generator controls correlated faults.

The v1 sealed artifacts show that Sentinel's dominant failures are unsafe abstention under true attacks, overly restrictive policy, and execution mismatch. This means the earlier five-scenario result does not generalize cleanly. The next controller must not be tuned against the v1 sealed test; changes should be developed on train/dev and evaluated on a new sealed test version.

## Controller v2 findings

V2 reduced unsafe abstention from 36 v1 cases to 4 and had no policy violations, but produced 37 execution mismatches and 37 escalations. Nineteen mismatches ended with residual or operational failure; only one case reached a second action and it did not recover. The immediate critical-mismatch escalation rule prevented blind retries but also made the replanning capability mostly dormant.

Policy v2 denied 86/180 candidates for critical-service disruption, allowed 34 candidates through the reversible contextual rule, and left no scenario with every candidate denied. The policy was therefore less globally restrictive without becoming permissive under the benchmark's policy-violation definition. However, observed critical outages still rose, demonstrating that authorization safety depends on execution-model validity.

The strengthened claim is limited: adaptive v2 reduced unsafe abstention and final residual risk versus v1 and policy-only on a different synthetic family. The failed claim is equally important: it did not reduce execution failure or operational harm versus v1, and it increased intervention regret.

## Controller v3 findings

V3 produced 35 escalations versus 40 for immediate escalation, including 11 versus 15 unnecessary escalations. It left residual risk in 18/80 scenarios, compared with 14 for immediate escalation and 16 for naïve retry. Two controller-v3 cases were falsely confident about success.

The estimator was strongest on critical dependency state and weakest on action application. Recovery rules remained too conservative or selected imperfect alternatives: v3 recovered 61.11% of cases where it actually attempted recovery, below naïve retry's 75.86%. The frozen retry policy deliberately rejected unreliable account-disable retries, but this selective behavior did not compensate for switching and escalation errors.

This benchmark does not support claiming intelligent recovery superiority. It supports the narrower claim that post-action belief can be represented and audited without exposing executor truth, and that such a controller can modestly reduce immediate escalation while retaining deterministic authorization.

## Controller v4 decomposition

Sealed-v4 contained 38 replayable initial mismatches. Overlapping labels were:

- correct estimate but wrong recovery action: 20;
- incorrect state estimate: 15;
- hidden alternate path: 27;
- missing candidate action, usually cached-token revocation: 11;
- retry would have succeeded but Sentinel switched: 4;
- correct action followed by execution failure: 1.

No sealed case was classified as policy blocking a useful recovery, insufficient observation, or delayed-effect timing under the frozen definitions. That absence should not be generalized beyond this generator.

The dominant v4 failure was the recovery mapping. Structural-path heuristics overinterpreted residual indicators, while false critical or service signals caused conservative escalation. Targeted evidence did not reliably repair these beliefs: only one authentication and four service-health follow-ups removed any component errors, and every observation family had negative mean net value.

Retry-then-fallback remains the benchmark winner. Selective recovery was useful only in the narrower condition where an action was confidently applied, a distinct residual route remained, and an authorized alternative addressed that route without critical-service harm. Those cases were too rare and too noisily detected to offset incorrect switches and escalations.

## Controller v5 sequence losses

Against the bounded three-step oracle, structural switching lost through overlapping causes:

- wrong sequence: 80;
- hidden alternate path: 75;
- execution failure: 53;
- unnecessary escalation: 43;
- bad state estimate: 20;
- insufficient action horizon: 17;
- missing action: 5.

The added session-revocation and targeted-connection actions materially expanded recoverability, but action coverage is still incomplete in five cases. The much larger wrong-sequence count means adding more actions alone is unlikely to close the gap.

Narrow switching helped when session or credential remediation was confirmed and a different typed path remained. It hurt when noisy residual indicators were mistaken for structural persistence or when the alternative action failed independently. The product default therefore remains retry once, then fallback; any switch must retain its typed evidence and rejected-retry explanation in the audit trail.
