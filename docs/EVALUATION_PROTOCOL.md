# Sealed evaluation protocol v1

## Freeze boundary

`configs/controller-v1.json` freezes utility weights, policy thresholds, the uncertainty request threshold, and the ranking rule. `configs/sealed-benchmark-v1.json` freezes generator version, disjoint seed ranges, execution seed offset, and bootstrap settings.

The generated manifest records SHA-256 hashes for both configs and a canonical hash of test metadata. Controller v1 must not be changed in response to sealed-test results. A future controller change requires a new controller version and a new untouched test partition.

## Partitions

- Train: 30 scenarios, seeds 1000–1029. Available for future fitting; unused by controller v1.
- Development: 30 scenarios, seeds 2000–2029. Available for future preregistered tuning; unused by controller v1.
- Sealed test: 60 scenarios, seeds 3000–3059. Used only for final v1 evaluation.

There was no tuning in this milestone. The partitioning exists to prevent later work from silently optimizing against the v1 test corpus.

## Generator

Generator v1 varies host and service counts, pivot depth, compromised identity, attack presence, alternate HTTPS paths, critical generated services, and observation quality. Observation controls include missing telemetry, false positives, false negatives, stale vulnerability reports, and conflicting maintenance evidence.

The generated `ScenarioDefinition` contains controller-visible evidence and model-estimate fixtures. `GeneratedMetadata` contains evaluation-only hidden truth. `DecisionBundle` does not serialize hidden labels or world compromise fields.

## Independent execution

Prediction uses `sentinel.simulator`. Observed execution uses separately implemented code in `sentinel.execution` and does not import prediction transitions or reachability. Seeded faults cover partial actions, delayed isolation, incomplete firewall propagation, credential-rotation failure, unexpected restarts, unknown alternate paths, and business-dependency mismatch.

Every selected action produces an `ObservedExecutionOutcome` and `IndependentVerificationReport`. Any action-completion, reachability, business-impact, or critical-service mismatch sets `escalation_required=true`.

## Oracle and regret

The benchmark-only oracle executes every candidate with hidden world state and the same action-specific seed, plus an abstain option. It never enters the production controller or `DecisionBundle` input. Reported regret decomposes into intervention, security, and operational regret.

The oracle is still synthetic: it is an evaluation reference inside this benchmark, not real-world ground truth.

## Statistics

The runner reports per-scenario records and aggregate rates for all six methods. Unsafe-action rate and mean intervention regret receive deterministic percentile bootstrap intervals using 2,000 samples and the frozen bootstrap seed.

## Reproduction

```bash
uv run --no-sync python -m sentinel.sealed_evaluate --output-dir artifacts/sealed-v1
```

Do not edit controller v1 or sealed benchmark v1 after inspecting test results. Create new versioned files instead.

## Sealed benchmark v2

Controller v2 was developed only on generator-v1 train seeds 1000–1029 and development seeds 2000–2029. Before sealed-v2 was opened, its config was frozen at SHA-256 `981a8eecf88a8e46724d1f176e6cdd4a3f9832ee7692b999171eb9bed85a6361`.

Sealed-v2 uses the structurally separate service-centric generator, test seeds 6000–6059, execution offset 900000, and bootstrap seed 92002. Its test metadata hash is `b8aec08aa9a543cec526575ef614e155fe7321547129cd51a1f8982bdfe869f2`. No controller value was changed after results were viewed.

The four methods are Sentinel v1, Sentinel v2, policy-only selection, and minimum-operational-impact (the strongest other deterministic baseline from sealed v1). Evidence usefulness requires a request to change the decision and move it in the hidden-truth-consistent direction. Replanning success is measured only among executions that actually performed a second action.

Joint sensitivity is post-freeze analysis, not refitting. It crosses 0.75x/1.25x security, operations, uncertainty, and evidence threshold factors. `policy-strictness.json` and `decision-boundaries.json` expose deterministic authorization codes and cases near frozen boundaries.

## Sealed benchmark v3

Execution-corpus v1 uses recovery-family train seeds 7000–7059 and development seeds 8000–8039. It measures synthetic action-completion and observation correctness. These values are labeled synthetic execution-model estimates and must not be treated as production reliability probabilities.

Controller v3 was frozen before sealed evaluation at SHA-256 `f25e19ce3696592ff8016dc0d600807e503a07fb0eee37979e16881cba9b0361`. Sealed-v3 uses untouched seeds 9000–9079, test metadata hash `7d5854fb0dfa47f6a479e2dc08a05a90cc233565cef560d83930f3da46ff85c2`, and compares immediate escalation, naïve retry, fixed fallback, and state-estimation recovery.

State accuracy compares controller estimates with hidden executor truth only inside evaluation. False confident success means either high-confidence action application when it was incomplete or estimated path elimination while a hidden path remained. Recovery success requires at least one recovery intervention followed by zero hidden residual paths and an available critical dependency.

## Sealed benchmark v4

V4 recovery analysis used only new train seeds 10000–10079 and development seeds 11000–11059. Controller v4 was frozen at SHA-256 `212c4cabb495977b855cf2873d9a9c579cc4f390b39f11aa8e9b0572f54bf7a8` before sealed-v4 seeds 12000–12099 were generated or inspected.

The benchmark includes parallel paths, cached credentials, partial firewall behavior, benign ambiguity, delayed isolation faults, misleading noisy observations, dependency mismatch, and action-specific failure. Randomized execution makes some mismatches recoverable and others harmful to retry.

Baselines are v3, retry-until-limit, retry-on-partial-success, retry-then-fallback, v4 selective recovery, and an evaluation-only one-step recovery oracle. The oracle chooses the best next option from the replayed recovery point; it is not a global multi-step sequence oracle, which is why a fixed multi-step baseline can outperform it on aggregate resolution.

Failure labels are overlapping causal diagnostics rather than mutually exclusive causes. Regret is decomposed into state-estimation regret for cases with a materially wrong estimate, action-selection regret between the chosen and best replayed option, and execution regret between modeled and observed results.

## Sealed benchmark v5

Sequence-controller development used only train seeds 13000–13079 and development seeds 14000–14059. Controller v5 was frozen at SHA-256 `b8c7aeed9e7d4755a8680ad2ae7d817d50628641aae7472b4bc5f96bd773895e` before sealed seeds 15000–15119 were inspected.

The generator includes cached sessions, credential paths, alternate protocols, independent paths, retry-beneficial and retry-harm patterns, switch-required cases, and synthetic true-escalation cases. Benign cases are retained and correctly resolved by taking no action.

The bounded-sequence oracle enumerates lengths zero through three. It is evaluation-only and sees hidden synthetic outcomes. Production controllers see observations and estimates only. The oracle prefers policy compliance, final resolution, higher security-minus-operational score, fewer steps, and higher estimated execution probability, in that order.

Compared methods are retry-until-limit, retry-then-fallback default, fixed sequence, v4 selective recovery, v5 narrow structural switching, and the bounded-sequence oracle. Metrics include resolution, residual paths, cumulative cost, outages, escalation, policy violations, steps, time-to-resolution, and sequence regret.
