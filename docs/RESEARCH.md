# Research design

## Research question

Does explicit counterfactual intervention testing reduce policy-violating, operationally unnecessary, or security-incomplete incident-response decisions compared with direct recommendation and simpler deterministic policies?

The original milestone evaluated mechanics on five controlled scenarios. Sealed benchmark v1 now evaluates an unchanged controller on 60 generated test scenarios plus independent seeded execution. It still does **not** establish real-world security effectiveness or live Nemotron quality.

Controller v2 asks a narrower follow-up question: can adaptive evidence acquisition and verification-driven replanning reduce unsafe abstention and execution failure without increasing policy violations or operational harm? The sealed-v2 answer is mixed: unsafe abstention and residual risk improved, but operational harm and regret increased.

## Controller v2

The evidence decision estimates `expected decision improvement + avoidable operational harm - acquisition cost - attack-path-weighted delay cost`. A request is permitted only when resolving uncertainty could change action necessity or rank, the utility margin is decision-sensitive, and net value exceeds the frozen minimum. This is interpretable value-of-information accounting, not a calibrated probability model.

Policy v2 keeps destructive, downtime, and critical-service denials. It adds one deterministic exception for highly reversible actions that stop all modeled paths, have verification available, and stay within a contextual user-impact bound. A critical-service exception additionally requires multiple pre-action attack paths. These changes were selected from generator-v1 train/dev failures, not either sealed test.

Replanning is bounded to two alternatives, excludes the failed action, recomputes simulation, policy, and utility on accumulated fully applied actions, and escalates immediately on critical-service mismatch. Partial actions remain observed outcomes rather than assumed state transitions.

Generator v2 changes topology and observations: service-tier fan-out/mesh patterns, chained service identities, service dependencies, token-lineage/application traces, and a service-control-plane failure label. It is not a seed-only extension of generator v1.

## Sealed-v2 result

On 60 frozen generator-v2 scenarios, v2 reduced unsafe rate from 0.6833 (v1) and 0.8167 (policy-only) to 0.4167, and unsafe abstention from 0.6000 to 0.0667, with zero policy violations. It did **not** dominate v1: critical outage rose from 0.0167 to 0.1333, mean cumulative operational cost from 0.6667 to 9.7333, and mean regret from 3.5000 to 10.9667. Verification mismatch was 0.9024, escalation 0.6167, and only one scenario actually replanned; it did not recover. Three evidence requests were made and all three met the benchmark usefulness definition, which is too small a sample for a strong claim.

Joint 0.75x/1.25x perturbations of security, operations, uncertainty, and evidence threshold produced decision-flip rates from 0 to 0.5333, act rates from 0.15 to 0.75, and request rates from 0 to 0.0833. This sensitivity and the operational regression argue against adding more utility knobs.

## Controller v3 research question

Can explicit post-action state estimation and bounded recovery reduce unnecessary escalation and execution failure compared with controllers that assume requested actions were successfully applied?

On sealed-v3, estimator action-state accuracy was 0.8103, residual-state accuracy 0.8793, critical-state accuracy 0.9655, and false-confident success 0.0345. Mismatch detection was 0.9355 with zero-step delay for detected cases.

V3 reduced escalation from 0.5000 under immediate escalation to 0.4375 and unnecessary escalation from 0.1875 to 0.1375. Recovery success was 0.6111. However, naïve retry achieved 0.7586 recovery success, 0.1125 escalation, lower residual risk (0.2000 versus 0.2875), and lower cumulative operational cost (10.7875 versus 11.7125). V3 had higher regret than immediate escalation and naïve retry.

The only robustly strengthened claims are that controller-visible observations can estimate several hidden state components with useful synthetic accuracy, reduce false confidence, and modestly reduce escalation relative to immediate escalation. The main recovery hypothesis failed against naïve retry on this benchmark.

## Controller v4: when should Sentinel not retry?

The refined question was: when does post-action state estimation justify switching away from simple retry, and can selective recovery reduce regret without increasing operational harm?

Train/dev recovery replay showed that retry was the best immediate choice in only 9/50 mismatches; escalation was best in 26 and switching in 15. However, state-estimation errors were concentrated in decision-relevant components—especially alternate paths and service health—and v3 also switched away from six cases where retry would have been best. Targeted follow-up observations had negative mean net value for every observation family; service health was useful in only 2/16 development cases.

Sealed-v4 rejected selective recovery superiority. Retry-then-fallback achieved 0.9444 recovery success, 0.71 final resolution, 0.15 mean residual risk, 6.33 operational cost, and 7.06 regret. V4 achieved 0.2857 recovery success, 0.44 final resolution, 0.36 residual risk, 7.03 cost, and 17.525 regret. Retry-until-limit was also substantially stronger than v4.

At 38 sealed recovery points, the one-step oracle preferred escalation 26 times, switching 6, and retry 6. Yet v4 had 20 correct-estimate/wrong-action failures versus 15 incorrect-estimate failures. Mean action-selection regret was 33.1053, state-estimation regret 9.3421, and execution regret 26.1. This answers the causal question: v4 more often understood the bounded state well enough but mapped it to the wrong recovery decision.

Component headline accuracy was misleading. Alternate-path accuracy was 0.7368 with 27.8 mean regret when wrong; service-health accuracy was 0.8684 with the same conditional regret. A single network-reachability error carried 62.0 regret. In contrast, several high-accuracy critical/dependency errors produced no measured selection regret in this sealed sample.

The claim strengthened is narrow: offline recovery replay can identify whether perception, choice, or execution dominated a failure, and selective switching is justified when a high-confidence applied action leaves a structurally distinct path. The rejected claim is that the implemented selective controller beats bounded retry. It does not.

## Controller v5: bounded sequence recovery

The research question was: does sequence-level recovery with narrow structural switching improve over bounded retry-then-fallback when the action space includes realistic identity/session remediation and alternate attack paths?

The action-space expansion was strongly useful to the evaluation oracle. Its most frequent resolved sequence was session revocation followed by account disable (25/120), followed by account disable alone (19), targeted cached-HTTPS restriction followed by account disable (11), and session revocation followed by SMB blocking (10). The oracle used two steps in 54 cases and three in 23; this shows the earlier one-step action space was materially limiting.

On sealed-v5, structural switching modestly improved the retry-then-fallback default: resolution 0.3000 versus 0.2750, cost 12.10 versus 12.9417, critical outages 0.2917 versus 0.3083, escalation 0.5083 versus 0.5417, and regret 34.6069 versus 35.6292. It slightly worsened mean residual risk, 1.0667 versus 1.0583. Structural switching occurred in 19.17% of scenarios.

The bounded-sequence oracle remained much stronger: 0.8333 resolution, 0.1417 residual risk, 3.25 cost, 0.025 outage, and 1.6833 mean steps. Therefore simple bounded sequences are not sufficient in the expanded path space, but the production controller has not learned to choose the oracle sequences reliably.

Loss attribution against the oracle was dominated by wrong sequence (80), hidden alternate paths (75), execution failure (53), unnecessary escalation (43), bad state estimate (20), insufficient three-step horizon (17), and missing action (5). No policy-restriction loss was observed under the frozen definition.

The strengthened claim is narrow: typed-path evidence can justify occasional deviations from retry-then-fallback and improve several aggregate safety/cost metrics. The rejected claim is that narrow structural switching closes the sequence-oracle gap or improves every metric. It does neither. Retry-then-fallback remains the product default; structural switching is an inspectable exception.

## Hypotheses

- H1: Counterfactual selection with policy enforcement will reduce policy-violating actions relative to first-valid, maximum-security, and model-preferred selection.
- H2: Modeling business impact will reduce critical-service outages and unnecessary disruption.
- H3: Explicit uncertainty handling will produce safe evidence requests or abstentions in ambiguous incidents.
- H4: Multi-path simulation will avoid interventions that block only the most obvious path.

## Variables

Independent variables:

- decision policy;
- policy enforcement enabled or removed;
- uncertainty penalty and evidence-request gate enabled or removed;
- business-impact cost enabled or removed;
- scenario topology, hidden ground truth, evidence, and controlled model-estimate fixture.

Dependent variables:

- unsafe action and policy-violation rates;
- residual and reduced attack paths;
- critical-service outage and unnecessary-disruption rates;
- utility and regret relative to the best policy-allowed candidate under the declared utility;
- safe abstention and useful evidence-request counts;
- simulated prediction error.

## Utility

The default deterministic score is:

```text
utility =
    35 * normalized attack-path reduction
  + 25 * normalized sensitive-exposure reduction
  - 30 * normalized residual attack reachability
  - 12 * disrupted services
  -  3 * impacted users
  -  0.2 * downtime minutes
  - 25 if payroll is unavailable
  - 100 if policy denies the action
  - reversibility penalty (0 high, 5 medium, 12 low)
  - 20 * model-estimated uncertainty
```

Every term is exposed in `UtilityBreakdown`; weights are typed and configurable. The normalization denominator is at least one, so a zero-path false-positive scenario does not create division-by-zero or artificial security gain. The weights are engineering assumptions for controlled comparison, not learned facts. Sensitivity analysis is still required.

## Baselines

- `first-valid-action`: first simulation-successful candidate, ignoring policy and comparative outcomes.
- `maximum-security-action`: least residual reachability, ignoring operations and policy.
- `minimum-operational-impact`: smallest operational cost, ignoring security effectiveness.
- `policy-only-selection`: first policy-allowed candidate, without utility ranking or uncertainty abstention.
- `nemotron-preferred-action-fixture`: controlled model-preference fixture. This is not a live Nemotron benchmark.
- `sentinel-counterfactual-selection`: policy-eligible positive-utility maximum with uncertainty-driven evidence requests.

## Controlled scenarios

1. Payroll-linked lateral movement: all three actions stop the path, but isolation and SMB blocking disrupt payroll. Its deliberately permissive policy isolates the contribution of business-impact utility.
2. Critical service credential compromise: each available containment has a critical operational consequence.
3. Public web compromise: only web-server isolation stops the modeled database route.
4. Ambiguous telemetry: hidden ground truth is benign; endpoint telemetry changes the decision from `REQUEST_MORE_EVIDENCE` to `DEFER`.
5. Two-path attack: SMB blocking leaves an HTTPS route; account disabling stops both.

Each scenario keeps evidence separate from simulator-only hidden state. `DecisionBundle` never serializes the world or compromised-state fields.

## Ablations

The runner evaluates full Sentinel and variants without policy, uncertainty handling, or business-impact cost. The model-preference and policy-only baselines also serve as no-counterfactual-ranking controls. These are component ablations, not statistical causal estimates.

## Reproduction

```bash
uv run python -m sentinel.evaluate --output-dir artifacts/evaluation
```

The command generates detailed JSON, CSV, Markdown summary, ablation JSON, and a sample `DecisionBundle`. Outputs are generated from code, not manually copied into this document.

The sealed benchmark is reproduced separately:

```bash
uv run --no-sync python -m sentinel.sealed_evaluate --output-dir artifacts/sealed-v1
```

See `docs/EVALUATION_PROTOCOL.md` for the freeze boundary, partitions, oracle, independent execution design, and statistics. See generated aggregate metrics for exact results.

## Limitations

- The sealed generator is broader than five hand-authored scenarios but is still synthetic and uses one generator family.
- Model preferences, confidence, and uncertainty are explicitly labeled controlled fixtures; live Nemotron calls were not used in these results.
- Utility weights encode designer preference. One-at-a-time 0.5x/1.5x sensitivity is implemented, but wider and joint perturbations remain untested.
- The oracle and regret metric use the same simulator and utility as Sentinel, favoring internal consistency rather than external validity.
- Independent execution is separately implemented but remains synthetic.
- Bootstrap intervals describe variation across generated scenarios, not sampling from a real incident population.
- No real telemetry, analyst study, sandbox execution, or live Nemotron repeatability measurements exist yet.
- Replanning accumulation only commits actions reported fully applied; partial physical effects are not reconstructed.
- Generator-v2 independent execution retains a synthetic failure model and exposes a severe simulator/executor mismatch.
- The recovery generator and observation channel share synthetic design assumptions, so state-estimation accuracy is internal validity evidence only.
- V3 does not yet reconstruct partial state components; it commits only highly confident complete transitions to its belief world.
- The v4 one-step oracle is not a global sequence optimizer, and the causal labels share synthetic causes and may overlap.
- The observation-value calculation measures component-error reduction, not analyst or production information value.
- The sequence oracle optimizes synthetic realized executions and is an upper-bound diagnostic, not a deployable planner or real-world optimum.
- Mean steps-to-resolution includes benign zero-action resolutions and must be interpreted alongside pattern-stratified results.
