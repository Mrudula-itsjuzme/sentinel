# Architecture

Sentinel separates untrusted proposal, simulation, policy, simulated execution, and verification. Real infrastructure execution does not exist.

```text
evidence -> prompt -> Nebius/Nemotron -> local schema + grounding validation
                                      |
                                      v
                               typed proposals
                                      |
scenario -----------------------------+
       |
       v
counterfactual service ----------> clone world x 3
       |                    |
       |                    v
       |              intervention
       |                    |
       v                    v
structured results <- reachability + operational impact
       |
       v
deterministic policy -> ALLOW / DENY + code
```

## Modules

- `domain`: typed world, evidence, actions, and outcome contracts.
- `scenarios`: reproducible world and observations. Evidence never changes ground truth.
- `simulator`: connection availability, reachability, impacts, and single-action execution against a clone.
- `services`: orchestrates the frozen set of three counterfactuals.
- `reasoning`: strict proposal types, evidence-only prompts, and semantic boundary validation.
- `providers`: isolated external inference transport; currently Nebius Token Factory.
- `decision`: utility decomposition, verification contracts, baselines, selection, and the canonical `DecisionBundle`.
- `evaluation`: reproducible scenario-by-method metrics and ablations.
- `execution`: independently coded seeded execution outcomes and mismatch verification; it does not import simulator transitions.
- `policy`: deterministic rules with no model dependency.
- `api`: a thin transport layer; it contains no simulation logic.
- `services/incidents`: the product loop, in-memory report store, and structured audit timeline.
- `web`: a dependency-free dashboard that renders only API state and checked-in experiment data.

## Product loop

`POST /incidents` creates a report with explicit detected, observed, reasoned, proposed, policy-approved or policy-rejected, executing, succeeded or failed, verified, and escalated states. Timestamps and the incident ID identify each event; evidence IDs, action, target, policy result, execution result, and deterministic/model provenance are structured fields rather than prose-only logs.

The default product demo applies an authorized action only to a cloned `WorldState`. Verification recomputes attack paths and the payroll dependency from the changed state. A policy-rejected proposal can trigger a supported lower-impact fallback, but policy is evaluated again and never bypassed.

## AI trust boundary

Nemotron receives the incident observations and the exact supported action/target pairs. It does not receive simulation results. Token Factory is asked for strict JSON-schema output, then Sentinel independently parses the response with Pydantic and rejects unknown fields, malformed structures, mismatched incident IDs, nonexistent evidence IDs, duplicate actions, unsupported targets, and inconsistent insufficient-evidence declarations. A proposal is not an authorization decision.

The provider adapter uses the OpenAI-compatible Token Factory chat-completions endpoint directly through `httpx`. This keeps the external dependency small and makes all normal tests network-free.

## Decision artifact

`DecisionBundle` is the frontend-facing product contract. It contains evidence, hypotheses, explicitly named model-estimated uncertainty, candidate simulations, policy decisions, utility components, selection or abstention, verification plans/results, concise rationale, and audit metadata. It intentionally excludes hidden world state and chain-of-thought.

After an independently simulated execution, the bundle also exposes observed outcome, mismatch fields, verification status, and whether escalation is required.

Controller v2 extends the bundle with an adaptive resolution timeline: initial decision, evidence-value estimate, requested evidence, revised uncertainty and belief summary, execution/verification steps, replans, cumulative operational cost, final residual risk, resolution, and escalation status. This is the intended future UI story; no frontend or real remediation exists yet.

## Execution-state separation

Controller v3 makes three objects distinct:

1. The prediction model computes what should happen if an intervention applies as modeled.
2. The execution world injects hidden partial actions and dependency failures. Its `ObservedExecutionOutcome` is evaluation-only in v3.
3. The state estimator consumes only action receipts, connectivity/authentication probes, service health, dependency status, endpoint telemetry, and attack-path indicators.

`ExecutionStateEstimate` reports action-application probability, estimated residual paths, critical-service availability probability, confirmed and inferred changes, unknowns, and contradicted predictions. The v3 `DecisionBundle` steps contain controller-visible observations and estimates but deliberately leave `observed_outcome` empty.

Recovery can accept, retry, compensate, switch action, request one additional observation round, or escalate. Every second intervention is selected from policy-authorized candidates; the recovery path cannot bypass simulation or policy.

Controller v4 adds component-level state beliefs for network containment, credential invalidation, service health, alternate paths, and dependency availability. Recovery decisions now retain a `rejected_retry_reason`, allowing the future UI to show why Sentinel retried, switched, requested evidence, or refused another action.

Offline recovery replay branches from the same hidden execution point and evaluates retry, switch, and escalation choices. Hidden truth remains confined to evaluation artifacts; production decisions receive only estimates and observations.

## Typed paths and bounded sequences

Controller v5 represents path edges as network, credential, cached-session, or service-trust relationships. `typed_attack_paths` preserves the connection IDs, accounts, and path kinds needed to explain why an apparently successful action left a structurally distinct route.

Two recovery actions were added because v4 failures demonstrated concrete gaps:

- `REVOKE_SESSION` invalidates cached sessions for one identity without disabling the account.
- `RESTRICT_CONNECTION` disables one named connection rather than an entire protocol.

Both actions use the same deterministic intervention, simulation, policy, independent execution, observation, and verification contracts as the original actions.

The product controller is an inspectable state machine: attempt, verify, retry once, use the best authorized fallback, then escalate. It may skip the retry only when application is confirmed, the targeted path disappeared, a different typed path remains, and a policy-authorized alternative reduces that path with acceptable modeled impact. The timeline records both `rejected_retry_reason` and `structural_switch_evidence`.

The exhaustive sequence planner is evaluation-only. It replays every candidate sequence up to three actions against hidden synthetic execution state, disqualifies policy-denied steps, and reports residual risk, cumulative cost, outages, execution probability, and step count.

## Metric provenance

- Attack paths are all simple directed paths from a non-isolated compromised host to a sensitive host over available connections.
- A connection is unavailable when denied, globally protocol-blocked, attached to an isolated host, or dependent on a disabled account.
- Disrupted services are initially available services whose hosting node becomes unavailable.
- Impacted users come from isolated hosts, newly unavailable connections, and disabled accounts.
- Downtime uses an explicit action table in `simulator/impact.py`; it is a scenario assumption, not an AI estimate.
- Payroll availability is computed from its declared service, connection, and account dependencies.

NetworkX is omitted because this graph is small and the explicit traversal is easier to audit.
