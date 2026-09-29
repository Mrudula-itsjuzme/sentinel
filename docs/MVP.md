# MVP boundary

## Included now

- One static enterprise world: Internet, firewall, web server, database, internal host, and workstation.
- One reproducible lateral-movement path from Workstation A to the sensitive database.
- Four timestamped observations distinct from scenario truth.
- Exactly three interventions: host isolation, SMB blocking, and account disabling.
- Counterfactual security and operations metrics.
- Policy checks for allowlisting, destructiveness, successful simulation, user impact, downtime, and critical-service continuity.
- Typed Nemotron hypotheses and supported-action suggestions through an isolated Nebius provider.
- Local rejection of malformed output, invented evidence IDs, mismatched incidents, and unsupported targets.
- Five controlled scenarios, six selection methods, four component ablations, and generated evaluation artifacts.
- Canonical `DecisionBundle` with utility and verification decomposition.

## Explicitly deferred

- Intervention ranking or automatic selection
- Real remediation execution and post-action verification
- Authentication, persistence, threat feeds, multi-tenant state, and a frontend
- Additional scenarios, actions, and environment scale

The AI layer may propose candidates and explanations. It does not calculate simulator metrics, modify policy, or authorize execution. Live inference requires caller-supplied `NEBIUS_API_KEY` and a current `NEBIUS_MODEL`; no credential or model response is persisted.
