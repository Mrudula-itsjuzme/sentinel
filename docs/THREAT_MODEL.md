# Threat model

## Protected properties

- A model-generated proposal cannot bypass deterministic policy.
- Simulations cannot mutate the source world.
- Observed evidence cannot silently become ground truth.
- Operational harm is evaluated before any future execution step.
- Results remain reproducible for identical inputs.
- Model output cannot introduce unknown evidence, actions, targets, or authorization fields.

## Current scenario

An adversary controls Workstation A and has accessed Alice's credential. That credential permits SMB movement to the internal host; the internal host can reach the web server, which can reach the sensitive database. Suspicious PowerShell, credential access, SMB traffic, and unusual DNS are observations, not proof fields used to rewrite the ground truth.

Payroll depends on the internal file-share service, a separate legitimate SMB connection that crosses the compromised workstation, and an enabled service account. A global SMB block or workstation isolation therefore stops the modeled attack but also makes payroll unavailable; disabling only Alice leaves payroll available.

## Trust boundaries

- LLM output is untrusted proposal input and is validated locally before use.
- Scenario definitions and deterministic code form the trusted simulation boundary.
- Policy is a separate trusted authorization boundary.
- Future execution adapters and post-action sensors require their own validation boundary.

## Known limitations

This is not an enterprise emulator. It does not model probabilistic attacker behavior, hidden assets, telemetry fidelity, concurrency, credential rotation, rollback, or real infrastructure. The fixed downtime values are transparent scenario assumptions. Evidence-ID validation cannot prove that every natural-language inference is semantically correct; hypotheses therefore retain confidence and uncertainty fields. No current API executes an action.
