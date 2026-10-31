# Sentinel — exact narration script

Target duration: 2:05. The shipped MP4 includes an ElevenLabs neural narration track and an embedded subtitle track. The renderer also supports an explicitly labeled synthetic fallback when credentials are unavailable.

## 00:00–00:11 — Hook

What if stopping a cyberattack could cause more damage than the attack itself? Sentinel tests a recommended response before allowing it to proceed.

## 00:11–00:23 — Incident

This incident is credential-backed lateral movement: Alice's workstation, an internal host, and the payroll dependency are on the active attack path. Four observed signals and two affected identities ground the investigation.

## 00:23–00:40 — Proposal

Sentinel evaluates candidate interventions against the same synthetic world. This run uses the explicit deterministic fallback because no live Nebius credentials are configured. No AI inference is claimed.

## 00:40–01:05 — Simulation and policy

The digital twin predicts that isolating the workstation or blocking SMB would stop the path, but would also make payroll unavailable and impact too many users. The policy controller rejects both. Disabling the compromised account stops the path while preserving payroll, so it is approved.

## 01:05–01:23 — Execution and verification

The approved action executes only inside an isolated deterministic world clone. Sentinel recomputes the attack graph, confirms zero remaining paths, verifies payroll availability, and records the result.

## 01:23–01:41 — Why Sentinel

Traditional assistants recommend actions. Sentinel predicts consequences first, then lets deterministic policy rules decide. The model may propose; it cannot authorize execution.

## 01:41–02:05 — Close

Sentinel: AI-assisted incident response, grounded in simulation and governed by policy. NVIDIA and Nebius integration is available when configured; this recording uses the clearly labeled fallback. Every result is traceable to incident evidence, a simulated outcome, and a policy decision.
