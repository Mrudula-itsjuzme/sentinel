# Sentinel demo

This script takes about 2–3 minutes. It uses the deterministic simulator by default, so it works without credentials. If Nebius Token Factory is configured, enable the model toggle to add live NVIDIA Nemotron reasoning.

## Setup

```bash
uv sync --extra dev
uv run uvicorn sentinel.main:app --reload
```

Open `http://127.0.0.1:8000`.

## Main recovery (about 90 seconds)

1. Point out the healthy control-plane state and model configuration label. If credentials are absent, say explicitly that Sentinel is using its deterministic fallback.
2. Click **Run recovery**. Sentinel loads the fixed lateral-movement world and four observed signals.
3. Show the diagnosis. With the model enabled, this is a schema-validated NVIDIA Nemotron proposal through Nebius Token Factory. Without it, the UI labels the deterministic fallback.
4. Show the proposed `DISABLE_ACCOUNT` action and deterministic `ALLOW` result.
5. Show `DETERMINISTIC_SIMULATION`: no real infrastructure is changed.
6. Show post-action verification: attack paths fall from one to zero and payroll remains available.
7. Walk down the structured timeline from detection through verification.

## Safety gate (about 40 seconds)

1. Click **Show policy block**.
2. Sentinel proposes `ISOLATE_HOST`. The simulation predicts containment, but also two impacted users and loss of payroll.
3. The policy engine rejects it with `USER_IMPACT_EXCEEDED` before execution.
4. Sentinel evaluates the supported fallback, authorizes `DISABLE_ACCOUNT`, simulates it, and verifies recovery.

The message: **Sentinel does not give an LLM unrestricted control of infrastructure. AI proposes and reasons; deterministic policy decides what is allowed; execution is verified afterward.**

## Research result (about 30 seconds)

Show the sealed-v5 resolution bars. The production retry-then-fallback default resolved 27.5% of 120 seeded scenarios. Structural switching reached 30.0% but slightly worsened residual risk. The 83.33% bounded oracle is an offline diagnostic upper bound using hidden execution state, not a deployable controller or product claim. All compared methods recorded zero policy violations under the frozen benchmark definition.
