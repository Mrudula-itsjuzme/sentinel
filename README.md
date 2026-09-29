# Sentinel

Sentinel is a counterfactual incident-response engine. This first milestone is deliberately narrow: one deterministic cyber world, one lateral-movement incident, and exactly three simulated interventions. No LLM decides metrics or authorization, and no endpoint performs a real remediation.

## What is implemented

- Inspectable enterprise topology and ground-truth state
- Incident observations stored separately from ground truth
- Deterministic attack-path and business-dependency calculations
- `ISOLATE_HOST`, `BLOCK_SMB`, and `DISABLE_ACCOUNT` counterfactuals
- Deterministic allow/deny policy evaluation
- Evidence-grounded Nemotron proposal generation through Nebius Token Factory
- Counterfactual utility decomposition, decision baselines, abstention, and evidence requests
- Controller v2 evidence-value decisions, context-dependent deterministic policy, and bounded verification-driven replanning
- A structurally distinct service-centric generator and frozen sealed-v2 evaluation
- Controller v3 post-action observations, explicit state estimation, bounded recovery, and sealed-v3 comparison baselines
- Controller v4 recovery replay, component-level error attribution, targeted-observation value, and strong retry baselines
- Controller v5 retry-then-fallback default, typed network/credential/session/trust paths, two justified recovery actions, and a bounded sequence oracle
- Five-scenario controlled evaluation and verification contracts
- FastAPI endpoints and deterministic tests

Nemotron is an untrusted reasoning layer: it can produce typed hypotheses and suggest only the three supported interventions. Sentinel validates its incident ID, evidence references, action, and target locally. The model does not receive simulator results and cannot authorize, mutate, or execute anything.

## Run locally

```bash
uv sync --extra dev
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 uv run pytest
uv run uvicorn sentinel.main:app --reload
```

Python 3.11 or newer is required. Equivalent `venv` and `pip install -e '.[dev]'` commands also work. Disabling ambient pytest plugins keeps unrelated system packages (such as ROS plugins) out of this project's test run.

Open `http://127.0.0.1:8000/docs` for the generated API schema.

To enable live reasoning, copy `.env.example` values into your environment, set `NEBIUS_API_KEY`, and set `NEBIUS_MODEL` to a currently available NVIDIA Nemotron model ID. The model is deliberately configuration-required rather than hard-coded because Token Factory availability changes.

## API

- `GET /health` — service status
- `GET /scenario` — world state and separately modeled evidence
- `POST /simulate` — all three counterfactual results
- `POST /policy/evaluate` — deterministic policy decision for a supplied simulation result
- `POST /reason` — ask configured Nemotron for a typed, evidence-grounded proposal

`/reason` returns `503 NEBIUS_NOT_CONFIGURED` without credentials. Invalid provider envelopes and unsafe model output fail closed with a `502` and a stable error code.

## Controlled evaluation

```bash
uv run python -m sentinel.evaluate --output-dir artifacts/evaluation
```

This runs five deterministic scenarios against six decision methods and four ablation configurations. Generated results explicitly label model preference and uncertainty as fixtures rather than live Nemotron measurements. See [docs/RESEARCH.md](docs/RESEARCH.md).

Run the frozen sealed benchmark with independent execution:

```bash
uv run --no-sync python -m sentinel.sealed_evaluate --output-dir artifacts/sealed-v1
```

Controller v2 is evaluated separately after its train/dev freeze:

```bash
uv run --no-sync python -m sentinel.sealed_evaluate_v2
```

Run the frozen execution-state recovery benchmark with:

```bash
uv run --no-sync python -m sentinel.sealed_evaluate_v3
```

Run the frozen recovery-choice benchmark with:

```bash
uv run --no-sync python -m sentinel.sealed_evaluate_v4
```

Run the frozen bounded-sequence benchmark with:

```bash
uv run --no-sync python -m sentinel.sealed_evaluate_v5
```

The protocol and failure taxonomy are documented in [docs/EVALUATION_PROTOCOL.md](docs/EVALUATION_PROTOCOL.md) and [docs/FAILURE_ANALYSIS.md](docs/FAILURE_ANALYSIS.md).

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/MVP.md](docs/MVP.md), [docs/RESEARCH.md](docs/RESEARCH.md), and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
