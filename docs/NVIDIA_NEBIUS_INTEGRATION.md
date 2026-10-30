# NVIDIA model and Nebius integration

Sentinel calls an NVIDIA Nemotron chat model through the Nebius Token Factory OpenAI-compatible `POST /v1/chat/completions` endpoint. The model only produces evidence-grounded hypotheses and candidate interventions. It cannot authorize or execute an action.

## Implementation

- `src/sentinel/providers/nebius.py` — authenticated HTTPS request, timeout/error handling, response metadata, and strict JSON-schema request.
- `src/sentinel/reasoning/prompts.py` — evidence-only model context.
- `src/sentinel/reasoning/service.py` — schema, incident, evidence-ID, action, and target validation.
- `src/sentinel/services/incidents.py` — inference provenance, explicit fallback, simulation, policy, execution, and verification.

Set `NEBIUS_MODEL` to an NVIDIA Nemotron chat/instruct model ID currently available in the account's Token Factory catalog. Sentinel does not hard-code a catalog ID because availability changes; the adapter rejects IDs that do not contain `nemotron`. For the submission recording, retain the exact ID shown in the dashboard. The chosen model's license applies separately from Sentinel's MIT license.

## Request contract

The adapter sends the selected model, evidence-only messages, `temperature: 0`, and a strict `response_format.json_schema` to `/chat/completions`. The provider response is untrusted. Sentinel rejects unknown evidence, unsupported targets/actions, extra fields, mismatched incident IDs, truncation, refusals, and malformed envelopes.

## Honest inference states

- `success: true`, `fallback_used: false`: a provider response was received and validated. Provider, model, latency, request ID, and token counts are recorded only when returned.
- `fallback_used: true`: the local deterministic proposal was used. If a live call was requested, `error_code` records the failure.
- Missing credentials never produce a synthetic model response or invented usage.

## Configuration

```bash
cp .env.example .env
export NEBIUS_API_KEY='your-token-factory-key'
export NEBIUS_MODEL='the-current-NVIDIA-Nemotron-model-id'
uv run uvicorn sentinel.main:app --host 127.0.0.1 --port 8000
```

The app does not automatically load `.env`; export variables in the process environment or pass them through Docker Compose. `/config/model` never returns the API key.

Tests exercise the request/response contract with an HTTP mock. A paid live Nebius call has not been made in this checkout because no credentials are configured. Do not claim live inference until the dashboard reports a validated live response.
