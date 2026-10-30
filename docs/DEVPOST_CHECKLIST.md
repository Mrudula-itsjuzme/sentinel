# Devpost submission checklist

## Story and judging

- [ ] Explain the problem: fast response without giving an LLM infrastructure authority.
- [ ] Show evidence → proposal → twin → policy → simulated execution → verification.
- [ ] Run the rejected-action path and explain the safer fallback.
- [ ] State that all worlds, interventions, and verification results are simulated.
- [ ] State whether the recording used real inference or deterministic fallback.

## Nebius × NVIDIA proof

- [ ] Configure a current NVIDIA Nemotron model in Nebius Token Factory.
- [ ] Record the exact `NEBIUS_MODEL` ID used.
- [ ] Capture provider, model, latency, and any returned token usage.
- [ ] Preserve a redacted provider-console or request/response screenshot; never expose the key.
- [ ] Link `docs/NVIDIA_NEBIUS_INTEGRATION.md`.

## Assets and reproducibility

- [ ] Public repository and demo URLs point at the reviewed revision.
- [ ] Three-minute video has readable captions.
- [ ] Include incident, policy-rejection, receipt, and verification screenshots.
- [ ] Credit Nebius Token Factory and the exact NVIDIA model.
- [ ] `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 uv run pytest -q` passes.
- [ ] Credential-free mode says “no inference.”
- [ ] `.env` is ignored; `.env.example` contains no credential.
- [ ] No real intervention adapter, private incident data, or invented benchmark is included.
- [ ] Review the destination before any push or deployment.
