# Three-minute narrated demo

## Before recording

Run `uv run uvicorn sentinel.main:app --host 127.0.0.1 --port 8000` and open `http://127.0.0.1:8000`. If credentials are configured, enable the live toggle and confirm the header names the exact model. Otherwise leave it off and say “deterministic fallback; no AI inference occurred.”

## 0:00–0:30 — The problem

“This is Sentinel. Responders need speed, but an AI suggestion should never become infrastructure authority. A model may interpret observed evidence and propose actions; a deterministic twin predicts consequences; explicit policy decides what is allowed; and execution is confined to a simulation.”

Point to **Simulation only**, the reasoning mode, and affected path.

## 0:30–1:15 — Evidence and proposal

Click **Run response**.

“Four observed signals describe suspicious credential access and SMB activity. Hidden simulator state is not included in the prompt. In this run, [name the exact live Nemotron model and Nebius Token Factory / say deterministic fallback with no inference]. The response is validated locally against a strict schema and known evidence IDs.”

Show the candidate comparison. “The model proposes; the deterministic twin evaluates every supported candidate.”

## 1:15–2:05 — Twin and policy control

Click **Test unsafe proposal**.

“Isolating the workstation contains the modeled attack, but exceeds the user-impact threshold and disrupts payroll. Policy returns DENY. Sentinel selects the lowest-impact supported action that passes every rule. The LLM cannot override this gate.”

## 2:05–2:40 — Execution and verification

“The approved action is applied only to an isolated clone. The receipt says production changes: false. Sentinel then independently recomputes reachability and business dependencies. Recovery requires zero attack paths while payroll remains available.”

Show the receipt, verification metrics, and audit timeline.

## 2:40–3:00 — Close

“Every step is retained, including rejection and inference provenance. The checked-in research is synthetic and includes negative results; it is not real-world security performance. Sentinel’s trust boundary is simple: AI assists reasoning, deterministic systems control consequences.”
