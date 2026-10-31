# Sentinel demo storyboard

| Time | Shot | Evidence shown |
| --- | --- | --- |
| 00:00–00:15 | Dark hook card with attack path | Payroll marked as a critical dependency; no fabricated live event |
| 00:15–00:29 | Real Sentinel incident screenshot | `incident-lateral-001`, SEV-1, evidence count, attack path |
| 00:29–00:37 | Unsafe proposal browser state | Real `Test unsafe proposal` result; policy rejection and safe fallback |
| 00:37–00:45 | Approved response browser state | Real `Run response` result; verified deterministic fallback |
| 00:45–01:09 | Candidate-actions card | Exact deterministic fallback label and candidate actions |
| 01:09–01:33 | Digital-twin comparison | ISOLATE_HOST/BLOCK_SMB rejected; DISABLE_ACCOUNT allowed |
| 01:33–01:58 | Verification card | Simulated success, zero attack paths, payroll available, no production changes |
| 01:58–02:29 | Safety architecture card | Proposal → simulation → policy → verification |
| 02:29–02:45 | Closing Sentinel card | NVIDIA/Nebius integration caveat and product thesis |

The renderer uses real values from `sentinel.services.incidents.run_incident` and browser frames captured after the two actual response interactions.
