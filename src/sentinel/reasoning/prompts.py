import json

from sentinel.domain.actions import INTERVENTIONS
from sentinel.domain.evidence import IncidentEvidence


SYSTEM_PROMPT = """You are Sentinel's untrusted incident reasoning layer.
Generate evidence-grounded hypotheses and optional remediation suggestions.
Use only the supplied evidence IDs. Never invent evidence, simulator outcomes,
policy decisions, authorization, or execution claims. Suggest only an action
and exact target from supported_interventions. If the observations do not
support a conclusion, set evidence_insufficient=true and name the missing
evidence. Return only the requested JSON schema."""


def build_messages(evidence: IncidentEvidence) -> list[dict[str, str]]:
    context = {
        "incident_id": evidence.incident_id,
        "observations": [item.model_dump(mode="json") for item in evidence.observations],
        "supported_interventions": [
            {"action": item.action.value, "target": item.target} for item in INTERVENTIONS
        ],
    }
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps(context, separators=(",", ":"), sort_keys=True)},
    ]

