import asyncio
import json

import pytest

from sentinel.providers.base import ProviderResponse
from sentinel.reasoning.service import IncidentReasoner, UnsafeModelOutput
from sentinel.scenarios.lateral_movement import build_evidence


def valid_proposal() -> dict:
    return {
        "incident_id": "incident-lateral-001",
        "hypotheses": [
            {
                "id": "hyp-credential-lateral-movement",
                "statement": "The observed account may be moving laterally over SMB.",
                "evidence_ids": ["obs-002", "obs-004"],
                "confidence": 0.82,
                "uncertainty": "The destination host has not been forensically confirmed compromised.",
            }
        ],
        "interventions": [
            {
                "action": "DISABLE_ACCOUNT",
                "target": "alice",
                "rationale": "Contain use of the observed account pending validation.",
                "evidence_ids": ["obs-002", "obs-004"],
            }
        ],
        "evidence_insufficient": False,
        "missing_evidence": [],
    }


class FakeProvider:
    name = "fake"

    def __init__(self, payload: dict | str) -> None:
        self.payload = payload
        self.messages = None
        self.schema = None

    async def complete_json(self, *, messages, json_schema) -> ProviderResponse:
        self.messages = messages
        self.schema = json_schema
        content = self.payload if isinstance(self.payload, str) else json.dumps(self.payload)
        return ProviderResponse(content=content, model="nvidia/test-nemotron", request_id="req-test")


def run_reasoner(provider):
    return asyncio.run(IncidentReasoner(provider).reason(build_evidence()))


def test_reasoner_accepts_grounded_typed_output() -> None:
    provider = FakeProvider(valid_proposal())
    response = run_reasoner(provider)
    assert response.proposal.interventions[0].target == "alice"
    assert response.provider == "fake"
    assert "simulation_succeeded" not in provider.messages[1]["content"]
    assert "payroll_available" not in provider.messages[1]["content"]
    assert provider.schema["additionalProperties"] is False


def test_reasoner_rejects_invented_evidence() -> None:
    payload = valid_proposal()
    payload["hypotheses"][0]["evidence_ids"] = ["obs-invented"]
    with pytest.raises(UnsafeModelOutput, match="does not exist") as error:
        run_reasoner(FakeProvider(payload))
    assert error.value.code == "UNKNOWN_EVIDENCE"


def test_reasoner_rejects_wrong_target() -> None:
    payload = valid_proposal()
    payload["interventions"][0]["target"] = "payroll_service"
    with pytest.raises(UnsafeModelOutput) as error:
        run_reasoner(FakeProvider(payload))
    assert error.value.code == "UNSUPPORTED_TARGET"


def test_reasoner_rejects_malformed_or_extra_fields() -> None:
    malformed = valid_proposal()
    malformed["authorization"] = "ALLOW"
    with pytest.raises(UnsafeModelOutput) as error:
        run_reasoner(FakeProvider(malformed))
    assert error.value.code == "INVALID_MODEL_OUTPUT"


def test_reasoner_rejects_mismatched_incident() -> None:
    payload = valid_proposal()
    payload["incident_id"] = "incident-other"
    with pytest.raises(UnsafeModelOutput) as error:
        run_reasoner(FakeProvider(payload))
    assert error.value.code == "INCIDENT_MISMATCH"


def test_insufficient_evidence_requires_missing_evidence() -> None:
    payload = valid_proposal()
    payload["evidence_insufficient"] = True
    with pytest.raises(UnsafeModelOutput) as error:
        run_reasoner(FakeProvider(payload))
    assert error.value.code == "INVALID_MODEL_OUTPUT"
