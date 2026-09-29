import asyncio

import httpx

from sentinel.main import app
from sentinel.api.routes import get_reasoner
from sentinel.reasoning.models import ReasoningResponse


def request(method: str, path: str, **kwargs) -> httpx.Response:
    async def send() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(send())


def test_health_and_scenario() -> None:
    assert request("GET", "/health").json() == {"status": "ok"}
    scenario = request("GET", "/scenario")
    assert scenario.status_code == 200
    assert scenario.json()["world"]["scenario_id"] == "lateral-movement-v1"


def test_simulate_returns_exactly_three_results() -> None:
    response = request("POST", "/simulate")
    assert response.status_code == 200
    assert len(response.json()["results"]) == 3


def test_policy_evaluate_accepts_simulation_result() -> None:
    simulation = request("POST", "/simulate").json()["results"][2]
    response = request("POST", "/policy/evaluate", json={"result": simulation})
    assert response.status_code == 200
    assert response.json()["decision"] == "ALLOW"


def test_reason_fails_closed_without_configuration(monkeypatch) -> None:
    monkeypatch.delenv("NEBIUS_API_KEY", raising=False)
    monkeypatch.delenv("NEBIUS_MODEL", raising=False)
    response = request("POST", "/reason")
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "NEBIUS_NOT_CONFIGURED"


def test_reason_returns_validated_provider_result() -> None:
    class FakeReasoner:
        async def reason(self, evidence):
            return ReasoningResponse.model_validate(
                {
                    "proposal": {
                        "incident_id": evidence.incident_id,
                        "hypotheses": [
                            {
                                "id": "hyp-api",
                                "statement": "Observed account activity may represent lateral movement.",
                                "evidence_ids": ["obs-004"],
                                "confidence": 0.7,
                                "uncertainty": "Destination compromise is not confirmed.",
                            }
                        ],
                        "interventions": [],
                        "evidence_insufficient": True,
                        "missing_evidence": ["Destination host forensic status"],
                    },
                    "provider": "fake",
                    "model": "nvidia/test-nemotron",
                    "request_id": "req-api",
                }
            )

    async def override_reasoner():
        return FakeReasoner()

    app.dependency_overrides[get_reasoner] = override_reasoner
    try:
        response = request("POST", "/reason")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json()["proposal"]["evidence_insufficient"] is True
    assert response.json()["provider"] == "fake"
