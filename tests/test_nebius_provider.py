import asyncio
import json

import httpx
import pytest

from sentinel.providers.base import ProviderError
from sentinel.providers.nebius import NebiusConfig, NebiusReasoningClient


def test_nebius_client_sends_strict_schema_without_leaking_key() -> None:
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["authorization"] = request.headers["authorization"]
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            headers={"x-request-id": "req-123"},
            json={
                "model": "nvidia/test-nemotron",
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": "{\"ok\":true}"},
                    }
                ],
            },
        )

    async def call():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
            client = NebiusReasoningClient(
                NebiusConfig(api_key="secret", model="nvidia/test-nemotron"),
                http_client=http_client,
            )
            return await client.complete_json(
                messages=[{"role": "user", "content": "incident"}],
                json_schema={"type": "object", "additionalProperties": False},
            )

    response = asyncio.run(call())

    assert captured["authorization"] == "Bearer secret"
    assert captured["body"]["temperature"] == 0
    assert captured["body"]["response_format"]["json_schema"]["strict"] is True
    assert response.request_id == "req-123"


def test_nebius_client_fails_safely_on_bad_envelope() -> None:
    async def call():
        transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"choices": []}))
        async with httpx.AsyncClient(transport=transport) as http_client:
            client = NebiusReasoningClient(
                NebiusConfig(api_key="secret", model="nvidia/test-nemotron"),
                http_client=http_client,
            )
            return await client.complete_json(messages=[], json_schema={})

    with pytest.raises(ProviderError) as error:
        asyncio.run(call())
    assert error.value.code == "MALFORMED_PROVIDER_RESPONSE"
    assert "secret" not in str(error.value)


def test_nebius_client_rejects_truncated_output() -> None:
    async def call():
        transport = httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                json={
                    "choices": [
                        {
                            "finish_reason": "length",
                            "message": {"content": "{}"},
                        }
                    ]
                },
            )
        )
        async with httpx.AsyncClient(transport=transport) as http_client:
            client = NebiusReasoningClient(
                NebiusConfig(api_key="secret", model="nvidia/test-nemotron"),
                http_client=http_client,
            )
            return await client.complete_json(messages=[], json_schema={})

    with pytest.raises(ProviderError) as error:
        asyncio.run(call())
    assert error.value.code == "INCOMPLETE_MODEL_OUTPUT"


def test_environment_config_requires_key_and_nemotron(monkeypatch) -> None:
    monkeypatch.delenv("NEBIUS_API_KEY", raising=False)
    monkeypatch.delenv("NEBIUS_MODEL", raising=False)
    with pytest.raises(ProviderError) as missing:
        NebiusConfig.from_env()
    assert missing.value.code == "NEBIUS_NOT_CONFIGURED"

    monkeypatch.setenv("NEBIUS_API_KEY", "secret")
    monkeypatch.setenv("NEBIUS_MODEL", "other/model")
    with pytest.raises(ProviderError) as wrong_model:
        NebiusConfig.from_env()
    assert wrong_model.value.code == "INVALID_MODEL"
