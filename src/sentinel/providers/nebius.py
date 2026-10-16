from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any

import httpx

from sentinel.providers.base import ProviderError, ProviderResponse


DEFAULT_BASE_URL = "https://api.tokenfactory.nebius.com/v1"


@dataclass(frozen=True)
class NebiusConfig:
    api_key: str
    model: str
    base_url: str = DEFAULT_BASE_URL
    timeout_seconds: float = 30.0

    @classmethod
    def from_env(cls) -> NebiusConfig:
        api_key = os.getenv("NEBIUS_API_KEY", "").strip()
        model = os.getenv("NEBIUS_MODEL", "").strip()
        base_url = os.getenv("NEBIUS_BASE_URL", DEFAULT_BASE_URL).strip().rstrip("/")
        if not api_key:
            raise ProviderError("NEBIUS_NOT_CONFIGURED", "NEBIUS_API_KEY is not configured")
        if not model:
            raise ProviderError("NEBIUS_NOT_CONFIGURED", "NEBIUS_MODEL is not configured")
        if "nemotron" not in model.casefold():
            raise ProviderError("INVALID_MODEL", "NEBIUS_MODEL must identify a Nemotron model")
        if not base_url.startswith("https://"):
            raise ProviderError("INVALID_BASE_URL", "NEBIUS_BASE_URL must use HTTPS")
        return cls(api_key=api_key, model=model, base_url=base_url)


class NebiusReasoningClient:
    name = "nebius-token-factory"

    def __init__(
        self,
        config: NebiusConfig,
        *,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.config = config
        self._http_client = http_client

    async def complete_json(
        self,
        *,
        messages: list[dict[str, str]],
        json_schema: dict[str, Any],
    ) -> ProviderResponse:
        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": 0,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "sentinel_incident_reasoning",
                    "strict": True,
                    "schema": json_schema,
                },
            },
        }
        owns_client = self._http_client is None
        client = self._http_client or httpx.AsyncClient(timeout=self.config.timeout_seconds)
        try:
            try:
                started_at = time.perf_counter()
                response = await client.post(
                    f"{self.config.base_url}/chat/completions",
                    headers={"Authorization": f"Bearer {self.config.api_key}"},
                    json=payload,
                )
                response.raise_for_status()
            except httpx.TimeoutException as exc:
                raise ProviderError("PROVIDER_TIMEOUT", "Nebius inference timed out") from exc
            except httpx.HTTPStatusError as exc:
                raise ProviderError(
                    "PROVIDER_HTTP_ERROR",
                    f"Nebius inference returned HTTP {exc.response.status_code}",
                ) from exc
            except httpx.HTTPError as exc:
                raise ProviderError("PROVIDER_UNAVAILABLE", "Nebius inference is unavailable") from exc

            try:
                body = response.json()
                choice = body["choices"][0]
                if choice.get("finish_reason") != "stop":
                    raise ProviderError(
                        "INCOMPLETE_MODEL_OUTPUT",
                        "Nemotron did not complete the reasoning response",
                    )
                message = choice["message"]
                content = message["content"]
                if message.get("refusal"):
                    raise ProviderError("MODEL_REFUSAL", "Nemotron refused the reasoning request")
                if not isinstance(content, str) or not content.strip():
                    raise ValueError("empty content")
            except ProviderError:
                raise
            except (KeyError, IndexError, TypeError, ValueError) as exc:
                raise ProviderError("MALFORMED_PROVIDER_RESPONSE", "Nebius returned an invalid response envelope") from exc

            request_id = response.headers.get("x-request-id")
            usage = body.get("usage") if isinstance(body.get("usage"), dict) else {}
            return ProviderResponse(
                content=content,
                model=str(body.get("model", self.config.model)),
                request_id=request_id,
                latency_ms=round((time.perf_counter() - started_at) * 1000, 2),
                input_tokens=usage.get("prompt_tokens"),
                output_tokens=usage.get("completion_tokens"),
                total_tokens=usage.get("total_tokens"),
            )
        finally:
            if owns_client:
                await client.aclose()
