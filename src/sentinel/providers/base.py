from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class ProviderResponse:
    content: str
    model: str
    request_id: str | None = None
    latency_ms: float | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    total_tokens: int | None = None


class ReasoningProvider(Protocol):
    name: str

    async def complete_json(
        self,
        *,
        messages: list[dict[str, str]],
        json_schema: dict[str, Any],
    ) -> ProviderResponse: ...


class ProviderError(RuntimeError):
    """Safe provider failure that contains no credentials or response body."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)
