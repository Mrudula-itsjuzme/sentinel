from pydantic import ValidationError

from sentinel.domain.actions import INTERVENTIONS
from sentinel.domain.evidence import IncidentEvidence
from sentinel.providers.base import ReasoningProvider
from sentinel.reasoning.models import ReasoningProposal, ReasoningResponse
from sentinel.reasoning.prompts import build_messages


class UnsafeModelOutput(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class IncidentReasoner:
    def __init__(self, provider: ReasoningProvider) -> None:
        self.provider = provider

    async def reason(self, evidence: IncidentEvidence) -> ReasoningResponse:
        provider_response = await self.provider.complete_json(
            messages=build_messages(evidence),
            json_schema=ReasoningProposal.model_json_schema(),
        )
        try:
            proposal = ReasoningProposal.model_validate_json(provider_response.content)
        except ValidationError as exc:
            raise UnsafeModelOutput("INVALID_MODEL_OUTPUT", "Model output failed schema validation") from exc

        if proposal.incident_id != evidence.incident_id:
            raise UnsafeModelOutput("INCIDENT_MISMATCH", "Model output referenced a different incident")

        known_evidence_ids = {item.id for item in evidence.observations}
        referenced_ids = {
            evidence_id
            for hypothesis in proposal.hypotheses
            for evidence_id in hypothesis.evidence_ids
        } | {
            evidence_id
            for intervention in proposal.interventions
            for evidence_id in intervention.evidence_ids
        }
        unknown_ids = sorted(referenced_ids - known_evidence_ids)
        if unknown_ids:
            raise UnsafeModelOutput("UNKNOWN_EVIDENCE", "Model output referenced evidence that does not exist")

        supported_targets = {item.action: item.target for item in INTERVENTIONS}
        for intervention in proposal.interventions:
            if supported_targets[intervention.action] != intervention.target:
                raise UnsafeModelOutput("UNSUPPORTED_TARGET", "Model output used an unsupported action target")

        return ReasoningResponse(
            proposal=proposal,
            provider=self.provider.name,
            model=provider_response.model,
            request_id=provider_response.request_id,
        )

