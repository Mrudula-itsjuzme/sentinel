from pydantic import BaseModel, ConfigDict, Field, model_validator

from sentinel.domain.actions import ActionType


class Hypothesis(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^hyp-[A-Za-z0-9_-]+$")
    statement: str = Field(min_length=1, max_length=500)
    evidence_ids: tuple[str, ...] = Field(min_length=1)
    confidence: float = Field(ge=0, le=1)
    uncertainty: str = Field(min_length=1, max_length=300)


class SuggestedIntervention(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    action: ActionType
    target: str = Field(min_length=1, max_length=100)
    rationale: str = Field(min_length=1, max_length=500)
    evidence_ids: tuple[str, ...] = Field(min_length=1)


class ReasoningProposal(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    incident_id: str
    hypotheses: tuple[Hypothesis, ...] = Field(min_length=1, max_length=6)
    interventions: tuple[SuggestedIntervention, ...] = Field(max_length=3)
    evidence_insufficient: bool
    missing_evidence: tuple[str, ...] = Field(max_length=6)

    @model_validator(mode="after")
    def enforce_internal_consistency(self) -> "ReasoningProposal":
        hypothesis_ids = [item.id for item in self.hypotheses]
        if len(hypothesis_ids) != len(set(hypothesis_ids)):
            raise ValueError("hypothesis IDs must be unique")
        actions = [item.action for item in self.interventions]
        if len(actions) != len(set(actions)):
            raise ValueError("suggested actions must be unique")
        if self.evidence_insufficient and not self.missing_evidence:
            raise ValueError("missing_evidence is required when evidence is insufficient")
        if not self.evidence_insufficient and self.missing_evidence:
            raise ValueError("missing_evidence must be empty when evidence is sufficient")
        return self


class ReasoningResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    proposal: ReasoningProposal
    provider: str
    model: str
    request_id: str | None = None

