from datetime import datetime

from pydantic import BaseModel, ConfigDict


class IncidentObservation(BaseModel):
    """Observed evidence, intentionally separate from world-state ground truth."""

    model_config = ConfigDict(frozen=True)

    id: str
    observed_at: datetime
    source: str
    kind: str
    subject: str
    detail: str
    confidence: float


class IncidentEvidence(BaseModel):
    model_config = ConfigDict(frozen=True)

    incident_id: str
    observations: tuple[IncidentObservation, ...]

