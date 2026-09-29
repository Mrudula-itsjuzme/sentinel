from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from sentinel.domain.evidence import IncidentEvidence
from sentinel.domain.models import SimulationResult, WorldState
from sentinel.policy.engine import PolicyResult, evaluate_policy
from sentinel.policy.rules import PolicyConfig
from sentinel.providers.base import ProviderError
from sentinel.providers.nebius import NebiusConfig, NebiusReasoningClient
from sentinel.reasoning.models import ReasoningResponse
from sentinel.reasoning.service import IncidentReasoner, UnsafeModelOutput
from sentinel.scenarios.lateral_movement import build_evidence, build_world
from sentinel.services.counterfactual import simulate_all

router = APIRouter()


class ScenarioResponse(BaseModel):
    world: WorldState
    evidence: IncidentEvidence


class SimulationResponse(BaseModel):
    scenario_id: str
    results: list[SimulationResult]


class PolicyEvaluationRequest(BaseModel):
    result: SimulationResult
    policy: PolicyConfig | None = None
    destructive: bool = False


async def get_reasoner() -> IncidentReasoner:
    try:
        return IncidentReasoner(NebiusReasoningClient(NebiusConfig.from_env()))
    except ProviderError as exc:
        raise HTTPException(
            status_code=503,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/scenario", response_model=ScenarioResponse)
async def scenario() -> ScenarioResponse:
    return ScenarioResponse(world=build_world(), evidence=build_evidence())


@router.post("/simulate", response_model=SimulationResponse)
async def simulate() -> SimulationResponse:
    world = build_world()
    return SimulationResponse(scenario_id=world.scenario_id, results=simulate_all(world))


@router.post("/policy/evaluate", response_model=PolicyResult)
async def policy_evaluate(request: PolicyEvaluationRequest) -> PolicyResult:
    return evaluate_policy(request.result, request.policy, destructive=request.destructive)


@router.post("/reason", response_model=ReasoningResponse)
async def reason(reasoner: IncidentReasoner = Depends(get_reasoner)) -> ReasoningResponse:
    try:
        return await reasoner.reason(build_evidence())
    except ProviderError as exc:
        status = 503 if exc.code == "NEBIUS_NOT_CONFIGURED" else 502
        raise HTTPException(status_code=status, detail={"code": exc.code, "message": str(exc)}) from exc
    except UnsafeModelOutput as exc:
        raise HTTPException(status_code=502, detail={"code": exc.code, "message": str(exc)}) from exc
