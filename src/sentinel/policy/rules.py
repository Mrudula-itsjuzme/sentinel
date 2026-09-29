from pydantic import BaseModel, ConfigDict

from sentinel.domain.actions import ActionType


class PolicyConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    allowed_actions: frozenset[ActionType] = frozenset(ActionType)
    destructive_actions_forbidden: bool = True
    maximum_users_impacted: int = 1
    maximum_downtime_minutes: int = 30
    critical_services: frozenset[str] = frozenset({"payroll"})

