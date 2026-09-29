from __future__ import annotations

from collections import Counter, defaultdict

from sentinel.domain.execution import ObservationKind
from sentinel.evaluation.config import ControllerConfig
from sentinel.execution.adapter import execute_independently
from sentinel.execution.observation import observe_execution
from sentinel.scenarios.generator_v3 import generate_recovery_partition


def build_calibration_report(partition: str, start: int, count: int, controller: ControllerConfig, execution_offset: int) -> dict:
    action_counts=defaultdict(Counter); signal_correct=defaultdict(list)
    scenarios=generate_recovery_partition(partition,start,count,controller)
    for scenario in scenarios:
        for index,candidate in enumerate(scenario.definition.candidates):
            hidden=execute_independently(scenario.definition.world,candidate.intervention,execution_offset+scenario.metadata.seed*10+index)
            action_counts[candidate.intervention.action.value]["total"]+=1
            action_counts[candidate.intervention.action.value]["fully_applied"]+=int(hidden.action_applied_fully)
            for observation in observe_execution(candidate.intervention,hidden,execution_offset+scenario.metadata.seed*10+index):
                if observation.kind is ObservationKind.ACTION_RECEIPT: continue
                if observation.kind in (ObservationKind.CONNECTIVITY_PROBE,ObservationKind.AUTHENTICATION_PROBE,ObservationKind.ENDPOINT_TELEMETRY):
                    positive=observation.value in {"ISOLATED","BLOCKED","REJECTED"}
                    correct=positive==hidden.action_applied_fully
                elif observation.kind is ObservationKind.ATTACK_PATH_INDICATOR:
                    correct=(observation.value=="CLEAR")== (hidden.residual_attack_paths==0)
                elif observation.kind is ObservationKind.SERVICE_HEALTH:
                    correct=(observation.value=="HEALTHY")== (hidden.services_disrupted==0)
                else:
                    correct=(observation.value=="AVAILABLE")==hidden.payroll_available
                signal_correct[observation.kind.value].append(int(correct))
    return {"label":"synthetic execution-model estimates; not real-world calibrated probabilities","partition":partition,"scenario_count":count,"action_reliability":{action:round(values["fully_applied"]/values["total"],4) for action,values in action_counts.items()},"signal_reliability":{kind:round(sum(values)/len(values),4) for kind,values in signal_correct.items()}}
