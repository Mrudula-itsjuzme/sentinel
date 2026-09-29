from __future__ import annotations

from dataclasses import dataclass
from itertools import product

from sentinel.decision.v2 import build_decision_bundle_v2
from sentinel.domain.actions import apply_intervention
from sentinel.evaluation.config import ControllerV4Config,ControllerV5Config
from sentinel.execution.adapter import execute_independently
from sentinel.policy.engine import PolicyDecision
from sentinel.policy.v2 import evaluate_policy_v2
from sentinel.scenarios.generator import GeneratedScenario
from sentinel.simulator.engine import simulate_intervention
from sentinel.simulator.reachability import attack_paths


@dataclass(frozen=True)
class SequencePlan:
    actions:tuple[tuple[str,str],...]
    final_residual_paths:int
    cumulative_operational_cost:float
    critical_outage:bool
    policy_compliant:bool
    execution_probability:float
    resolved:bool
    score:float
    steps:int


def _cost(outcome,weights):
    return weights.disrupted_service*outcome.services_disrupted+weights.impacted_user*outcome.users_impacted+(0 if outcome.payroll_available else weights.payroll_outage)


def evaluate_sequence(generated:GeneratedScenario,sequence,controller:ControllerV4Config,seed:int)->SequencePlan:
    v3=controller.controller_v3; weights=v3.controller_v2.utility_weights; world=generated.definition.world.clone(); cumulative=0.0; outage=False; compliant=True; probability=1.0; executed=[]; final_paths=len(attack_paths(world))
    for step,candidate in enumerate(sequence):
        simulation=simulate_intervention(world,candidate.intervention)
        policy=evaluate_policy_v2(simulation,candidate,pre_attack_paths=len(attack_paths(world)),verification_available=True,config=v3.controller_v2)
        if policy.decision is PolicyDecision.DENY: compliant=False; break
        outcome=execute_independently(world,candidate.intervention,seed+step*101+list(generated.definition.candidates).index(candidate)); cumulative+=_cost(outcome,weights); outage|=not outcome.payroll_available; probability*=v3.estimator.action_reliability.get(candidate.intervention.action.value,.55); executed.append((candidate.intervention.action.value,candidate.intervention.target))
        if outcome.action_applied_fully: apply_intervention(world,candidate.intervention)
        final_paths=outcome.residual_attack_paths
        if final_paths==0 and outcome.payroll_available: break
    pre=generated.metadata.hidden_attack_paths; security=weights.attack_path_reduction*((pre-final_paths)/max(1,pre))-weights.residual_attack_reachability*(final_paths/max(1,pre)); score=security-cumulative-(weights.policy_denial if not compliant else 0)
    return SequencePlan(tuple(executed),final_paths,round(cumulative,4),outage,compliant,round(probability,6),bool(executed and final_paths==0 and not outage),round(score,4),len(executed))


def bounded_sequence_oracle(generated:GeneratedScenario,controller:ControllerV4Config,v5:ControllerV5Config,seed:int)->tuple[SequencePlan,tuple[SequencePlan,...]]:
    candidates=generated.definition.candidates; plans=[]
    # Include escalation/no further action.
    plans.append(SequencePlan((),generated.metadata.hidden_attack_paths,0.0,False,True,1.0,generated.metadata.hidden_attack_paths==0,0.0,0))
    for length in range(1,v5.maximum_sequence_steps+1):
        for sequence in product(candidates,repeat=length): plans.append(evaluate_sequence(generated,sequence,controller,seed))
    best=max(plans,key=lambda p:(p.policy_compliant,p.resolved,p.score,-p.steps,p.execution_probability))
    return best,tuple(plans)
