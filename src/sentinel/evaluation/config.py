from __future__ import annotations

import hashlib
import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from sentinel.domain.actions import ActionType
from sentinel.domain.decision import UtilityWeights
from sentinel.policy.rules import PolicyConfig


class FrozenPolicy(BaseModel):
    model_config = ConfigDict(frozen=True)

    maximum_users_impacted: int
    maximum_downtime_minutes: int
    destructive_actions_forbidden: bool
    critical_services: tuple[str, ...]


class ControllerConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    version: str
    frozen_at: str
    ranking_rule: str
    uncertainty_request_threshold: float
    policy: FrozenPolicy
    utility_weights: UtilityWeights

    def policy_config(self) -> PolicyConfig:
        return PolicyConfig(
            allowed_actions=frozenset(ActionType),
            destructive_actions_forbidden=self.policy.destructive_actions_forbidden,
            maximum_users_impacted=self.policy.maximum_users_impacted,
            maximum_downtime_minutes=self.policy.maximum_downtime_minutes,
            critical_services=frozenset(self.policy.critical_services),
        )


class ContextPolicyConfig(FrozenPolicy):
    contextual_maximum_users_impacted: int
    allow_reversible_context_override: bool
    override_requires_attack_stopped: bool
    override_requires_verification: bool
    critical_outage_override_minimum_pre_paths: int


class EvidenceValueConfig(BaseModel):
    model_config = ConfigDict(frozen=True)
    acquisition_cost: float
    delay_cost_per_attack_path: float
    resolved_uncertainty: float
    minimum_expected_value: float
    material_action_margin: float


class ReplanningConfig(BaseModel):
    model_config = ConfigDict(frozen=True)
    maximum_replans: int
    repeat_same_action: bool
    escalate_on_critical_service_mismatch: bool


class ControllerV2Config(BaseModel):
    model_config = ConfigDict(frozen=True)
    version: str
    frozen_at: str
    developed_on: tuple[str, ...]
    ranking_rule: str
    policy: ContextPolicyConfig
    evidence_value: EvidenceValueConfig
    replanning: ReplanningConfig
    utility_weights: UtilityWeights


class EstimatorConfig(BaseModel):
    model_config = ConfigDict(frozen=True)
    confirmed_threshold: float
    contradicted_threshold: float
    minimum_residual_confidence: float
    signal_reliability: dict[str, float]
    action_reliability: dict[str, float]


class RecoveryConfig(BaseModel):
    model_config = ConfigDict(frozen=True)
    maximum_steps: int
    retry_minimum_reliability: float
    request_evidence_below_confidence: float
    escalate_critical_below_probability: float
    maximum_cumulative_operational_cost: float


class ControllerV3Config(BaseModel):
    model_config = ConfigDict(frozen=True)
    version: str
    frozen_at: str
    developed_on: tuple[str, ...]
    controller_v2: ControllerV2Config
    estimator: EstimatorConfig
    recovery: RecoveryConfig


class BenchmarkV3Config(BaseModel):
    model_config = ConfigDict(frozen=True)
    version: str
    generator_version: str
    controller_v3_config: str
    test_seed_start: int
    test_count: int
    execution_seed_offset: int
    bootstrap_samples: int
    bootstrap_seed: int


class RecoveryV4Rules(BaseModel):
    model_config = ConfigDict(frozen=True)
    maximum_steps: int
    maximum_retries_per_action: int
    partial_retry_minimum_probability: float
    partial_retry_maximum_probability: float
    structural_switch_alternate_path_probability: float
    targeted_evidence_minimum_value: float
    evidence_acquisition_cost: float
    evidence_delay_cost: float


class ControllerV4Config(BaseModel):
    model_config = ConfigDict(frozen=True)
    version: str
    frozen_at: str
    developed_on: tuple[str, ...]
    controller_v3: ControllerV3Config
    recovery: RecoveryV4Rules


class BenchmarkV4Config(BaseModel):
    model_config = ConfigDict(frozen=True)
    version: str
    generator_version: str
    controller_v4_config: str
    test_seed_start: int
    test_count: int
    execution_seed_offset: int
    bootstrap_samples: int
    bootstrap_seed: int


class ControllerV5Config(BaseModel):
    model_config = ConfigDict(frozen=True)
    version: str
    frozen_at: str
    developed_on: tuple[str, ...]
    reference_controller_config: str
    maximum_sequence_steps: int
    maximum_retries: int
    confirmed_application_threshold: float
    structural_residual_confidence_threshold: float
    default_policy: str


class BenchmarkV5Config(BaseModel):
    model_config = ConfigDict(frozen=True)
    version: str
    generator_version: str
    controller_v5_config: str
    test_seed_start: int
    test_count: int
    execution_seed_offset: int
    bootstrap_samples: int
    bootstrap_seed: int


class BenchmarkV2Config(BaseModel):
    model_config = ConfigDict(frozen=True)
    version: str
    generator_version: str
    controller_v1_config: str
    controller_v2_config: str
    test_seed_start: int
    test_count: int
    execution_seed_offset: int
    bootstrap_samples: int
    bootstrap_seed: int
    protocol: str


class SeedRange(BaseModel):
    model_config = ConfigDict(frozen=True)
    start: int
    count: int


class BenchmarkConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    version: str
    generator_version: str
    controller_config: str
    partition_seeds: dict[str, SeedRange]
    execution_seed_offset: int
    bootstrap_samples: int
    bootstrap_seed: int
    protocol: str


def load_controller_config(path: Path = Path("configs/controller-v1.json")) -> ControllerConfig:
    return ControllerConfig.model_validate_json(path.read_text())


def load_benchmark_config(path: Path = Path("configs/sealed-benchmark-v1.json")) -> BenchmarkConfig:
    return BenchmarkConfig.model_validate_json(path.read_text())


def load_controller_v2_config(path: Path = Path("configs/controller-v2.json")) -> ControllerV2Config:
    return ControllerV2Config.model_validate_json(path.read_text())


def load_benchmark_v2_config(path: Path = Path("configs/sealed-benchmark-v2.json")) -> BenchmarkV2Config:
    return BenchmarkV2Config.model_validate_json(path.read_text())


def load_controller_v3_config(path: Path = Path("configs/controller-v3.json")) -> ControllerV3Config:
    return ControllerV3Config.model_validate_json(path.read_text())


def load_benchmark_v3_config(path: Path = Path("configs/sealed-benchmark-v3.json")) -> BenchmarkV3Config:
    return BenchmarkV3Config.model_validate_json(path.read_text())


def load_controller_v4_config(path: Path = Path("configs/controller-v4.json")) -> ControllerV4Config:
    return ControllerV4Config.model_validate_json(path.read_text())


def load_benchmark_v4_config(path: Path = Path("configs/sealed-benchmark-v4.json")) -> BenchmarkV4Config:
    return BenchmarkV4Config.model_validate_json(path.read_text())


def load_controller_v5_config(path: Path = Path("configs/controller-v5.json")) -> ControllerV5Config:
    return ControllerV5Config.model_validate_json(path.read_text())


def load_benchmark_v5_config(path: Path = Path("configs/sealed-benchmark-v5.json")) -> BenchmarkV5Config:
    return BenchmarkV5Config.model_validate_json(path.read_text())


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()
