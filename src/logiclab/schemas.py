from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import StrEnum
from ipaddress import ip_address
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


SCHEMA_VERSION = "1.0"
FULL_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=False)


class VersionedModel(StrictModel):
    schema_version: str = Field(default=SCHEMA_VERSION, pattern=r"^\d+\.\d+$")


class FindingStatus(StrEnum):
    HYPOTHESIS = "HYPOTHESIS"
    OBSERVED_ANOMALY = "OBSERVED_ANOMALY"
    REPRODUCIBLE_ANOMALY = "REPRODUCIBLE_ANOMALY"
    SUPPORTED_POLICY_VIOLATION = "SUPPORTED_POLICY_VIOLATION"
    SECURITY_CONFIRMED = "SECURITY_CONFIRMED"
    CONFIGURATION_DEPENDENT = "CONFIGURATION_DEPENDENT"
    INCONCLUSIVE = "INCONCLUSIVE"
    REJECTED = "REJECTED"


_TRANSITIONS: dict[FindingStatus, set[FindingStatus]] = {
    FindingStatus.HYPOTHESIS: {
        FindingStatus.OBSERVED_ANOMALY,
        FindingStatus.INCONCLUSIVE,
        FindingStatus.REJECTED,
    },
    FindingStatus.OBSERVED_ANOMALY: {
        FindingStatus.REPRODUCIBLE_ANOMALY,
        FindingStatus.INCONCLUSIVE,
        FindingStatus.REJECTED,
    },
    FindingStatus.REPRODUCIBLE_ANOMALY: {
        FindingStatus.SUPPORTED_POLICY_VIOLATION,
        FindingStatus.CONFIGURATION_DEPENDENT,
        FindingStatus.INCONCLUSIVE,
        FindingStatus.REJECTED,
    },
    FindingStatus.SUPPORTED_POLICY_VIOLATION: {
        FindingStatus.SECURITY_CONFIRMED,
        FindingStatus.CONFIGURATION_DEPENDENT,
        FindingStatus.INCONCLUSIVE,
        FindingStatus.REJECTED,
    },
    FindingStatus.SECURITY_CONFIRMED: set(),
    FindingStatus.CONFIGURATION_DEPENDENT: set(),
    FindingStatus.INCONCLUSIVE: set(),
    FindingStatus.REJECTED: set(),
}


def assert_status_transition(current: FindingStatus, target: FindingStatus) -> None:
    if target not in _TRANSITIONS[current]:
        raise ValueError(f"Invalid finding transition: {current} -> {target}")


class FactKind(StrEnum):
    ENTRY_POINT = "entry_point"
    HTTP_EDGE = "http_edge"
    SECURITY_GUARD = "security_guard"
    DB_MUTATION = "db_mutation"
    DATA_MODEL = "data_model"
    COMMAND = "command"
    CONFIGURATION = "configuration"
    SERVICE = "service"
    CAPABILITY = "capability"
    TOPOLOGY = "topology"


class ExperimentKind(StrEnum):
    TRUST_LAUNDERING = "trust_laundering"
    HMAC_NONCE_MUTATION = "hmac_nonce_mutation"


class EvidenceType(StrEnum):
    HTTP = "http"
    DATABASE_DIFF = "database_diff"
    SOURCE = "source"
    MODEL = "model"
    REPLAY = "replay"
    REGRESSION_TEST = "regression_test"


class VerificationDecision(StrEnum):
    CONFIRMED = "confirmed"
    CONFIGURATION_DEPENDENT = "configuration_dependent"
    INCONCLUSIVE = "inconclusive"
    REJECTED = "rejected"


class RepositorySpec(VersionedModel):
    url: str
    commit: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        if not value.startswith("https://github.com/") or not value.endswith(".git"):
            raise ValueError("repository URL must be an HTTPS GitHub clone URL")
        return value

    @field_validator("commit")
    @classmethod
    def validate_commit(cls, value: str) -> str:
        if not FULL_SHA_RE.fullmatch(value):
            raise ValueError("commit must be a full 40-character SHA")
        return value.lower()


class Limits(StrictModel):
    max_runtime_seconds: int = Field(default=1800, ge=30, le=28800)
    max_model_tokens: int = Field(default=32000, ge=1000, le=500000)
    replay_count: int = Field(default=3, ge=3, le=10)


class ModelPolicy(StrictModel):
    base_url: str = "http://127.0.0.1:11434"
    hunter_model: str = "qwen3-coder:30b"
    verifier_model: str = "gpt-oss:20b"
    temperature: float = Field(default=0.0, ge=0.0, le=1.0)
    timeout_seconds: float = Field(default=300.0, ge=1.0, le=1800.0)

    @field_validator("base_url")
    @classmethod
    def validate_local_gateway(cls, value: str) -> str:
        parsed = urlsplit(value.strip())
        host = (parsed.hostname or "").lower().rstrip(".")
        if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
            raise ValueError("model gateway must be credential-free HTTP(S)")
        try:
            loopback = ip_address(host).is_loopback
        except ValueError:
            loopback = host == "localhost"
        if not loopback:
            raise ValueError("model gateway must resolve through a configured loopback alias")
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError("model gateway base URL cannot contain a path, query, or fragment")
        netloc = host if parsed.port is None else f"{host}:{parsed.port}"
        return urlunsplit((parsed.scheme, netloc, "", "", ""))


class Engagement(VersionedModel):
    id: UUID = Field(default_factory=uuid4)
    name: str = Field(min_length=1, max_length=128)
    repository: RepositorySpec
    focus: list[str] = Field(default_factory=lambda: ["cross-service-trust", "hmac-state"])
    limits: Limits = Field(default_factory=Limits)
    models: ModelPolicy = Field(default_factory=ModelPolicy)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ServiceSpec(StrictModel):
    name: str
    kind: Literal["database", "api", "worker", "model", "sensor"]
    base_url: str | None = None
    health_path: str | None = None


class DatabaseSpec(StrictModel):
    engine: Literal["mysql"] = "mysql"
    host: str = "127.0.0.1"
    port: int = Field(default=13306, ge=1, le=65535)
    database: str = "tls_ids"
    user: str = "tls_user"
    password_env: str = "LOGICLAB_TARGET_DB_PASSWORD"


class LabBlueprint(VersionedModel):
    target_name: str = "tls-anomaly-detection-ids"
    services: list[ServiceSpec]
    database: DatabaseSpec = Field(default_factory=DatabaseSpec)
    compose_file: str = "docker-compose.sensor.yml"
    compose_project: str = "logiclab_tls_ids"
    environment: dict[str, str] = Field(default_factory=dict)
    reset_tables: list[str] = Field(
        default_factory=lambda: ["firewall_actions", "flow_events", "request_nonces"]
    )


class StaticFact(VersionedModel):
    id: UUID = Field(default_factory=uuid4)
    kind: FactKind
    subject: str
    source_path: str
    line: int | None = Field(default=None, ge=1)
    data: dict[str, Any] = Field(default_factory=dict)


class Invariant(VersionedModel):
    id: UUID = Field(default_factory=uuid4)
    title: str
    expression: str
    expected_outcome: dict[str, Any]
    evidence_refs: list[str] = Field(min_length=1)


class Hypothesis(VersionedModel):
    id: UUID = Field(default_factory=uuid4)
    invariant_id: UUID
    title: str
    rationale: str
    candidate_entry_point: str
    experiment_kind: ExperimentKind
    source_refs: list[str] = Field(min_length=1)


class HypothesisSet(VersionedModel):
    invariants: list[Invariant] = Field(min_length=1)
    hypotheses: list[Hypothesis] = Field(min_length=1)


class Experiment(VersionedModel):
    id: UUID = Field(default_factory=uuid4)
    hypothesis_id: UUID
    kind: ExperimentKind
    replay_count: int = Field(default=3, ge=3, le=10)
    marker_ip: str = "198.18.0.42"


class ArtifactRef(StrictModel):
    path: str
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size: int = Field(ge=0)


class Evidence(VersionedModel):
    id: UUID = Field(default_factory=uuid4)
    experiment_id: UUID
    run_index: int = Field(ge=1)
    type: EvidenceType
    summary: str
    artifact: ArtifactRef
    source_refs: list[str] = Field(default_factory=list)


class Verification(VersionedModel):
    id: UUID = Field(default_factory=uuid4)
    hypothesis_id: UUID
    decision: VerificationDecision
    rationale: str
    supporting_evidence_ids: list[UUID] = Field(min_length=1)
    contradicting_evidence_ids: list[UUID] = Field(default_factory=list)
    model: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Finding(VersionedModel):
    id: UUID = Field(default_factory=uuid4)
    engagement_id: UUID
    hypothesis_id: UUID
    experiment_kind: ExperimentKind = ExperimentKind.TRUST_LAUNDERING
    title: str
    status: FindingStatus = FindingStatus.HYPOTHESIS
    invariant: Invariant
    evidence_ids: list[UUID] = Field(default_factory=list)
    verification_id: UUID | None = None
    regression_artifact: ArtifactRef | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RunStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class Run(VersionedModel):
    id: UUID = Field(default_factory=uuid4)
    engagement_id: UUID
    finding_id: UUID | None = None
    status: RunStatus = RunStatus.QUEUED
    error: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
