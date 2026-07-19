from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Iterable

from pydantic import ConfigDict, Field, JsonValue, model_validator

from logiclab.schemas import VersionedModel


class HarnessModel(VersionedModel):
    """Immutable, versioned contract used at every harness boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True, use_enum_values=False)


def _canonical_json(value: Any) -> str:
    if isinstance(value, VersionedModel):
        value = value.model_dump(mode="json")
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _content_hash(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _stable_unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted(set(values)))


class AgentRole(StrEnum):
    RESEARCH_DIRECTOR = "research_director"
    REPO_SURVEYOR = "repo_surveyor"
    ARCHITECTURE_MAPPER = "architecture_mapper"
    SECURITY_DOMAIN_MAPPER = "security_domain_mapper"
    BUILD_RUNTIME_SCOUT = "build_runtime_scout"
    TEST_HISTORY_ANALYST = "test_history_analyst"
    TWIN_SYNTHESIZER = "twin_synthesizer"
    INDEPENDENT_SKEPTIC = "independent_skeptic"


class TaskKind(StrEnum):
    DIRECT_WORKFLOW = "direct_workflow"
    INVENTORY_REPOSITORY = "inventory_repository"
    NEGOTIATE_CAPABILITIES = "negotiate_capabilities"
    INDEX_REPOSITORY = "index_repository"
    MAP_ARCHITECTURE = "map_architecture"
    MAP_SECURITY_DOMAIN = "map_security_domain"
    MAP_BUILD_RUNTIME = "map_build_runtime"
    MAP_TEST_HISTORY = "map_test_history"
    SYNTHESIZE_TWIN = "synthesize_twin"
    RESOLVE_CONFLICT = "resolve_conflict"
    VALIDATE_TWIN = "validate_twin"


class TaskStatus(StrEnum):
    PENDING = "PENDING"
    READY = "READY"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    PARTIAL = "PARTIAL"
    RETRYABLE = "RETRYABLE"
    ABSTAINED = "ABSTAINED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    CANCELLED = "CANCELLED"


class DependencyPolicy(StrEnum):
    STRICT = "strict"
    TOLERANT = "tolerant"


class ContextChannel(StrEnum):
    SYMBOLIC = "symbolic"
    GRAPH = "graph"
    SEMANTIC = "semantic"
    TEMPORAL = "temporal"
    RUNTIME_EVIDENCE = "runtime_evidence"


ROLE_TASK_KINDS: dict[AgentRole, frozenset[TaskKind]] = {
    AgentRole.RESEARCH_DIRECTOR: frozenset({TaskKind.DIRECT_WORKFLOW}),
    AgentRole.REPO_SURVEYOR: frozenset(
        {
            TaskKind.INVENTORY_REPOSITORY,
            TaskKind.NEGOTIATE_CAPABILITIES,
            TaskKind.INDEX_REPOSITORY,
        }
    ),
    AgentRole.ARCHITECTURE_MAPPER: frozenset({TaskKind.MAP_ARCHITECTURE}),
    AgentRole.SECURITY_DOMAIN_MAPPER: frozenset({TaskKind.MAP_SECURITY_DOMAIN}),
    AgentRole.BUILD_RUNTIME_SCOUT: frozenset({TaskKind.MAP_BUILD_RUNTIME}),
    AgentRole.TEST_HISTORY_ANALYST: frozenset({TaskKind.MAP_TEST_HISTORY}),
    AgentRole.TWIN_SYNTHESIZER: frozenset({TaskKind.SYNTHESIZE_TWIN}),
    AgentRole.INDEPENDENT_SKEPTIC: frozenset({TaskKind.RESOLVE_CONFLICT, TaskKind.VALIDATE_TWIN}),
}


class TaskScope(HarnessModel):
    module_ids: tuple[str, ...] = ()
    path_prefixes: tuple[str, ...] = ()
    symbol_ids: tuple[str, ...] = ()

    @model_validator(mode="after")
    def normalize(self) -> "TaskScope":
        paths: list[str] = []
        for raw_path in self.path_prefixes:
            path = raw_path.replace("\\", "/").strip("/")
            if not path or path == ".." or "../" in f"{path}/":
                raise ValueError("path prefixes must be relative and cannot traverse parents")
            paths.append(path)
        object.__setattr__(self, "module_ids", _stable_unique(self.module_ids))
        object.__setattr__(self, "path_prefixes", _stable_unique(paths))
        object.__setattr__(self, "symbol_ids", _stable_unique(self.symbol_ids))
        return self


class ContextRequest(HarnessModel):
    purpose: TaskKind
    channels: tuple[ContextChannel, ...] = ()
    anchor_refs: tuple[str, ...] = ()
    max_context_tokens: int = Field(default=12_000, ge=1, le=500_000)
    reserve_counterevidence_tokens: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def normalize(self) -> "ContextRequest":
        channels = tuple(sorted(set(self.channels), key=lambda item: item.value))
        object.__setattr__(self, "channels", channels)
        object.__setattr__(self, "anchor_refs", _stable_unique(self.anchor_refs))
        if self.reserve_counterevidence_tokens > self.max_context_tokens:
            raise ValueError("counterevidence reserve exceeds context limit")
        return self


class TaskBudget(HarnessModel):
    max_context_tokens: int = Field(default=12_000, ge=1, le=500_000)
    max_tool_calls: int = Field(default=40, ge=1, le=100_000)
    max_wall_seconds: int = Field(default=600, ge=1, le=86_400)
    max_retries: int = Field(default=2, ge=0, le=20)
    max_probe_rounds: int = Field(default=2, ge=0, le=20)
    max_artifact_bytes: int = Field(default=100_000_000, ge=1)


class TaskSpec(HarnessModel):
    task_id: str = Field(min_length=1, max_length=128)
    engagement_id: str = Field(min_length=1, max_length=128)
    snapshot_id: str = Field(min_length=1, max_length=128)
    kind: TaskKind
    role: AgentRole
    scope: TaskScope = Field(default_factory=TaskScope)
    required_input_refs: tuple[str, ...] = ()
    context: ContextRequest | None = None
    budget: TaskBudget = Field(default_factory=TaskBudget)
    depends_on: tuple[str, ...] = ()
    dependency_policy: DependencyPolicy = DependencyPolicy.STRICT
    priority: int = Field(default=0, ge=-100, le=100)
    idempotency_key: str = ""

    @model_validator(mode="after")
    def validate_and_derive_key(self) -> "TaskSpec":
        if self.kind not in ROLE_TASK_KINDS[self.role]:
            raise ValueError(f"role {self.role.value} cannot execute task {self.kind.value}")
        if self.task_id in self.depends_on:
            raise ValueError("task cannot depend on itself")
        object.__setattr__(self, "depends_on", _stable_unique(self.depends_on))
        object.__setattr__(self, "required_input_refs", _stable_unique(self.required_input_refs))
        if self.context is not None:
            if self.context.purpose is not self.kind:
                raise ValueError("context purpose must match task kind")
            if self.context.max_context_tokens > self.budget.max_context_tokens:
                raise ValueError("context request exceeds task budget")
        if not self.idempotency_key:
            key_material = {
                "schema_version": self.schema_version,
                "engagement_id": self.engagement_id,
                "snapshot_id": self.snapshot_id,
                "kind": self.kind.value,
                "role": self.role.value,
                "scope": self.scope.model_dump(mode="json"),
                "required_input_refs": self.required_input_refs,
                "context": self.context.model_dump(mode="json") if self.context else None,
                "budget": self.budget.model_dump(mode="json"),
            }
            object.__setattr__(self, "idempotency_key", _content_hash(key_material))
        return self


class ToolStatus(StrEnum):
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"


class ToolError(HarnessModel):
    code: str = Field(min_length=1, max_length=128)
    root_cause_hint: str = Field(min_length=1, max_length=1_000)
    safe_retry_instruction: str = Field(min_length=1, max_length=1_000)
    stop_condition: str = Field(min_length=1, max_length=1_000)


class ToolObservation(HarnessModel):
    tool_name: str = Field(min_length=1, max_length=128)
    status: ToolStatus
    summary: str = Field(min_length=1, max_length=1_000)
    data: dict[str, JsonValue] = Field(default_factory=dict)
    next_actions: tuple[str, ...] = ()
    artifacts: tuple[str, ...] = ()
    error: ToolError | None = None

    @model_validator(mode="after")
    def enforce_error_contract(self) -> "ToolObservation":
        if self.status is ToolStatus.ERROR and self.error is None:
            raise ValueError("error observation requires a recovery contract")
        if self.status is not ToolStatus.ERROR and self.error is not None:
            raise ValueError("only error observations may include a recovery contract")
        object.__setattr__(self, "next_actions", _stable_unique(self.next_actions))
        object.__setattr__(self, "artifacts", _stable_unique(self.artifacts))
        return self


class ClaimKind(StrEnum):
    REPOSITORY = "repository"
    CAPABILITY = "capability"
    MODULE = "module"
    SYMBOL = "symbol"
    ENTRY_POINT = "entry_point"
    DATA_MODEL = "data_model"
    SECURITY_CONTROL = "security_control"
    RUNTIME = "runtime"
    TEST_INTENT = "test_intent"
    TEMPORAL = "temporal"
    BEHAVIOR = "behavior"
    INTENT = "intent"


class EpistemicStatus(StrEnum):
    OBSERVED = "observed"
    DERIVED = "derived"
    INFERRED = "inferred"
    DISPUTED = "disputed"


class SourceRef(HarnessModel):
    ref_id: str = Field(min_length=1, max_length=256)
    artifact_id: str = Field(min_length=1, max_length=256)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    path: str | None = None
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def validate_span(self) -> "SourceRef":
        if (self.start_line is None) != (self.end_line is None):
            raise ValueError("source span requires both start_line and end_line")
        if self.start_line is not None and self.end_line is not None:
            if self.path is None:
                raise ValueError("source span requires a path")
            if self.end_line < self.start_line:
                raise ValueError("source span end cannot precede its start")
        return self


class ClaimProvenance(HarnessModel):
    snapshot_id: str = Field(min_length=1, max_length=128)
    repository_url: str = Field(min_length=1, max_length=2_048)
    commit: str = Field(pattern=r"^[0-9a-fA-F]{40}$")
    producer_role: AgentRole
    producer_run_id: str = Field(min_length=1, max_length=128)
    tool_name: str = Field(min_length=1, max_length=128)
    tool_version: str = Field(min_length=1, max_length=128)
    source_refs: tuple[SourceRef, ...] = Field(min_length=1)
    context_pack_id: str | None = Field(default=None, max_length=128)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def hash_material(self) -> dict[str, JsonValue]:
        """Identity of the evidence, excluding when it happened to be recorded.

        ``created_at`` is observation metadata, not part of what is claimed. Two
        runs over the same pinned commit produce the same evidence and must
        therefore produce the same ``content_hash``; including a wall clock here
        would make every claim ID time-dependent and break reproducibility.
        """

        material = self.model_dump(mode="json")
        material.pop("created_at", None)
        return material

    @model_validator(mode="after")
    def normalize(self) -> "ClaimProvenance":
        ids = [item.ref_id for item in self.source_refs]
        if len(ids) != len(set(ids)):
            raise ValueError("provenance source refs must have unique IDs")
        object.__setattr__(self, "commit", self.commit.lower())
        object.__setattr__(
            self, "source_refs", tuple(sorted(self.source_refs, key=lambda item: item.ref_id))
        )
        return self


class ClaimScope(HarnessModel):
    module_id: str | None = None
    config_profile: str | None = None
    operation_id: str | None = None


class Claim(HarnessModel):
    claim_id: str = Field(min_length=1, max_length=128)
    snapshot_id: str = Field(min_length=1, max_length=128)
    kind: ClaimKind
    subject_ref: str = Field(min_length=1, max_length=512)
    predicate: str = Field(min_length=1, max_length=256)
    value: JsonValue
    epistemic_status: EpistemicStatus
    scope: ClaimScope = Field(default_factory=ClaimScope)
    support_refs: tuple[str, ...] = Field(min_length=1)
    counterevidence_refs: tuple[str, ...] = ()
    provenance: ClaimProvenance
    supersedes_claim_id: str | None = None
    content_hash: str = ""

    def hash_material(self) -> dict[str, JsonValue]:
        return {
            "snapshot_id": self.snapshot_id,
            "kind": self.kind.value,
            "subject_ref": self.subject_ref,
            "predicate": self.predicate,
            "value": self.value,
            "epistemic_status": self.epistemic_status.value,
            "scope": self.scope.model_dump(mode="json"),
            "support_refs": list(self.support_refs),
            "counterevidence_refs": list(self.counterevidence_refs),
            "provenance": self.provenance.hash_material(),
            "supersedes_claim_id": self.supersedes_claim_id,
        }

    @model_validator(mode="after")
    def normalize_and_hash(self) -> "Claim":
        object.__setattr__(self, "support_refs", _stable_unique(self.support_refs))
        object.__setattr__(self, "counterevidence_refs", _stable_unique(self.counterevidence_refs))
        if self.supersedes_claim_id == self.claim_id:
            raise ValueError("claim cannot supersede itself")
        expected = _content_hash(self.hash_material())
        if self.content_hash and self.content_hash != expected:
            raise ValueError("claim content hash does not match its payload")
        object.__setattr__(self, "content_hash", expected)
        return self


class AbstainReason(StrEnum):
    UNSUPPORTED_STACK = "unsupported_stack"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    BUILD_UNREPRODUCIBLE = "build_unreproducible"
    FIXTURE_UNAVAILABLE = "fixture_unavailable"
    POLICY_DENIED = "policy_denied"
    BUDGET_EXHAUSTED = "budget_exhausted"
    CONTRADICTION_UNRESOLVED = "contradiction_unresolved"
    REPOSITORY_CONTENT_UNREADABLE = "repository_content_unreadable"


class AgentResultStatus(StrEnum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    ABSTAIN = "ABSTAIN"
    ERROR = "ERROR"


class AgentError(ToolError):
    """A role-level failure. Structurally identical to :class:`ToolError`.

    Both names are kept because the producers differ — one is raised by a tool
    call, the other by a whole role — but the recovery contract is one concept
    and inheriting it here means the two can never silently drift apart.
    """


class BudgetUsage(HarnessModel):
    context_tokens: int = Field(default=0, ge=0)
    tool_calls: int = Field(default=0, ge=0)
    wall_seconds: int = Field(default=0, ge=0)
    retries: int = Field(default=0, ge=0)
    probe_rounds: int = Field(default=0, ge=0)
    artifact_bytes: int = Field(default=0, ge=0)


class AgentResult(HarnessModel):
    task_id: str = Field(min_length=1, max_length=128)
    role: AgentRole
    status: AgentResultStatus
    summary: str = Field(min_length=1, max_length=1_000)
    claims: tuple[Claim, ...] = ()
    artifacts: tuple[str, ...] = ()
    next_actions: tuple[str, ...] = ()
    missing_information: tuple[str, ...] = ()
    conflict_ids: tuple[str, ...] = ()
    usage: BudgetUsage = Field(default_factory=BudgetUsage)
    abstain_reason: AbstainReason | None = None
    error: AgentError | None = None

    @model_validator(mode="after")
    def enforce_result_contract(self) -> "AgentResult":
        if self.status is AgentResultStatus.ERROR and self.error is None:
            raise ValueError("ERROR result requires an error recovery contract")
        if self.status is not AgentResultStatus.ERROR and self.error is not None:
            raise ValueError("only ERROR results may include an error contract")
        if self.status is AgentResultStatus.ABSTAIN and self.abstain_reason is None:
            raise ValueError("ABSTAIN result requires an abstain reason")
        if self.status is not AgentResultStatus.ABSTAIN and self.abstain_reason is not None:
            raise ValueError("only ABSTAIN results may include an abstain reason")
        if self.status is AgentResultStatus.PARTIAL and not self.missing_information:
            raise ValueError("PARTIAL result requires missing information")
        object.__setattr__(self, "artifacts", _stable_unique(self.artifacts))
        object.__setattr__(self, "next_actions", _stable_unique(self.next_actions))
        object.__setattr__(self, "missing_information", _stable_unique(self.missing_information))
        object.__setattr__(self, "conflict_ids", _stable_unique(self.conflict_ids))
        return self


class ConflictKind(StrEnum):
    VALUE_MISMATCH = "value_mismatch"


class ConflictStatus(StrEnum):
    UNRESOLVED = "unresolved"
    RESOLVED = "resolved"
    CONDITIONAL = "conditional"


class ClaimConflict(HarnessModel):
    conflict_id: str
    kind: ConflictKind = ConflictKind.VALUE_MISMATCH
    status: ConflictStatus = ConflictStatus.UNRESOLVED
    snapshot_id: str
    claim_kind: ClaimKind
    subject_ref: str
    predicate: str
    scope: ClaimScope
    claim_ids: tuple[str, ...] = Field(min_length=2)
    value_hashes: tuple[str, ...] = Field(min_length=2)
    blocking: bool


class BlackboardView(HarnessModel):
    accepted_claims: tuple[Claim, ...]
    disputed_claim_ids: tuple[str, ...]
    superseded_claim_ids: tuple[str, ...]
    conflicts: tuple[ClaimConflict, ...]


class BlackboardValidationError(ValueError):
    pass


class Blackboard:
    """Append-only in-memory claim ledger with deterministic materialization."""

    _blocking_kinds = frozenset(
        {
            ClaimKind.ENTRY_POINT,
            ClaimKind.SECURITY_CONTROL,
            ClaimKind.RUNTIME,
            ClaimKind.BEHAVIOR,
        }
    )

    def __init__(self) -> None:
        self._claims: dict[str, Claim] = {}
        self._order: list[str] = []
        self._snapshot_commits: dict[str, str] = {}

    @property
    def claims(self) -> tuple[Claim, ...]:
        return tuple(self._claims[item].model_copy(deep=True) for item in self._order)

    def get_claim(self, claim_id: str) -> Claim:
        try:
            return self._claims[claim_id].model_copy(deep=True)
        except KeyError as exc:
            raise KeyError(f"claim not found: {claim_id}") from exc

    def append_claim(self, claim: Claim) -> Claim:
        return self.append_claim_batch((claim,))[0]

    def append_claim_batch(self, claims: Iterable[Claim]) -> tuple[Claim, ...]:
        batch = tuple(claims)
        staged_claims = dict(self._claims)
        staged_order = list(self._order)
        staged_commits = dict(self._snapshot_commits)
        results: list[Claim] = []
        for incoming in batch:
            claim = incoming.model_copy(deep=True)
            existing = staged_claims.get(claim.claim_id)
            if existing is not None:
                # Compare the content seal, not the whole model: ``created_at``
                # is observation metadata and differs between two records of the
                # very same assertion. Full-model equality here would turn an
                # idempotent re-append into a hard failure.
                if existing.content_hash == claim.content_hash:
                    results.append(existing.model_copy(deep=True))
                    continue
                raise BlackboardValidationError(
                    f"claim {claim.claim_id} is append-only and cannot be overwritten"
                )
            self._validate_claim(claim, staged_claims, staged_commits)
            staged_claims[claim.claim_id] = claim
            staged_order.append(claim.claim_id)
            staged_commits.setdefault(claim.snapshot_id, claim.provenance.commit)
            results.append(claim.model_copy(deep=True))
        self._claims = staged_claims
        self._order = staged_order
        self._snapshot_commits = staged_commits
        return tuple(results)

    @staticmethod
    def _validate_claim(
        claim: Claim,
        known_claims: dict[str, Claim],
        snapshot_commits: dict[str, str],
    ) -> None:
        if claim.snapshot_id != claim.provenance.snapshot_id:
            raise BlackboardValidationError("claim snapshot does not match its provenance")
        known_commit = snapshot_commits.get(claim.snapshot_id)
        if known_commit is not None and known_commit != claim.provenance.commit:
            raise BlackboardValidationError("snapshot cannot contain claims from different commits")
        provenance_refs = {item.ref_id for item in claim.provenance.source_refs}
        cited_refs = set(claim.support_refs) | set(claim.counterevidence_refs)
        unknown_refs = cited_refs - provenance_refs
        if unknown_refs:
            raise BlackboardValidationError(
                f"claim cites unknown provenance refs: {', '.join(sorted(unknown_refs))}"
            )
        expected_hash = _content_hash(claim.hash_material())
        if expected_hash != claim.content_hash:
            raise BlackboardValidationError("claim content hash does not match its payload")
        if claim.supersedes_claim_id is not None:
            previous = known_claims.get(claim.supersedes_claim_id)
            if previous is None:
                raise BlackboardValidationError("superseded claim must already exist")
            identity = (
                claim.snapshot_id,
                claim.kind,
                claim.subject_ref,
                claim.predicate,
                claim.scope,
            )
            previous_identity = (
                previous.snapshot_id,
                previous.kind,
                previous.subject_ref,
                previous.predicate,
                previous.scope,
            )
            if identity != previous_identity:
                raise BlackboardValidationError(
                    "a claim may only supersede the same scoped predicate"
                )

    def query(
        self,
        *,
        snapshot_id: str | None = None,
        kind: ClaimKind | None = None,
        subject_ref: str | None = None,
        predicate: str | None = None,
    ) -> tuple[Claim, ...]:
        result = []
        for claim_id in self._order:
            claim = self._claims[claim_id]
            if snapshot_id is not None and claim.snapshot_id != snapshot_id:
                continue
            if kind is not None and claim.kind is not kind:
                continue
            if subject_ref is not None and claim.subject_ref != subject_ref:
                continue
            if predicate is not None and claim.predicate != predicate:
                continue
            result.append(claim.model_copy(deep=True))
        return tuple(result)

    def detect_conflicts(self) -> tuple[ClaimConflict, ...]:
        superseded = {claim.supersedes_claim_id for claim in self._claims.values()}
        groups: dict[tuple[str, str, str, str, str], list[Claim]] = defaultdict(list)
        for claim_id in self._order:
            if claim_id in superseded:
                continue
            claim = self._claims[claim_id]
            key = (
                claim.snapshot_id,
                claim.kind.value,
                claim.subject_ref,
                claim.predicate,
                _canonical_json(claim.scope.model_dump(mode="json")),
            )
            groups[key].append(claim)

        conflicts: list[ClaimConflict] = []
        for grouped_claims in groups.values():
            by_value: dict[str, list[Claim]] = defaultdict(list)
            for claim in grouped_claims:
                by_value[_content_hash(claim.value)].append(claim)
            if len(by_value) < 2:
                continue
            exemplar = grouped_claims[0]
            claim_ids = tuple(sorted(item.claim_id for item in grouped_claims))
            value_hashes = tuple(sorted(by_value))
            conflict_id = (
                "CONFLICT-"
                + _content_hash(
                    {
                        "snapshot_id": exemplar.snapshot_id,
                        "kind": exemplar.kind.value,
                        "subject_ref": exemplar.subject_ref,
                        "predicate": exemplar.predicate,
                        "scope": exemplar.scope.model_dump(mode="json"),
                        "claim_ids": claim_ids,
                        "value_hashes": value_hashes,
                    }
                )[:20]
            )
            conflicts.append(
                ClaimConflict(
                    conflict_id=conflict_id,
                    snapshot_id=exemplar.snapshot_id,
                    claim_kind=exemplar.kind,
                    subject_ref=exemplar.subject_ref,
                    predicate=exemplar.predicate,
                    scope=exemplar.scope,
                    claim_ids=claim_ids,
                    value_hashes=value_hashes,
                    blocking=exemplar.kind in self._blocking_kinds,
                )
            )
        return tuple(sorted(conflicts, key=lambda item: item.conflict_id))

    def reduce(self) -> BlackboardView:
        conflicts = self.detect_conflicts()
        conflicted = {claim_id for item in conflicts for claim_id in item.claim_ids}
        explicitly_disputed = {
            item.claim_id
            for item in self._claims.values()
            if item.epistemic_status is EpistemicStatus.DISPUTED
        }
        disputed = conflicted | explicitly_disputed
        superseded = {
            item.supersedes_claim_id
            for item in self._claims.values()
            if item.supersedes_claim_id is not None
        }
        accepted = tuple(
            self._claims[claim_id].model_copy(deep=True)
            for claim_id in self._order
            if claim_id not in disputed and claim_id not in superseded
        )
        return BlackboardView(
            accepted_claims=accepted,
            disputed_claim_ids=tuple(sorted(disputed)),
            superseded_claim_ids=tuple(sorted(superseded)),
            conflicts=conflicts,
        )


class InvalidTaskTransition(ValueError):
    pass


class TaskRecord(HarnessModel):
    spec: TaskSpec
    status: TaskStatus


_TASK_TRANSITIONS: dict[TaskStatus, frozenset[TaskStatus]] = {
    TaskStatus.PENDING: frozenset({TaskStatus.READY, TaskStatus.BLOCKED, TaskStatus.CANCELLED}),
    TaskStatus.READY: frozenset({TaskStatus.RUNNING, TaskStatus.BLOCKED, TaskStatus.CANCELLED}),
    TaskStatus.RUNNING: frozenset(
        {
            TaskStatus.SUCCEEDED,
            TaskStatus.PARTIAL,
            TaskStatus.RETRYABLE,
            TaskStatus.ABSTAINED,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED,
        }
    ),
    TaskStatus.RETRYABLE: frozenset(
        {TaskStatus.READY, TaskStatus.FAILED, TaskStatus.ABSTAINED, TaskStatus.CANCELLED}
    ),
    TaskStatus.SUCCEEDED: frozenset(),
    TaskStatus.PARTIAL: frozenset(),
    TaskStatus.ABSTAINED: frozenset(),
    TaskStatus.FAILED: frozenset(),
    TaskStatus.BLOCKED: frozenset(),
    TaskStatus.CANCELLED: frozenset(),
}


class TaskDAG:
    """Deterministic dependency scheduler; it executes no commands or models."""

    def __init__(
        self,
        tasks: Iterable[TaskSpec] = (),
        *,
        role_team: "RoleTeam | None" = None,
    ) -> None:
        self._records: dict[str, TaskRecord] = {}
        self._idempotency_keys: dict[str, str] = {}
        self._usage: dict[str, BudgetUsage] = {}
        self._role_team = role_team
        initial = tuple(tasks)
        if initial:
            self.add_tasks(initial)

    def add_task(self, spec: TaskSpec) -> TaskSpec:
        return self.add_tasks((spec,))[0]

    def add_tasks(self, specs: Iterable[TaskSpec]) -> tuple[TaskSpec, ...]:
        batch = tuple(specs)
        batch_ids = [item.task_id for item in batch]
        if len(batch_ids) != len(set(batch_ids)):
            raise ValueError("task IDs must be unique")
        if any(item in self._records for item in batch_ids):
            raise ValueError("task ID already exists")

        available_ids = set(self._records) | set(batch_ids)
        for spec in batch:
            missing = set(spec.depends_on) - available_ids
            if missing:
                raise ValueError(f"unknown task dependencies: {', '.join(sorted(missing))}")
            existing_task_id = self._idempotency_keys.get(spec.idempotency_key)
            if existing_task_id is not None:
                raise ValueError(f"idempotency key already belongs to task {existing_task_id}")
        batch_keys = [item.idempotency_key for item in batch]
        if len(batch_keys) != len(set(batch_keys)):
            raise ValueError("idempotency key is duplicated within task batch")

        dependencies = {
            task_id: tuple(record.spec.depends_on) for task_id, record in self._records.items()
        }
        dependencies.update({item.task_id: item.depends_on for item in batch})
        self._assert_acyclic(dependencies)

        for spec in batch:
            initial_status = TaskStatus.READY if not spec.depends_on else TaskStatus.PENDING
            self._records[spec.task_id] = TaskRecord(spec=spec, status=initial_status)
            self._idempotency_keys[spec.idempotency_key] = spec.task_id
        self._refresh_dependencies()
        return tuple(item.model_copy(deep=True) for item in batch)

    @staticmethod
    def _assert_acyclic(dependencies: dict[str, tuple[str, ...]]) -> None:
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(task_id: str) -> None:
            if task_id in visiting:
                raise ValueError("task dependencies contain a cycle")
            if task_id in visited:
                return
            visiting.add(task_id)
            for dependency_id in dependencies.get(task_id, ()):
                visit(dependency_id)
            visiting.remove(task_id)
            visited.add(task_id)

        for task_id in dependencies:
            visit(task_id)

    def status(self, task_id: str) -> TaskStatus:
        return self._get(task_id).status

    def record(self, task_id: str) -> TaskRecord:
        return self._get(task_id).model_copy(deep=True)

    def ready_tasks(self, role: AgentRole | None = None) -> tuple[TaskSpec, ...]:
        self._refresh_dependencies()
        specs = [
            record.spec
            for record in self._records.values()
            if record.status is TaskStatus.READY and (role is None or record.spec.role is role)
        ]
        specs.sort(key=lambda item: (-item.priority, item.task_id))
        return tuple(item.model_copy(deep=True) for item in specs)

    def _max_parallelism(self, role: AgentRole) -> int:
        team = self._role_team if self._role_team is not None else DEFAULT_ROLE_TEAM
        for member in team.members:
            if member.role is role:
                return member.max_parallelism
        return 1

    def running_counts(self) -> dict[AgentRole, int]:
        return dict(
            Counter(
                record.spec.role
                for record in self._records.values()
                if record.status is TaskStatus.RUNNING
            )
        )

    def dispatchable_tasks(self, role: AgentRole | None = None) -> tuple[TaskSpec, ...]:
        """Ready tasks whose role still has concurrency headroom.

        ``ready_tasks`` answers "are this task's dependencies satisfied"; this
        answers "may it start right now", which additionally respects the role
        team's ``max_parallelism``.
        """

        running = self.running_counts()
        allowed: list[TaskSpec] = []
        for spec in self.ready_tasks(role):
            limit = self._max_parallelism(spec.role)
            if running.get(spec.role, 0) + sum(
                1 for item in allowed if item.role is spec.role
            ) < limit:
                allowed.append(spec)
        return tuple(allowed)

    def claim_next(self, role: AgentRole | None = None) -> TaskSpec | None:
        dispatchable = self.dispatchable_tasks(role)
        if not dispatchable:
            return None
        spec = dispatchable[0]
        self.transition(spec.task_id, TaskStatus.RUNNING)
        return spec

    def record_usage(self, task_id: str, usage: BudgetUsage) -> BudgetUsage:
        """Accumulate observed budget consumption for one task."""

        self._get(task_id)
        current = self._usage.get(task_id, BudgetUsage())
        merged = BudgetUsage(
            context_tokens=current.context_tokens + usage.context_tokens,
            tool_calls=current.tool_calls + usage.tool_calls,
            wall_seconds=current.wall_seconds + usage.wall_seconds,
            retries=current.retries + usage.retries,
            probe_rounds=current.probe_rounds + usage.probe_rounds,
            artifact_bytes=current.artifact_bytes + usage.artifact_bytes,
        )
        self._usage[task_id] = merged
        return merged

    def usage_for(self, task_id: str) -> BudgetUsage:
        self._get(task_id)
        return self._usage.get(task_id, BudgetUsage())

    def aggregate_usage(self) -> BudgetUsage:
        total = BudgetUsage()
        for usage in self._usage.values():
            total = BudgetUsage(
                context_tokens=total.context_tokens + usage.context_tokens,
                tool_calls=total.tool_calls + usage.tool_calls,
                wall_seconds=total.wall_seconds + usage.wall_seconds,
                retries=total.retries + usage.retries,
                probe_rounds=total.probe_rounds + usage.probe_rounds,
                artifact_bytes=total.artifact_bytes + usage.artifact_bytes,
            )
        return total

    def assess_stop(
        self,
        task_id: str,
        *,
        policy_denied: bool = False,
        snapshot_matches: bool = True,
        recent_coverage_gains: tuple[float, ...] = (),
    ) -> StopAssessment:
        """Apply the budget and convergence gates to one task's recorded usage."""

        record = self._get(task_id)
        return StopRules.evaluate(
            record.spec.budget,
            self.usage_for(task_id),
            policy_denied=policy_denied,
            snapshot_matches=snapshot_matches,
            recent_coverage_gains=recent_coverage_gains,
        )

    def transition(self, task_id: str, target: TaskStatus) -> TaskRecord:
        record = self._get(task_id)
        if target not in _TASK_TRANSITIONS[record.status]:
            raise InvalidTaskTransition(f"invalid task transition: {record.status} -> {target}")
        updated = record.model_copy(update={"status": target})
        self._records[task_id] = updated
        self._refresh_dependencies()
        return updated.model_copy(deep=True)

    def complete_task(self, task_id: str, result: AgentResult) -> TaskRecord:
        record = self._get(task_id)
        if result.task_id != task_id:
            raise ValueError("agent result references the wrong task")
        if result.role is not record.spec.role:
            raise ValueError("agent result role does not match task role")
        target = {
            AgentResultStatus.COMPLETE: TaskStatus.SUCCEEDED,
            AgentResultStatus.PARTIAL: TaskStatus.PARTIAL,
            AgentResultStatus.ABSTAIN: TaskStatus.ABSTAINED,
            AgentResultStatus.ERROR: TaskStatus.RETRYABLE,
        }[result.status]
        # Validate before banking anything. A rejected completion must leave no
        # trace: otherwise a duplicated or retried call inflates usage and can
        # spuriously trip the MAX_RETRIES gate on work that never ran.
        transitioned = self.transition(task_id, target)
        self.record_usage(task_id, result.usage)
        if target is TaskStatus.RETRYABLE:
            # An ERROR result is itself the evidence that one attempt was spent;
            # without this the MAX_RETRIES gate could never fire.
            self.record_usage(task_id, BudgetUsage(retries=1))
        return transitioned

    def retry_task(self, task_id: str) -> TaskRecord:
        """Return a RETRYABLE task to the ready pool, or fail it once a stop rule fires.

        Without this, ERROR is a silent dead end: ``_refresh_dependencies`` only
        promotes PENDING tasks, so a RETRYABLE task would never be scheduled
        again and ``max_retries`` could never be reached. This is the explicit
        stop condition that closes the recovery contract.
        """

        record = self._get(task_id)
        if record.status is not TaskStatus.RETRYABLE:
            raise InvalidTaskTransition(
                f"only a RETRYABLE task can be retried, not {record.status}"
            )
        if self.assess_stop(task_id).stop:
            return self.transition(task_id, TaskStatus.FAILED)
        return self.transition(task_id, TaskStatus.READY)

    def _get(self, task_id: str) -> TaskRecord:
        try:
            return self._records[task_id]
        except KeyError as exc:
            raise KeyError(f"task not found: {task_id}") from exc

    def _refresh_dependencies(self) -> None:
        changed = True
        while changed:
            changed = False
            for task_id, record in tuple(self._records.items()):
                if record.status is not TaskStatus.PENDING:
                    continue
                statuses = [self._records[item].status for item in record.spec.depends_on]
                if not statuses:
                    target = TaskStatus.READY
                elif any(
                    item in {TaskStatus.FAILED, TaskStatus.BLOCKED, TaskStatus.CANCELLED}
                    for item in statuses
                ):
                    target = TaskStatus.BLOCKED
                elif record.spec.dependency_policy is DependencyPolicy.STRICT:
                    if any(item in {TaskStatus.PARTIAL, TaskStatus.ABSTAINED} for item in statuses):
                        target = TaskStatus.BLOCKED
                    elif all(item is TaskStatus.SUCCEEDED for item in statuses):
                        target = TaskStatus.READY
                    else:
                        continue
                else:
                    tolerated = {TaskStatus.SUCCEEDED, TaskStatus.PARTIAL, TaskStatus.ABSTAINED}
                    if all(item in tolerated for item in statuses):
                        target = TaskStatus.READY
                    else:
                        continue
                self._records[task_id] = record.model_copy(update={"status": target})
                changed = True


class StopReason(StrEnum):
    CONTEXT_BUDGET_EXHAUSTED = "context_budget_exhausted"
    TOOL_BUDGET_EXHAUSTED = "tool_budget_exhausted"
    WALL_TIME_EXHAUSTED = "wall_time_exhausted"
    ARTIFACT_BUDGET_EXHAUSTED = "artifact_budget_exhausted"
    MAX_RETRIES = "max_retries"
    MAX_PROBE_ROUNDS = "max_probe_rounds"
    POLICY_DENIED = "policy_denied"
    SNAPSHOT_MISMATCH = "snapshot_mismatch"
    NO_COVERAGE_GAIN = "no_coverage_gain"


class StopAssessment(HarnessModel):
    stop: bool
    reasons: tuple[StopReason, ...] = ()


class StopRules:
    """Pure budget and convergence checks used before scheduling more work."""

    @staticmethod
    def evaluate(
        budget: TaskBudget,
        usage: BudgetUsage,
        *,
        policy_denied: bool = False,
        snapshot_matches: bool = True,
        recent_coverage_gains: tuple[float, ...] = (),
        minimum_coverage_gain: float = 0.01,
        stagnant_rounds: int = 2,
    ) -> StopAssessment:
        reasons: list[StopReason] = []
        if usage.context_tokens >= budget.max_context_tokens:
            reasons.append(StopReason.CONTEXT_BUDGET_EXHAUSTED)
        if usage.tool_calls >= budget.max_tool_calls:
            reasons.append(StopReason.TOOL_BUDGET_EXHAUSTED)
        if usage.wall_seconds >= budget.max_wall_seconds:
            reasons.append(StopReason.WALL_TIME_EXHAUSTED)
        if usage.artifact_bytes >= budget.max_artifact_bytes:
            reasons.append(StopReason.ARTIFACT_BUDGET_EXHAUSTED)
        if usage.retries > 0 and usage.retries >= budget.max_retries:
            reasons.append(StopReason.MAX_RETRIES)
        if usage.probe_rounds > 0 and usage.probe_rounds >= budget.max_probe_rounds:
            reasons.append(StopReason.MAX_PROBE_ROUNDS)
        if policy_denied:
            reasons.append(StopReason.POLICY_DENIED)
        if not snapshot_matches:
            reasons.append(StopReason.SNAPSHOT_MISMATCH)
        if stagnant_rounds > 0 and len(recent_coverage_gains) >= stagnant_rounds:
            recent = recent_coverage_gains[-stagnant_rounds:]
            if all(gain < minimum_coverage_gain for gain in recent):
                reasons.append(StopReason.NO_COVERAGE_GAIN)
        unique = tuple(sorted(set(reasons), key=lambda item: item.value))
        return StopAssessment(stop=bool(unique), reasons=unique)


class RoleDefinition(HarnessModel):
    role: AgentRole
    task_kinds: tuple[TaskKind, ...] = Field(min_length=1)
    description: str = Field(min_length=1, max_length=1_000)
    max_parallelism: int = Field(default=1, ge=1, le=100)


class RoleTeam(HarnessModel):
    members: tuple[RoleDefinition, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_team(self) -> "RoleTeam":
        roles = [member.role for member in self.members]
        if len(roles) != len(set(roles)):
            raise ValueError("role team cannot contain duplicate roles")
        covered: set[TaskKind] = set()
        for member in self.members:
            expected = ROLE_TASK_KINDS[member.role]
            if set(member.task_kinds) != set(expected):
                raise ValueError(f"task assignment does not match role {member.role.value}")
            overlap = covered & set(member.task_kinds)
            if overlap:
                raise ValueError("each task kind must have exactly one owning role")
            covered.update(member.task_kinds)
        if covered != set(TaskKind):
            raise ValueError("role team must cover every task kind")
        return self

    def role_for(self, task_kind: TaskKind) -> AgentRole:
        for member in self.members:
            if task_kind in member.task_kinds:
                return member.role
        raise KeyError(f"no role owns task kind: {task_kind}")


def default_role_team() -> RoleTeam:
    descriptions = {
        AgentRole.RESEARCH_DIRECTOR: "Schedules typed work and enforces gates; it does not inspect source.",
        AgentRole.REPO_SURVEYOR: "Inventories the pinned repository and negotiates capabilities.",
        AgentRole.ARCHITECTURE_MAPPER: "Maps modules, symbols, entry points, and operation candidates.",
        AgentRole.SECURITY_DOMAIN_MAPPER: "Maps identity, resources, controls, and state transitions.",
        AgentRole.BUILD_RUNTIME_SCOUT: "Produces typed build and runtime blueprint candidates.",
        AgentRole.TEST_HISTORY_ANALYST: "Maps fixtures, test intent, and temporal evidence.",
        AgentRole.TWIN_SYNTHESIZER: "Reduces accepted claims into a project twin draft.",
        AgentRole.INDEPENDENT_SKEPTIC: "Resolves conflicts and validates the twin from cited evidence.",
    }
    members = tuple(
        RoleDefinition(
            role=role,
            task_kinds=tuple(sorted(kinds, key=lambda item: item.value)),
            description=descriptions[role],
            max_parallelism=4
            if role
            in {
                AgentRole.REPO_SURVEYOR,
                AgentRole.ARCHITECTURE_MAPPER,
                AgentRole.SECURITY_DOMAIN_MAPPER,
                AgentRole.TEST_HISTORY_ANALYST,
            }
            else 1,
        )
        for role, kinds in ROLE_TASK_KINDS.items()
    )
    return RoleTeam(members=members)


DEFAULT_ROLE_TEAM = default_role_team()


__all__ = [
    "AbstainReason",
    "AgentError",
    "AgentResult",
    "AgentResultStatus",
    "AgentRole",
    "Blackboard",
    "BlackboardValidationError",
    "BlackboardView",
    "BudgetUsage",
    "Claim",
    "ClaimConflict",
    "ClaimKind",
    "ClaimProvenance",
    "ClaimScope",
    "ConflictKind",
    "ConflictStatus",
    "ContextChannel",
    "ContextRequest",
    "DEFAULT_ROLE_TEAM",
    "DependencyPolicy",
    "EpistemicStatus",
    "InvalidTaskTransition",
    "ROLE_TASK_KINDS",
    "RoleDefinition",
    "RoleTeam",
    "SourceRef",
    "StopAssessment",
    "StopReason",
    "StopRules",
    "TaskBudget",
    "TaskDAG",
    "TaskKind",
    "TaskRecord",
    "TaskScope",
    "TaskSpec",
    "TaskStatus",
    "ToolError",
    "ToolObservation",
    "ToolStatus",
    "default_role_team",
]
