from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Protocol
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from logiclab.harness import (
    AgentResult,
    AgentResultStatus,
    AgentRole,
    Blackboard,
    BlackboardView,
    Claim as HarnessClaim,
    DependencyPolicy,
    EpistemicStatus,
    TaskDAG,
    TaskKind,
    TaskScope,
    TaskSpec,
    TaskStatus,
)
from logiclab.intelligence import (
    AnalysisStatus,
    Diagnostic as IntelligenceDiagnostic,
    DiagnosticSeverity,
    RepositoryIntelligenceReport,
    RuntimeLevel,
    UnderstandingLevel,
    UnsupportedZone,
    analyze_repository,
)
from logiclab.roles import (
    Adjudication,
    EvidenceIndex,
    adjudicate,
    execute_role,
    skeptic_result,
)
from logiclab.security import Redactor
from logiclab.snapshots import (
    GitSnapshotFetcher,
    SnapshotPolicyError,
    SnapshotResult,
    validate_repository_url,
)

if TYPE_CHECKING:  # the static path must not import the model stack at runtime
    from logiclab.proposals import ProposalOutcome


class AnalysisModel(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=False)


class RepositoryAnalysisStatus(StrEnum):
    QUEUED = "queued"
    FETCHING = "fetching"
    ANALYZING = "analyzing"
    READY = "ready"
    NEEDS_REVIEW = "needs_review"
    FAILED = "failed"


class RepositoryAnalysisRequest(AnalysisModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    repository_url: str
    commit: str = Field(pattern=r"^[0-9a-fA-F]{40}$")

    @field_validator("repository_url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        return validate_repository_url(value)

    @field_validator("commit")
    @classmethod
    def normalize_commit(cls, value: str) -> str:
        return value.lower()


class AgentTaskView(AnalysisModel):
    id: str
    title: str
    agent: str
    status: str
    depends_on: list[str] = Field(default_factory=list)
    output: str | None = None
    duration_ms: int | None = None


class CapabilityScore(AnalysisModel):
    score: float = Field(ge=0, le=100)
    label: str
    detail: str | None = None


class CapabilityView(AnalysisModel):
    understanding: CapabilityScore
    runtime: CapabilityScore
    coverage: CapabilityScore


class ComponentView(AnalysisModel):
    id: str
    name: str
    kind: str
    path: str
    language: str | None = None
    exposure: str | None = None
    confidence: float | None = Field(default=None, ge=0, le=1)


class DiagnosticView(AnalysisModel):
    id: str
    severity: str
    message: str
    path: str | None = None


class ClaimView(AnalysisModel):
    id: str
    subject: str
    predicate: str
    value: str
    confidence: float = Field(ge=0, le=1)
    source_refs: list[str]
    status: str


class EvidenceSourceView(AnalysisModel):
    ref_id: str
    artifact_id: str
    sha256: str
    path: str | None = None
    start_line: int | None = None
    end_line: int | None = None


class ProvenanceView(AnalysisModel):
    claim_id: str
    snapshot_id: str
    repository_url: str
    commit: str
    producer_role: str
    producer_run_id: str
    tool_name: str
    tool_version: str
    sources: list[EvidenceSourceView]


class RepositoryAnalysisResponse(AnalysisModel):
    id: UUID
    name: str
    status: str
    repository_url: str
    commit: str
    snapshot_digest: str | None
    created_at: datetime
    updated_at: datetime
    capabilities: CapabilityView
    components: list[ComponentView]
    diagnostics: list[DiagnosticView]
    agent_tasks: list[AgentTaskView]
    claims: list[ClaimView]
    provenance: list[ProvenanceView]
    component_total: int = Field(ge=0)
    diagnostic_total: int = Field(ge=0)
    claim_total: int = Field(ge=0)
    conflict_total: int = Field(ge=0)
    error_code: str | None = None
    error_message: str | None = None


class RepositoryAnalysis(AnalysisModel):
    id: UUID = Field(default_factory=uuid4)
    name: str
    repository_url: str
    commit: str
    status: RepositoryAnalysisStatus = RepositoryAnalysisStatus.QUEUED
    snapshot_digest: str | None = None
    report: RepositoryIntelligenceReport | None = None
    agent_tasks: list[AgentTaskView] = Field(default_factory=list)
    harness_claims: list[HarnessClaim] = Field(default_factory=list)
    disputed_claim_ids: list[str] = Field(default_factory=list)
    error_code: str | None = None
    error_message: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_response(
        self, *, include_details: bool = True, detail_limit: int = 2_000
    ) -> RepositoryAnalysisResponse:
        if not 1 <= detail_limit <= 10_000:
            raise ValueError("detail limit must be between 1 and 10000")
        report = self.report
        understanding = report.understanding_level if report else None
        runtime = report.runtime_level if report else RuntimeLevel.R0
        coverage = report.coverage.analysis_percent if report else 0.0
        understanding_scores = {
            UnderstandingLevel.U0: 20,
            UnderstandingLevel.U1: 40,
            UnderstandingLevel.U2: 60,
            UnderstandingLevel.U3: 80,
            UnderstandingLevel.U4: 100,
        }
        runtime_scores = {
            RuntimeLevel.R0: 0,
            RuntimeLevel.R1: 25,
            RuntimeLevel.R2: 50,
            RuntimeLevel.R3: 75,
            RuntimeLevel.R4: 100,
        }
        components = (
            []
            if report is None or not include_details
            else [
                ComponentView(
                    id=item.id,
                    name=item.name,
                    kind=", ".join(item.ecosystems) or "source",
                    path=item.root_path,
                    language=", ".join(item.languages) or None,
                    exposure=item.status.value.lower(),
                    confidence=understanding_scores[item.understanding_level] / 100,
                )
                for item in report.components[:detail_limit]
            ]
        )
        diagnostics: list[DiagnosticView] = []
        if report is not None and include_details:
            diagnostics.extend(
                DiagnosticView(
                    id=f"diagnostic-{index}",
                    severity=item.severity.value,
                    message=item.message,
                    path=item.path,
                )
                for index, item in enumerate(report.diagnostics, start=1)
            )
            diagnostics.extend(
                DiagnosticView(
                    id=f"unsupported-{index}",
                    severity="warning",
                    message=item.reason,
                    path=item.path,
                )
                for index, item in enumerate(report.unsupported_zones, start=1)
            )
            diagnostics = diagnostics[:detail_limit]
        disputed = set(self.disputed_claim_ids)
        selected_claims = self.harness_claims[:detail_limit] if include_details else []
        claims = [
            ClaimView(
                id=item.claim_id,
                subject=item.subject_ref,
                predicate=item.predicate,
                value=str(item.value),
                confidence=1.0 if item.epistemic_status is EpistemicStatus.OBSERVED else 0.75,
                source_refs=[
                    f"{source.path}:{source.start_line}"
                    if source.path and source.start_line
                    else source.ref_id
                    for source in item.provenance.source_refs
                ],
                status="conflicted" if item.claim_id in disputed else item.epistemic_status.value,
            )
            for item in selected_claims
        ]
        provenance = [
            ProvenanceView(
                claim_id=item.claim_id,
                snapshot_id=item.provenance.snapshot_id,
                repository_url=item.provenance.repository_url,
                commit=item.provenance.commit,
                producer_role=item.provenance.producer_role.value,
                producer_run_id=item.provenance.producer_run_id,
                tool_name=item.provenance.tool_name,
                tool_version=item.provenance.tool_version,
                sources=[
                    EvidenceSourceView(
                        ref_id=source.ref_id,
                        artifact_id=source.artifact_id,
                        sha256=source.sha256,
                        path=source.path,
                        start_line=source.start_line,
                        end_line=source.end_line,
                    )
                    for source in item.provenance.source_refs
                ],
            )
            for item in selected_claims
        ]
        return RepositoryAnalysisResponse(
            id=self.id,
            name=self.name,
            status=self.status.value,
            repository_url=self.repository_url,
            commit=self.commit,
            snapshot_digest=self.snapshot_digest,
            created_at=self.created_at,
            updated_at=self.updated_at,
            capabilities=CapabilityView(
                understanding=CapabilityScore(
                    score=0 if understanding is None else understanding_scores[understanding],
                    label="not assessed" if understanding is None else understanding.value,
                    detail=(
                        "Static understanding has not been assessed"
                        if understanding is None
                        else "Measured static understanding for the analyzed snapshot"
                    ),
                ),
                runtime=CapabilityScore(
                    score=runtime_scores[runtime],
                    label=runtime.value,
                    detail="Static-only until an approved sandbox manifest is available",
                ),
                coverage=CapabilityScore(
                    score=coverage,
                    label=f"{coverage:.0f}%",
                    detail="Eligible source-file analysis coverage",
                ),
            ),
            components=components,
            diagnostics=diagnostics,
            agent_tasks=self.agent_tasks,
            claims=claims,
            provenance=provenance,
            component_total=0 if report is None else len(report.components),
            diagnostic_total=(
                0 if report is None else len(report.diagnostics) + len(report.unsupported_zones)
            ),
            claim_total=len(self.harness_claims),
            conflict_total=len(self.disputed_claim_ids),
            error_code=self.error_code,
            error_message=self.error_message,
        )


class RepositoryAnalysisStore(Protocol):
    def create_repository_analysis(self, analysis: RepositoryAnalysis) -> RepositoryAnalysis: ...

    def update_repository_analysis(self, analysis: RepositoryAnalysis) -> RepositoryAnalysis: ...

    def claim_repository_analysis(self, analysis_id: UUID) -> RepositoryAnalysis | None: ...

    def get_repository_analysis(self, analysis_id: UUID) -> RepositoryAnalysis: ...

    def list_repository_analyses(
        self, *, limit: int = 20, offset: int = 0
    ) -> list[RepositoryAnalysis]: ...

    def count_repository_analyses(self) -> int: ...


class SnapshotFetcher(Protocol):
    def fetch(self, repository_url: str, commit: str, snapshot_key: str) -> SnapshotResult: ...


class ClaimProposer(Protocol):
    """Optional semantic proposer; see :mod:`logiclab.proposals`."""

    def propose(
        self,
        role: AgentRole,
        index: EvidenceIndex,
        report: RepositoryIntelligenceReport,
    ) -> ProposalOutcome: ...


class RepositoryAnalysisManager:
    def __init__(
        self,
        storage: RepositoryAnalysisStore,
        fetcher: SnapshotFetcher,
        redactor: Redactor | None = None,
        proposer: ClaimProposer | None = None,
    ) -> None:
        self.storage = storage
        self.fetcher = fetcher
        self.redactor = redactor or Redactor()
        self.proposer = proposer

    def create(self, request: RepositoryAnalysisRequest) -> RepositoryAnalysis:
        analysis = self.enqueue(request)
        return self.process(analysis.id)

    def enqueue(self, request: RepositoryAnalysisRequest) -> RepositoryAnalysis:
        name = request.name or PurePosixPath(request.repository_url).name.removesuffix(".git")
        return self.storage.create_repository_analysis(
            RepositoryAnalysis(
                name=name,
                repository_url=request.repository_url,
                commit=request.commit,
            )
        )

    def process(self, analysis_id: UUID) -> RepositoryAnalysis:
        analysis = self.storage.get_repository_analysis(analysis_id)
        if analysis.status in {
            RepositoryAnalysisStatus.READY,
            RepositoryAnalysisStatus.NEEDS_REVIEW,
            RepositoryAnalysisStatus.FAILED,
        }:
            return analysis
        if analysis.status is not RepositoryAnalysisStatus.QUEUED:
            return analysis
        claimed = self.storage.claim_repository_analysis(analysis_id)
        if claimed is None:
            return self.storage.get_repository_analysis(analysis_id)
        analysis = claimed
        try:
            snapshot = self.fetcher.fetch(
                analysis.repository_url,
                analysis.commit,
                str(analysis.id),
            )
            analysis = self._update(
                analysis,
                status=RepositoryAnalysisStatus.ANALYZING,
                snapshot_digest=snapshot.tree_digest,
            )
            report = _merge_snapshot_diagnostics(analyze_repository(snapshot.root), snapshot)
            outcome = _run_agent_team(analysis, snapshot, report, proposer=self.proposer)
            report = _merge_uncitable_evidence(report, outcome)
            terminal = (
                RepositoryAnalysisStatus.READY
                if report.status is AnalysisStatus.COMPLETE
                else RepositoryAnalysisStatus.NEEDS_REVIEW
            )
            return self._update(
                analysis,
                status=terminal,
                report=report,
                agent_tasks=outcome.tasks,
                harness_claims=outcome.claims,
                disputed_claim_ids=outcome.disputed_claim_ids,
            )
        except SnapshotPolicyError as exc:
            return self._fail(analysis, "SNAPSHOT_POLICY_DENIED", exc)
        except Exception as exc:  # keep one repository failure outside the control plane
            return self._fail(analysis, "STATIC_ANALYSIS_FAILED", exc)

    def get(self, analysis_id: UUID) -> RepositoryAnalysis:
        return self.storage.get_repository_analysis(analysis_id)

    def list(self, *, limit: int = 20, offset: int = 0) -> list[RepositoryAnalysis]:
        return self.storage.list_repository_analyses(limit=limit, offset=offset)

    def count(self) -> int:
        return self.storage.count_repository_analyses()

    def _update(self, analysis: RepositoryAnalysis, **values: object) -> RepositoryAnalysis:
        updated = analysis.model_copy(update={**values, "updated_at": datetime.now(timezone.utc)})
        return self.storage.update_repository_analysis(updated)

    def _fail(
        self, analysis: RepositoryAnalysis, code: str, error: Exception
    ) -> RepositoryAnalysis:
        safe = str(self.redactor.redact(str(error)))[:500]
        return self._update(
            analysis,
            status=RepositoryAnalysisStatus.FAILED,
            error_code=code,
            error_message=safe or "Repository analysis failed",
        )


def default_repository_analysis_manager(
    storage: RepositoryAnalysisStore, workspace_root: str | Path
) -> RepositoryAnalysisManager:
    return RepositoryAnalysisManager(
        storage=storage,
        fetcher=GitSnapshotFetcher(Path(str(workspace_root)) / "repository-snapshots"),
    )


def _merge_snapshot_diagnostics(
    report: RepositoryIntelligenceReport,
    snapshot: SnapshotResult,
) -> RepositoryIntelligenceReport:
    """Make pre-analysis snapshot omissions visible in coverage and status."""

    diagnostics = list(report.diagnostics)
    unsupported = list(report.unsupported_zones)
    omission_count = 0
    for index, item in enumerate(snapshot.diagnostics, start=1):
        path = item.path or f"[snapshot-entry-{index}]"
        code = f"snapshot.{item.code.lower()}"
        diagnostics.append(
            IntelligenceDiagnostic(
                code=code,
                message=item.detail,
                severity=DiagnosticSeverity.WARNING,
                path=item.path,
                details={"snapshot_code": item.code},
            )
        )
        if not item.code.endswith("_SKIPPED"):
            continue
        omission_count += 1
        unsupported.append(UnsupportedZone(path=path, reason=item.detail))

    if not omission_count:
        return report.model_copy(
            update={
                "diagnostics": sorted(
                    diagnostics,
                    key=lambda item: (item.path or "", item.code, item.message),
                )
            }
        )

    coverage_denominator = report.coverage.source_files + omission_count
    coverage = report.coverage.model_copy(
        update={
            "inventory_files": report.coverage.inventory_files + omission_count,
            "unsupported_files": report.coverage.unsupported_files + omission_count,
            "snapshot_omissions": report.coverage.snapshot_omissions + omission_count,
            "analysis_percent": round(
                100.0 * report.coverage.analyzed_source_files / coverage_denominator,
                2,
            ),
        }
    )
    return report.model_copy(
        update={
            "status": AnalysisStatus.PARTIAL,
            "coverage": coverage,
            "diagnostics": sorted(
                diagnostics,
                key=lambda item: (item.path or "", item.code, item.message),
            ),
            "unsupported_zones": sorted(
                unsupported,
                key=lambda item: (item.path, item.reason),
            ),
        }
    )


def _task(
    analysis: RepositoryAnalysis,
    task_id: str,
    kind: TaskKind,
    role: AgentRole,
    modules: tuple[str, ...],
    depends_on: tuple[str, ...] = (),
) -> TaskSpec:
    return TaskSpec(
        task_id=task_id,
        engagement_id=str(analysis.id),
        snapshot_id=analysis.snapshot_digest or str(analysis.id),
        kind=kind,
        role=role,
        scope=TaskScope(module_ids=modules),
        depends_on=depends_on,
        dependency_policy=DependencyPolicy.TOLERANT,
    )


def _merge_uncitable_evidence(
    report: RepositoryIntelligenceReport,
    outcome: "AgentTeamOutcome",
) -> RepositoryIntelligenceReport:
    """Surface evidence a role wanted to cite but the snapshot did not carry.

    Dropping an uncitable claim silently would inflate apparent completeness.
    Each miss becomes a diagnostic and forces the report to PARTIAL, so the
    omission reaches the operator instead of disappearing.
    """

    if not outcome.missing_paths and not outcome.stop_reasons and not outcome.proposal_notes:
        return report

    diagnostics = list(report.diagnostics)
    for note in outcome.proposal_notes:
        diagnostics.append(
            IntelligenceDiagnostic(
                code="harness.proposal_rejected",
                message=note,
                severity=DiagnosticSeverity.WARNING,
            )
        )
    for path in outcome.missing_paths:
        diagnostics.append(
            IntelligenceDiagnostic(
                code="harness.evidence_uncitable",
                message="Role evidence was dropped because the snapshot carries no digest",
                severity=DiagnosticSeverity.WARNING,
                path=path,
            )
        )
    for reason in outcome.stop_reasons:
        diagnostics.append(
            IntelligenceDiagnostic(
                code="harness.budget_stop",
                message=f"Role budget gate reported: {reason}",
                severity=DiagnosticSeverity.WARNING,
                details={"stop_reason": reason},
            )
        )
    return report.model_copy(
        update={
            "status": AnalysisStatus.PARTIAL,
            "diagnostics": sorted(
                diagnostics,
                key=lambda item: (item.path or "", item.code, item.message),
            ),
        }
    )


@dataclass(frozen=True)
class AgentTeamOutcome:
    """Everything the role graph produced, including what it could not cite."""

    tasks: list[AgentTaskView]
    claims: list[HarnessClaim]
    disputed_claim_ids: list[str]
    missing_paths: tuple[str, ...]
    stop_reasons: tuple[str, ...]
    proposal_notes: tuple[str, ...] = ()


#: Roles whose output a semantic model may extend. Structural roles are
#: excluded: their claims are parsed facts and are not open to interpretation.
PROPOSING_ROLES = frozenset({AgentRole.SECURITY_DOMAIN_MAPPER, AgentRole.TWIN_SYNTHESIZER})


def _remaining_disputes(
    board: Blackboard,
    view: BlackboardView,
    adjudication: Adjudication,
) -> list[str]:
    """Which claims are still genuinely disputed once the skeptic has ruled.

    ``Blackboard.reduce`` marks every member of a conflict group as disputed,
    the eventual winner included. Clearing both the rejected losers and the
    accepted winner is what makes adjudication change the reported state; a
    claim that is disputed on its own merits (``EpistemicStatus.DISPUTED``) is
    deliberately never cleared, because no conflict resolution speaks to that.
    """

    rejected = set(adjudication.rejected_claim_ids)
    explicitly_disputed = {
        item.claim_id for item in board.claims if item.epistemic_status is EpistemicStatus.DISPUTED
    }
    settled = {
        item for item in adjudication.accepted_claim_ids if item not in explicitly_disputed
    }
    return sorted(
        item
        for item in view.disputed_claim_ids
        if item not in rejected and item not in settled
    )


def _extend_with_proposals(
    proposer: "ClaimProposer",
    role: AgentRole,
    result: AgentResult,
    index: EvidenceIndex,
    report: RepositoryIntelligenceReport,
    dag: TaskDAG,
) -> tuple[AgentResult, list[str]]:
    """Merge admitted semantic proposals into a deterministic role result.

    A proposer failure degrades the role to PARTIAL and is reported; it never
    fails the analysis, and it never turns an abstention into a success.
    """

    try:
        outcome = proposer.propose(role, index, report)
    except Exception as exc:  # an optional model must not break static analysis
        note = f"{role.value}: semantic proposal unavailable ({type(exc).__name__})"
        if result.status is AgentResultStatus.COMPLETE:
            return (
                result.model_copy(
                    update={
                        "status": AgentResultStatus.PARTIAL,
                        "missing_information": ("semantic proposal was unavailable",),
                    }
                ),
                [note],
            )
        return result, [note]

    notes = [f"{role.value}: rejected proposal — {item}" for item in outcome.rejected]
    dag.record_usage(result.task_id, outcome.usage)
    if not outcome.claims:
        return result, notes

    # Inferred claims can extend a result but never upgrade it: a role that
    # abstained for want of evidence has still not observed anything, and a
    # model guess is not the evidence it was missing.
    if result.status is AgentResultStatus.ABSTAIN:
        notes.append(
            f"{role.value}: discarded {len(outcome.claims)} inferred claims "
            "because the role abstained on evidence"
        )
        return result, notes

    merged = tuple(result.claims) + outcome.claims
    missing = (
        "includes inferred claims that are not reproducible across runs",
        *result.missing_information,
    )
    return (
        AgentResult(
            task_id=result.task_id,
            role=result.role,
            status=AgentResultStatus.PARTIAL,
            summary=f"{result.summary} (+{len(outcome.claims)} inferred)",
            claims=merged,
            missing_information=missing,
        ),
        notes,
    )


def _run_agent_team(
    analysis: RepositoryAnalysis,
    snapshot: SnapshotResult,
    report: RepositoryIntelligenceReport,
    proposer: "ClaimProposer | None" = None,
) -> AgentTeamOutcome:
    snapshot_id = snapshot.tree_digest
    index = EvidenceIndex(
        snapshot_id=snapshot_id,
        repository_url=analysis.repository_url,
        commit=analysis.commit,
        run_id=str(analysis.id),
        blob_sha256=snapshot.blob_sha256,
    )
    modules = tuple(item.id for item in report.components)
    specs = (
        _task(analysis, "director", TaskKind.DIRECT_WORKFLOW, AgentRole.RESEARCH_DIRECTOR, modules),
        _task(
            analysis,
            "survey",
            TaskKind.INVENTORY_REPOSITORY,
            AgentRole.REPO_SURVEYOR,
            modules,
            ("director",),
        ),
        _task(
            analysis,
            "architecture",
            TaskKind.MAP_ARCHITECTURE,
            AgentRole.ARCHITECTURE_MAPPER,
            modules,
            ("survey",),
        ),
        _task(
            analysis,
            "build-runtime",
            TaskKind.MAP_BUILD_RUNTIME,
            AgentRole.BUILD_RUNTIME_SCOUT,
            modules,
            ("survey",),
        ),
        _task(
            analysis,
            "test-history",
            TaskKind.MAP_TEST_HISTORY,
            AgentRole.TEST_HISTORY_ANALYST,
            modules,
            ("survey",),
        ),
        _task(
            analysis,
            "security-domain",
            TaskKind.MAP_SECURITY_DOMAIN,
            AgentRole.SECURITY_DOMAIN_MAPPER,
            modules,
            ("architecture",),
        ),
        _task(
            analysis,
            "twin",
            TaskKind.SYNTHESIZE_TWIN,
            AgentRole.TWIN_SYNTHESIZER,
            modules,
            ("architecture", "build-runtime", "security-domain", "test-history"),
        ),
        _task(
            analysis,
            "skeptic",
            TaskKind.VALIDATE_TWIN,
            AgentRole.INDEPENDENT_SKEPTIC,
            modules,
            ("twin",),
        ),
    )
    dag = TaskDAG(specs)
    summaries: dict[str, str] = {}
    board = Blackboard()
    adjudication: Adjudication | None = None
    stop_reasons: set[str] = set()
    proposal_notes: list[str] = []

    while (spec := dag.claim_next()) is not None:
        if spec.role is AgentRole.INDEPENDENT_SKEPTIC:
            # The skeptic can only adjudicate once every producing role has
            # appended its claims, which the DAG guarantees by dependency order.
            adjudication = adjudicate(board)
            result = skeptic_result(spec.task_id, adjudication)
        else:
            result = execute_role(spec.role, spec.task_id, index, report)
            if proposer is not None and spec.role in PROPOSING_ROLES:
                result, notes = _extend_with_proposals(
                    proposer, spec.role, result, index, report, dag
                )
                proposal_notes.extend(notes)
            if result.claims:
                board.append_claim_batch(result.claims)

        summaries[spec.task_id] = result.summary
        dag.complete_task(spec.task_id, result)

        # The budget gates are advisory for a static run: nothing here consumes
        # tokens or wall time. Recording the assessment still makes an exhausted
        # budget visible instead of silently ignored.
        assessment = dag.assess_stop(spec.task_id)
        if assessment.stop:
            stop_reasons.update(reason.value for reason in assessment.reasons)

    if adjudication is None:
        adjudication = adjudicate(board)

    status_map = {
        TaskStatus.SUCCEEDED: "complete",
        TaskStatus.PARTIAL: "partial",
        TaskStatus.ABSTAINED: "abstained",
        TaskStatus.BLOCKED: "blocked",
        TaskStatus.FAILED: "failed",
        TaskStatus.RETRYABLE: "retryable",
        TaskStatus.CANCELLED: "cancelled",
        TaskStatus.PENDING: "pending",
        TaskStatus.READY: "pending",
        TaskStatus.RUNNING: "running",
    }
    tasks = [
        AgentTaskView(
            id=spec.task_id,
            title=spec.kind.value.replace("_", " ").title(),
            agent=spec.role.value,
            status=status_map[dag.status(spec.task_id)],
            depends_on=list(spec.depends_on),
            output=summaries.get(spec.task_id),
        )
        for spec in specs
    ]

    view = board.reduce()
    rejected = set(adjudication.rejected_claim_ids)
    disputed = _remaining_disputes(board, view, adjudication)
    active = [item for item in board.claims if item.claim_id not in rejected]
    active.sort(key=lambda item: item.claim_id)
    return AgentTeamOutcome(
        tasks=tasks,
        claims=active,
        disputed_claim_ids=sorted(disputed),
        missing_paths=tuple(sorted(index.missing_paths)),
        stop_reasons=tuple(sorted(stop_reasons)),
        proposal_notes=tuple(proposal_notes),
    )
