"""Deterministic role executors that turn analysis evidence into cited claims.

``harness.py`` deliberately owns no I/O and no evidence: it defines the task
contract, the scheduler, and the gates. This module is the missing half — the
component that actually *does* a task. Each role projects the slice of the
repository report it owns into :class:`Claim` objects whose provenance points at
a real blob digest and line span.

Two rules hold everywhere in this module:

1. A claim is only ever emitted when the cited path has a snapshot blob digest.
   Evidence that was skipped (binary, oversized, sensitive, symlink) can never be
   fabricated into a citation; the role loses coverage instead.
2. A role with no usable evidence abstains with a typed reason rather than
   reporting success. Abstention is a real outcome, not a failure.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from logiclab.harness import (
    AbstainReason,
    AgentResult,
    AgentResultStatus,
    AgentRole,
    Blackboard,
    Claim,
    ClaimConflict,
    ClaimKind,
    ClaimProvenance,
    ClaimScope,
    ConflictStatus,
    EpistemicStatus,
    SourceRef,
)
from logiclab.intelligence import (
    RepositoryIntelligenceReport,
    RuntimeLevel,
    UnderstandingLevel,
)

TOOL_NAME = "deterministic_role_executor"
TOOL_VERSION = "1.0"

_ENDPOINT_PREFIXES = ("GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ")
_TEST_DIR_NAMES = frozenset({"test", "tests", "spec", "specs", "__tests__", "testing"})
_TEST_FILE_SUFFIXES = ("_test.py", "_test.go", ".test.ts", ".test.js", ".spec.ts", ".spec.js")

# Higher wins when the skeptic adjudicates a conflict.
_EPISTEMIC_RANK: dict[EpistemicStatus, int] = {
    EpistemicStatus.DISPUTED: 0,
    EpistemicStatus.INFERRED: 1,
    EpistemicStatus.DERIVED: 2,
    EpistemicStatus.OBSERVED: 3,
}


def _digest(material: object) -> str:
    payload = json.dumps(material, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def is_test_path(path: str) -> bool:
    """Conservative, convention-based test detection over a POSIX repository path."""

    pure = PurePosixPath(path)
    if any(part.lower() in _TEST_DIR_NAMES for part in pure.parts[:-1]):
        return True
    name = pure.name.lower()
    return name.startswith("test_") or name.endswith(_TEST_FILE_SUFFIXES)


@dataclass(frozen=True)
class EvidenceIndex:
    """Snapshot-bound citation factory.

    Every :class:`SourceRef` this produces is backed by a blob digest that was
    actually materialized, which is what makes ``Blackboard._validate_claim``
    able to reject invented evidence downstream.
    """

    snapshot_id: str
    repository_url: str
    commit: str
    run_id: str
    blob_sha256: Mapping[str, str]
    #: Paths a role wanted to cite but could not, because the snapshot omitted
    #: them. Recorded so the omission becomes a diagnostic instead of silence.
    missing_paths: set[str] = field(default_factory=set)

    def has(self, path: str) -> bool:
        return path in self.blob_sha256

    def source_ref(
        self,
        ref_id: str,
        path: str,
        start_line: int | None = None,
        end_line: int | None = None,
    ) -> SourceRef | None:
        """Return a citation, or ``None`` when the path carries no digest."""

        sha256 = self.blob_sha256.get(path)
        if sha256 is None:
            self.missing_paths.add(path)
            return None
        span_start = start_line
        span_end = end_line if end_line is not None else start_line
        return SourceRef(
            ref_id=ref_id[:256],
            artifact_id=self.snapshot_id[:256],
            sha256=sha256,
            path=path,
            start_line=span_start,
            end_line=span_end,
        )

    def build_claim(
        self,
        *,
        role: AgentRole,
        kind: ClaimKind,
        subject_ref: str,
        predicate: str,
        value: str,
        refs: Sequence[SourceRef],
        scope: ClaimScope | None = None,
        epistemic_status: EpistemicStatus = EpistemicStatus.DERIVED,
    ) -> Claim | None:
        if not refs:
            return None
        unique: dict[str, SourceRef] = {}
        for ref in refs:
            unique.setdefault(ref.ref_id, ref)
        source_refs = tuple(unique.values())
        claim_scope = scope or ClaimScope()
        claim_id = "{}:{}".format(
            role.value[:24],
            _digest(
                {
                    "snapshot": self.snapshot_id,
                    "kind": kind.value,
                    "subject": subject_ref,
                    "predicate": predicate,
                    "value": value,
                    "scope": claim_scope.model_dump(mode="json"),
                }
            ),
        )
        return Claim(
            claim_id=claim_id[:128],
            snapshot_id=self.snapshot_id,
            kind=kind,
            subject_ref=subject_ref[:512],
            predicate=predicate[:256],
            value=value,
            epistemic_status=epistemic_status,
            scope=claim_scope,
            support_refs=tuple(ref.ref_id for ref in source_refs),
            provenance=ClaimProvenance(
                snapshot_id=self.snapshot_id,
                repository_url=self.repository_url,
                commit=self.commit,
                producer_role=role,
                producer_run_id=self.run_id,
                tool_name=TOOL_NAME,
                tool_version=TOOL_VERSION,
                source_refs=source_refs,
            ),
        )


def _report_claim_refs(
    index: EvidenceIndex, item: object
) -> tuple[SourceRef, ...]:
    refs: list[SourceRef] = []
    for position, span in enumerate(getattr(item, "evidence", ()), start=1):
        ref = index.source_ref(
            f"{getattr(item, 'id', 'claim')}:{position}",
            span.path,
            span.start_line,
            span.end_line,
        )
        if ref is not None:
            refs.append(ref)
    return tuple(refs)


def _survey_claims(index: EvidenceIndex, report: RepositoryIntelligenceReport) -> list[Claim]:
    """Component boundaries, cited by the manifest that proves the component."""

    claims: list[Claim] = []
    for component in report.components:
        refs = [
            ref
            for position, manifest in enumerate(component.manifests, start=1)
            if (ref := index.source_ref(f"{component.id}:manifest:{position}", manifest.path))
        ]
        if not refs:
            continue
        for ecosystem in sorted(set(component.ecosystems)):
            claim = index.build_claim(
                role=AgentRole.REPO_SURVEYOR,
                kind=ClaimKind.MODULE,
                subject_ref=component.id,
                predicate="declares_ecosystem",
                value=ecosystem,
                refs=refs,
                scope=ClaimScope(module_id=component.id, config_profile=ecosystem),
            )
            if claim is not None:
                claims.append(claim)
    return claims


def _architecture_claims(index: EvidenceIndex, report: RepositoryIntelligenceReport) -> list[Claim]:
    """Symbol-level IR relations, excluding the endpoints the security role owns."""

    claims: list[Claim] = []
    for item in report.claims:
        if item.object.startswith(_ENDPOINT_PREFIXES):
            continue
        refs = _report_claim_refs(index, item)
        claim = index.build_claim(
            role=AgentRole.ARCHITECTURE_MAPPER,
            kind=ClaimKind.SYMBOL,
            subject_ref=item.subject,
            predicate=item.predicate,
            value=item.object,
            refs=refs,
            scope=ClaimScope(
                module_id=item.component_id,
                # ``declares`` is set-valued: without a per-edge identity two
                # sibling declarations would look like conflicting scalars.
                operation_id=item.id if item.predicate == "declares" else None,
            ),
        )
        if claim is not None:
            claims.append(claim)
    return claims


def _security_claims(index: EvidenceIndex, report: RepositoryIntelligenceReport) -> list[Claim]:
    """Externally reachable entry points — a blocking claim kind."""

    claims: list[Claim] = []
    for item in report.claims:
        if not item.object.startswith(_ENDPOINT_PREFIXES):
            continue
        refs = _report_claim_refs(index, item)
        claim = index.build_claim(
            role=AgentRole.SECURITY_DOMAIN_MAPPER,
            kind=ClaimKind.ENTRY_POINT,
            subject_ref=item.subject,
            predicate=item.predicate,
            value=item.object,
            refs=refs,
            scope=ClaimScope(module_id=item.component_id, operation_id=item.id),
        )
        if claim is not None:
            claims.append(claim)
    return claims


def _build_runtime_claims(
    index: EvidenceIndex, report: RepositoryIntelligenceReport
) -> list[Claim]:
    """Declared build systems. Runtime stays R0/R1: nothing here is executed."""

    claims: list[Claim] = []
    for component in report.components:
        for position, manifest in enumerate(component.manifests, start=1):
            ref = index.source_ref(f"{component.id}:build:{position}", manifest.path)
            if ref is None:
                continue
            claim = index.build_claim(
                role=AgentRole.BUILD_RUNTIME_SCOUT,
                kind=ClaimKind.RUNTIME,
                subject_ref=manifest.path,
                predicate="declares_build_system",
                value=manifest.build_system,
                refs=(ref,),
                scope=ClaimScope(module_id=component.id, operation_id=manifest.path),
            )
            if claim is not None:
                claims.append(claim)
    return claims


def _test_claims(index: EvidenceIndex, report: RepositoryIntelligenceReport) -> list[Claim]:
    """Test-shaped paths found by convention over the materialized inventory."""

    claims: list[Claim] = []
    for entry in report.inventory.entries:
        if not is_test_path(entry.path):
            continue
        ref = index.source_ref(f"test:{entry.path}", entry.path)
        if ref is None:
            continue
        claim = index.build_claim(
            role=AgentRole.TEST_HISTORY_ANALYST,
            kind=ClaimKind.TEST_INTENT,
            subject_ref=entry.path,
            predicate="is_test_path",
            value=entry.language or "unknown",
            refs=(ref,),
            scope=ClaimScope(operation_id=entry.path),
            # Convention, not proof: the file was never parsed for assertions.
            epistemic_status=EpistemicStatus.INFERRED,
        )
        if claim is not None:
            claims.append(claim)
    return claims


def _twin_claims(index: EvidenceIndex, report: RepositoryIntelligenceReport) -> list[Claim]:
    """Per-component capability summary, cited by the component's own manifests."""

    claims: list[Claim] = []
    for component in report.components:
        refs = [
            ref
            for position, manifest in enumerate(component.manifests, start=1)
            if (ref := index.source_ref(f"{component.id}:twin:{position}", manifest.path))
        ]
        if not refs:
            continue
        claim = index.build_claim(
            role=AgentRole.TWIN_SYNTHESIZER,
            kind=ClaimKind.CAPABILITY,
            subject_ref=component.id,
            predicate="static_understanding_level",
            value=component.understanding_level.value,
            refs=refs,
            scope=ClaimScope(module_id=component.id),
        )
        if claim is not None:
            claims.append(claim)
    return claims


ROLE_PRODUCERS: dict[
    AgentRole, Callable[[EvidenceIndex, RepositoryIntelligenceReport], list[Claim]]
] = {
    AgentRole.REPO_SURVEYOR: _survey_claims,
    AgentRole.ARCHITECTURE_MAPPER: _architecture_claims,
    AgentRole.SECURITY_DOMAIN_MAPPER: _security_claims,
    AgentRole.BUILD_RUNTIME_SCOUT: _build_runtime_claims,
    AgentRole.TEST_HISTORY_ANALYST: _test_claims,
    AgentRole.TWIN_SYNTHESIZER: _twin_claims,
}

_ROLE_SUMMARY: dict[AgentRole, str] = {
    AgentRole.RESEARCH_DIRECTOR: "Scheduled the typed task graph and enforced role gates",
    AgentRole.REPO_SURVEYOR: "Mapped component boundaries from manifest evidence",
    AgentRole.ARCHITECTURE_MAPPER: "Projected symbols and imports into cited IR claims",
    AgentRole.SECURITY_DOMAIN_MAPPER: "Mapped externally reachable entry points",
    AgentRole.BUILD_RUNTIME_SCOUT: "Mapped declared build systems; nothing was executed",
    AgentRole.TEST_HISTORY_ANALYST: "Indexed test-shaped paths by convention",
    AgentRole.TWIN_SYNTHESIZER: "Reduced accepted claims into a per-component twin",
    AgentRole.INDEPENDENT_SKEPTIC: "Adjudicated claim conflicts from cited evidence",
}

_ROLE_MISSING: dict[AgentRole, str] = {
    AgentRole.REPO_SURVEYOR: "no component carries a materialized manifest",
    AgentRole.ARCHITECTURE_MAPPER: "no symbol evidence survived snapshot materialization",
    AgentRole.SECURITY_DOMAIN_MAPPER: "no entry point was discovered in analyzable source",
    AgentRole.BUILD_RUNTIME_SCOUT: "no build manifest was materialized",
    AgentRole.TEST_HISTORY_ANALYST: "no test-shaped path was materialized",
    AgentRole.TWIN_SYNTHESIZER: "no component had enough evidence to synthesize",
}


def _partial_reason(role: AgentRole, report: RepositoryIntelligenceReport) -> str | None:
    """Capability ceilings that make an otherwise successful role incomplete."""

    if role is AgentRole.BUILD_RUNTIME_SCOUT and report.runtime_level < RuntimeLevel.R2:
        return "runtime execution is policy-locked; build claims are declaration-only"
    if role is AgentRole.SECURITY_DOMAIN_MAPPER and (
        report.understanding_level < UnderstandingLevel.U3
    ):
        return "framework adapters are required for full security/domain mapping"
    if role is AgentRole.TWIN_SYNTHESIZER and report.understanding_level < UnderstandingLevel.U4:
        return "twin is static-only until semantic verification is available"
    return None


def execute_role(
    role: AgentRole,
    task_id: str,
    index: EvidenceIndex,
    report: RepositoryIntelligenceReport,
) -> AgentResult:
    """Run one role over the report and return its real, cited output."""

    summary = _ROLE_SUMMARY[role]
    if role is AgentRole.RESEARCH_DIRECTOR:
        # The director owns scheduling only; it inspects no source and so has
        # nothing it could legitimately cite.
        return AgentResult(
            task_id=task_id,
            role=role,
            status=AgentResultStatus.COMPLETE,
            summary=summary,
        )

    if role is AgentRole.INDEPENDENT_SKEPTIC:
        # Adjudication needs the assembled board; it is handled by the caller
        # through ``adjudicate`` and reported via ``skeptic_result``.
        return AgentResult(
            task_id=task_id,
            role=role,
            status=AgentResultStatus.COMPLETE,
            summary=summary,
        )

    producer = ROLE_PRODUCERS[role]
    # Two IR facts can normalize to the same assertion (for example one source
    # line matched by two endpoint patterns). Identical content is one claim,
    # so collapse it here rather than appending a duplicate to the board.
    deduplicated: dict[str, Claim] = {}
    for claim in producer(index, report):
        deduplicated.setdefault(claim.claim_id, claim)
    claims = list(deduplicated.values())
    if not claims:
        return AgentResult(
            task_id=task_id,
            role=role,
            status=AgentResultStatus.ABSTAIN,
            summary=f"{summary} — abstained: {_ROLE_MISSING[role]}",
            abstain_reason=AbstainReason.INSUFFICIENT_EVIDENCE,
        )

    partial = _partial_reason(role, report)
    if partial is not None:
        return AgentResult(
            task_id=task_id,
            role=role,
            status=AgentResultStatus.PARTIAL,
            summary=summary,
            claims=tuple(claims),
            missing_information=(partial,),
        )
    return AgentResult(
        task_id=task_id,
        role=role,
        status=AgentResultStatus.COMPLETE,
        summary=summary,
        claims=tuple(claims),
    )


@dataclass(frozen=True)
class Adjudication:
    """Outcome of the skeptic's deterministic conflict resolution."""

    conflicts: tuple[ClaimConflict, ...]
    accepted_claim_ids: tuple[str, ...]
    rejected_claim_ids: tuple[str, ...]
    unresolved_conflict_ids: tuple[str, ...]

    @property
    def resolved_count(self) -> int:
        return sum(1 for item in self.conflicts if item.status is ConflictStatus.RESOLVED)


def adjudicate(board: Blackboard) -> Adjudication:
    """Resolve value conflicts by evidence strength, never by guessing.

    Precedence is strictly: epistemic rank, then citation count. When both tie
    the conflict stays ``UNRESOLVED`` — a deliberate refusal to break a tie that
    the evidence does not break, rather than an arbitrary winner.
    """

    view = board.reduce()
    claims_by_id = {item.claim_id: item for item in board.claims}
    resolved: list[ClaimConflict] = []
    accepted: list[str] = []
    rejected: list[str] = []
    unresolved: list[str] = []

    for conflict in view.conflicts:
        candidates = [
            claims_by_id[claim_id]
            for claim_id in conflict.claim_ids
            if claim_id in claims_by_id
        ]
        if not candidates:
            unresolved.append(conflict.conflict_id)
            resolved.append(conflict)
            continue

        def strength(item: Claim) -> tuple[int, int]:
            return (_EPISTEMIC_RANK[item.epistemic_status], len(item.support_refs))

        ranked = sorted(candidates, key=strength, reverse=True)
        best = strength(ranked[0])
        tied = [item for item in ranked if strength(item) == best]
        if len(tied) != 1:
            unresolved.append(conflict.conflict_id)
            resolved.append(conflict)
            continue

        winner = tied[0]
        accepted.append(winner.claim_id)
        rejected.extend(
            item.claim_id for item in candidates if item.claim_id != winner.claim_id
        )
        resolved.append(conflict.model_copy(update={"status": ConflictStatus.RESOLVED}))

    return Adjudication(
        conflicts=tuple(resolved),
        accepted_claim_ids=tuple(sorted(set(accepted))),
        rejected_claim_ids=tuple(sorted(set(rejected))),
        unresolved_conflict_ids=tuple(sorted(set(unresolved))),
    )


def skeptic_result(task_id: str, adjudication: Adjudication) -> AgentResult:
    """Report adjudication as a typed result, abstaining when ties remain."""

    total = len(adjudication.conflicts)
    summary = (
        f"Adjudicated {adjudication.resolved_count}/{total} claim conflicts from cited evidence"
        if total
        else "No claim conflicts were detected in the accepted evidence"
    )
    if adjudication.unresolved_conflict_ids:
        return AgentResult(
            task_id=task_id,
            role=AgentRole.INDEPENDENT_SKEPTIC,
            status=AgentResultStatus.PARTIAL,
            summary=summary,
            conflict_ids=adjudication.unresolved_conflict_ids,
            missing_information=(
                "evidence strength ties; conflicting claims remain disputed",
            ),
        )
    return AgentResult(
        task_id=task_id,
        role=AgentRole.INDEPENDENT_SKEPTIC,
        status=AgentResultStatus.COMPLETE,
        summary=summary,
    )


__all__ = [
    "Adjudication",
    "EvidenceIndex",
    "ROLE_PRODUCERS",
    "TOOL_NAME",
    "TOOL_VERSION",
    "adjudicate",
    "execute_role",
    "is_test_path",
    "skeptic_result",
]
