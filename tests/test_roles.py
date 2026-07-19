import pytest

from logiclab.harness import (
    AgentResultStatus,
    AgentRole,
    Blackboard,
    ClaimKind,
    ClaimScope,
    EpistemicStatus,
)
from logiclab.intelligence import (
    AnalysisStatus,
    BuildManifest,
    Claim as IRClaim,
    Component,
    Coverage,
    EvidenceSpan,
    InventoryEntry,
    InventoryEntryKind,
    RepositoryInventory,
    RepositoryIntelligenceReport,
    RuntimeLevel,
    UnderstandingLevel,
)
from logiclab.roles import (
    ROLE_PRODUCERS,
    EvidenceIndex,
    adjudicate,
    execute_role,
    is_test_path,
    skeptic_result,
)

MANIFEST_PATH = "pyproject.toml"
SOURCE_PATH = "src/app.py"
TEST_PATH = "tests/test_app.py"

BLOBS = {
    MANIFEST_PATH: "a" * 64,
    SOURCE_PATH: "b" * 64,
    TEST_PATH: "c" * 64,
}


def make_index(blob_sha256: dict[str, str] | None = None) -> EvidenceIndex:
    return EvidenceIndex(
        snapshot_id="sha256:" + "d" * 64,
        repository_url="https://github.com/acme/repo.git",
        commit="e" * 40,
        run_id="run-1",
        blob_sha256=BLOBS if blob_sha256 is None else blob_sha256,
    )


def make_report(
    *,
    with_component: bool = True,
    with_symbol: bool = True,
    with_endpoint: bool = False,
    with_test: bool = True,
    understanding: UnderstandingLevel = UnderstandingLevel.U2,
    duplicate_symbol: bool = False,
) -> RepositoryIntelligenceReport:
    components = []
    if with_component:
        components.append(
            Component(
                id="component-1",
                name="app",
                root_path=".",
                ecosystems=["python"],
                languages=["python"],
                manifests=[
                    BuildManifest(path=MANIFEST_PATH, ecosystem="python", build_system="hatchling")
                ],
                build_systems=["hatchling"],
                understanding_level=UnderstandingLevel.U2,
            )
        )
    claims = []
    if with_symbol:
        claims.append(
            IRClaim(
                id="ir-1",
                subject="src/app.py",
                predicate="declares",
                object="hello",
                component_id="component-1",
                evidence=[EvidenceSpan(path=SOURCE_PATH, start_line=1, end_line=2)],
            )
        )
    if with_endpoint:
        claims.append(
            IRClaim(
                id="ir-2",
                subject="src/app.py",
                predicate="exposes",
                object="GET /health",
                component_id="component-1",
                evidence=[EvidenceSpan(path=SOURCE_PATH, start_line=5, end_line=6)],
            )
        )
    if duplicate_symbol:
        # One source line matched by two extraction patterns: distinct IR ids,
        # identical normalized assertion. ``imports`` carries no operation_id,
        # so both normalize to exactly the same claim identity.
        claims.extend(
            IRClaim(
                id=f"ir-dup-{index}",
                subject="src/app.py",
                predicate="imports",
                object="os",
                component_id="component-1",
                evidence=[EvidenceSpan(path=SOURCE_PATH, start_line=3, end_line=3)],
            )
            for index in range(2)
        )
    entries = [
        InventoryEntry(path=MANIFEST_PATH, kind=InventoryEntryKind.FILE, is_manifest=True),
        InventoryEntry(path=SOURCE_PATH, kind=InventoryEntryKind.FILE, language="python"),
    ]
    if with_test:
        entries.append(
            InventoryEntry(path=TEST_PATH, kind=InventoryEntryKind.FILE, language="python")
        )
    return RepositoryIntelligenceReport(
        repository_name="repo",
        status=AnalysisStatus.COMPLETE,
        understanding_level=understanding,
        runtime_level=RuntimeLevel.R1,
        components=components,
        claims=claims,
        inventory=RepositoryInventory(entries=entries),
        coverage=Coverage(
            inventory_files=len(entries),
            source_files=len(entries),
            analyzed_source_files=len(entries),
            unsupported_files=0,
            manifest_files=1,
            total_bytes=100,
            analysis_percent=100.0,
        ),
    )


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("tests/test_app.py", True),
        ("src/__tests__/thing.js", True),
        ("pkg/handler_test.go", True),
        ("ui/App.spec.ts", True),
        ("src/app.py", False),
        ("src/latest.py", False),
        ("contest/main.py", False),
    ],
)
def test_is_test_path_uses_conventions_without_false_positives(path: str, expected: bool) -> None:
    assert is_test_path(path) is expected


def test_evidence_index_refuses_to_cite_a_path_without_a_digest() -> None:
    index = make_index()

    assert index.source_ref("r1", SOURCE_PATH, 1, 2) is not None
    assert index.source_ref("r2", "vendor/omitted.py", 1, 2) is None
    assert index.missing_paths == {"vendor/omitted.py"}


def test_evidence_index_never_builds_a_claim_without_a_citation() -> None:
    index = make_index()

    assert (
        index.build_claim(
            role=AgentRole.REPO_SURVEYOR,
            kind=ClaimKind.MODULE,
            subject_ref="component-1",
            predicate="declares_ecosystem",
            value="python",
            refs=(),
        )
        is None
    )


def test_claim_identity_is_reproducible_across_independent_runs() -> None:
    """Same commit, different run: the evidence identity must not move."""

    report = make_report()
    first_index = make_index()
    second_index = EvidenceIndex(
        snapshot_id=first_index.snapshot_id,
        repository_url=first_index.repository_url,
        commit=first_index.commit,
        run_id="a-completely-different-run",
        blob_sha256=BLOBS,
    )
    first = execute_role(AgentRole.ARCHITECTURE_MAPPER, "t", first_index, report)
    second = execute_role(AgentRole.ARCHITECTURE_MAPPER, "t", second_index, report)

    assert first.claims
    assert [item.claim_id for item in first.claims] == [item.claim_id for item in second.claims]
    # content_hash intentionally still binds the producing run: claim_id is the
    # content identity, content_hash is the integrity seal of one record.
    assert first.claims[0].provenance.producer_run_id != (
        second.claims[0].provenance.producer_run_id
    )


@pytest.mark.parametrize(
    ("role", "kind"),
    [
        (AgentRole.REPO_SURVEYOR, ClaimKind.MODULE),
        (AgentRole.ARCHITECTURE_MAPPER, ClaimKind.SYMBOL),
        (AgentRole.BUILD_RUNTIME_SCOUT, ClaimKind.RUNTIME),
        (AgentRole.TEST_HISTORY_ANALYST, ClaimKind.TEST_INTENT),
        (AgentRole.TWIN_SYNTHESIZER, ClaimKind.CAPABILITY),
    ],
)
def test_each_role_produces_its_own_cited_claims(role: AgentRole, kind: ClaimKind) -> None:
    result = execute_role(role, "task-1", make_index(), make_report())

    assert result.claims
    assert {item.kind for item in result.claims} == {kind}
    # Attribution is per role, not a single blanket producer.
    assert {item.provenance.producer_role for item in result.claims} == {role}
    for claim in result.claims:
        assert claim.support_refs
        assert set(claim.support_refs) <= {
            ref.ref_id for ref in claim.provenance.source_refs
        }
        # The citation must carry the real materialized digest for its path,
        # not merely something shaped like a digest.
        for ref in claim.provenance.source_refs:
            assert ref.path in BLOBS
            assert ref.sha256 == BLOBS[ref.path]


def test_test_claims_are_inferred_because_assertions_are_never_parsed() -> None:
    result = execute_role(AgentRole.TEST_HISTORY_ANALYST, "t", make_index(), make_report())

    assert {item.epistemic_status for item in result.claims} == {EpistemicStatus.INFERRED}


def test_security_role_owns_endpoints_and_architecture_role_does_not() -> None:
    report = make_report(with_endpoint=True)
    security = execute_role(AgentRole.SECURITY_DOMAIN_MAPPER, "t", make_index(), report)
    architecture = execute_role(AgentRole.ARCHITECTURE_MAPPER, "t", make_index(), report)

    assert {item.value for item in security.claims} == {"GET /health"}
    assert all(item.kind is ClaimKind.ENTRY_POINT for item in security.claims)
    assert "GET /health" not in {item.value for item in architecture.claims}


def test_role_abstains_instead_of_reporting_success_without_evidence() -> None:
    empty = make_report(with_component=False, with_symbol=False, with_test=False)
    result = execute_role(AgentRole.REPO_SURVEYOR, "task-1", make_index(), empty)

    assert result.status is AgentResultStatus.ABSTAIN
    assert result.abstain_reason is not None
    assert not result.claims


def test_role_abstains_when_the_snapshot_omitted_its_only_evidence() -> None:
    index = make_index(blob_sha256={})
    result = execute_role(AgentRole.BUILD_RUNTIME_SCOUT, "task-1", index, make_report())

    assert result.status is AgentResultStatus.ABSTAIN
    assert MANIFEST_PATH in index.missing_paths


def test_capability_ceiling_downgrades_a_successful_role_to_partial() -> None:
    result = execute_role(AgentRole.BUILD_RUNTIME_SCOUT, "task-1", make_index(), make_report())

    # Runtime is R1: build systems are declared, never executed.
    assert result.status is AgentResultStatus.PARTIAL
    assert result.missing_information


def test_director_completes_without_citing_anything() -> None:
    result = execute_role(AgentRole.RESEARCH_DIRECTOR, "director", make_index(), make_report())

    assert result.status is AgentResultStatus.COMPLETE
    assert not result.claims


def _conflicting_pair(status_a: EpistemicStatus, status_b: EpistemicStatus, refs: int = 1):
    index = make_index()
    base = dict(
        kind=ClaimKind.BEHAVIOR,
        subject_ref="src/app.py",
        predicate="enforces",
        scope=ClaimScope(operation_id="op-1"),
    )
    first = index.build_claim(
        role=AgentRole.SECURITY_DOMAIN_MAPPER,
        value="authentication",
        refs=(index.source_ref("r1", SOURCE_PATH, 1, 2),),
        epistemic_status=status_a,
        **base,
    )
    second_refs = [index.source_ref(f"r{position + 2}", SOURCE_PATH, 1, 2) for position in range(refs)]
    second = index.build_claim(
        role=AgentRole.SECURITY_DOMAIN_MAPPER,
        value="nothing",
        refs=tuple(second_refs),
        epistemic_status=status_b,
        **base,
    )
    board = Blackboard()
    board.append_claim_batch((first, second))
    return board, first, second


def test_skeptic_resolves_a_conflict_in_favour_of_stronger_evidence() -> None:
    board, observed, inferred = _conflicting_pair(
        EpistemicStatus.OBSERVED, EpistemicStatus.INFERRED
    )

    adjudication = adjudicate(board)

    assert adjudication.accepted_claim_ids == (observed.claim_id,)
    assert adjudication.rejected_claim_ids == (inferred.claim_id,)
    assert not adjudication.unresolved_conflict_ids
    assert adjudication.resolved_count == 1


def test_skeptic_refuses_to_break_a_tie_the_evidence_does_not_break() -> None:
    board, _, _ = _conflicting_pair(EpistemicStatus.DERIVED, EpistemicStatus.DERIVED)

    adjudication = adjudicate(board)

    assert adjudication.unresolved_conflict_ids
    assert not adjudication.accepted_claim_ids
    assert adjudication.resolved_count == 0


def test_skeptic_prefers_the_more_heavily_cited_claim_at_equal_rank() -> None:
    board, single, multiple = _conflicting_pair(
        EpistemicStatus.DERIVED, EpistemicStatus.DERIVED, refs=3
    )

    adjudication = adjudicate(board)

    assert adjudication.accepted_claim_ids == (multiple.claim_id,)
    assert adjudication.rejected_claim_ids == (single.claim_id,)


def test_skeptic_result_reports_unresolved_ties_as_partial() -> None:
    board, _, _ = _conflicting_pair(EpistemicStatus.DERIVED, EpistemicStatus.DERIVED)
    adjudication = adjudicate(board)

    result = skeptic_result("skeptic", adjudication)

    assert result.status is AgentResultStatus.PARTIAL
    assert result.conflict_ids == adjudication.unresolved_conflict_ids


def test_skeptic_result_is_complete_when_no_conflict_exists() -> None:
    result = skeptic_result("skeptic", adjudicate(Blackboard()))

    assert result.status is AgentResultStatus.COMPLETE


def test_identical_assertions_collapse_into_one_claim() -> None:
    """Two IR facts that normalize to the same assertion are one claim.

    Emitting both would collide on claim_id and abort the whole analysis when
    the board rejects the duplicate.
    """

    report = make_report(duplicate_symbol=True)
    result = execute_role(AgentRole.ARCHITECTURE_MAPPER, "t", make_index(), report)

    ids = [item.claim_id for item in result.claims]
    assert len(ids) == len(set(ids))
    assert sum(1 for item in result.claims if item.value == "os") == 1


def test_a_repository_with_duplicate_facts_still_reaches_the_board() -> None:
    board = Blackboard()
    result = execute_role(
        AgentRole.ARCHITECTURE_MAPPER, "t", make_index(), make_report(duplicate_symbol=True)
    )

    # Must not raise BlackboardValidationError.
    board.append_claim_batch(result.claims)

    assert len(board.claims) == len(result.claims)


def _pipeline_helpers():
    from logiclab.repository_analysis import (
        AgentTeamOutcome,
        _merge_uncitable_evidence,
        _remaining_disputes,
    )

    return AgentTeamOutcome, _merge_uncitable_evidence, _remaining_disputes


def test_uncitable_evidence_becomes_a_visible_diagnostic_and_forces_partial() -> None:
    AgentTeamOutcome, merge, _ = _pipeline_helpers()
    report = make_report()
    assert report.status is AnalysisStatus.COMPLETE

    merged = merge(
        report,
        AgentTeamOutcome(
            tasks=[],
            claims=[],
            disputed_claim_ids=[],
            missing_paths=("vendor/opaque.py",),
            stop_reasons=("tool_budget_exhausted",),
            proposal_notes=("security_domain_mapper: rejected proposal — bad path",),
        ),
    )

    assert merged.status is AnalysisStatus.PARTIAL
    codes = {item.code for item in merged.diagnostics}
    assert "harness.evidence_uncitable" in codes
    assert "harness.budget_stop" in codes
    assert "harness.proposal_rejected" in codes
    assert any(item.path == "vendor/opaque.py" for item in merged.diagnostics)


def test_a_clean_run_is_left_untouched() -> None:
    AgentTeamOutcome, merge, _ = _pipeline_helpers()
    report = make_report()

    merged = merge(
        report,
        AgentTeamOutcome(
            tasks=[], claims=[], disputed_claim_ids=[], missing_paths=(), stop_reasons=()
        ),
    )

    assert merged is report


def test_an_adjudicated_winner_is_no_longer_reported_as_disputed() -> None:
    _, _, remaining = _pipeline_helpers()
    board, observed, inferred = _conflicting_pair(
        EpistemicStatus.OBSERVED, EpistemicStatus.INFERRED
    )
    view = board.reduce()
    adjudication = adjudicate(board)

    # reduce() flags both sides of the conflict...
    assert set(view.disputed_claim_ids) == {observed.claim_id, inferred.claim_id}

    # ...but once the skeptic has ruled, neither is an outstanding dispute.
    assert remaining(board, view, adjudication) == []


def test_an_unresolved_tie_stays_reported_as_disputed() -> None:
    _, _, remaining = _pipeline_helpers()
    board, first, second = _conflicting_pair(
        EpistemicStatus.DERIVED, EpistemicStatus.DERIVED
    )
    view = board.reduce()

    assert remaining(board, view, adjudicate(board)) == sorted(
        [first.claim_id, second.claim_id]
    )


def test_an_abstaining_role_always_says_what_would_unblock_it() -> None:
    """An outcome with no next step is a dead end for whoever reads the report."""

    empty = make_report(with_component=False, with_symbol=False, with_test=False)
    # Every producing role, including the security mapper the proposer touches.
    for role in ROLE_PRODUCERS:
        result = execute_role(role, "t", make_index(), empty)
        assert result.status is AgentResultStatus.ABSTAIN
        assert result.next_actions, f"{role.value} abstained with no next action"


@pytest.mark.parametrize(
    ("role", "expected"),
    [
        (AgentRole.BUILD_RUNTIME_SCOUT, "sandbox manifest"),
        (AgentRole.SECURITY_DOMAIN_MAPPER, "framework adapters"),
        (AgentRole.TWIN_SYNTHESIZER, "understanding U4"),
    ],
)
def test_every_capability_limited_role_says_how_to_raise_the_ceiling(
    role: AgentRole, expected: str
) -> None:
    # U2 is the highest level the analyzer actually assigns, so all three
    # ceilings genuinely fire on a real report.
    result = execute_role(role, "t", make_index(), make_report(with_endpoint=True))

    assert result.status is AgentResultStatus.PARTIAL
    assert any(expected in item for item in result.next_actions)


def test_a_skeptic_that_cannot_break_a_tie_says_what_to_do_about_it() -> None:
    board, _, _ = _conflicting_pair(EpistemicStatus.DERIVED, EpistemicStatus.DERIVED)

    result = skeptic_result("skeptic", adjudicate(board))

    assert result.status is AgentResultStatus.PARTIAL
    assert result.next_actions


def test_a_crashing_role_is_retried_then_failed_without_killing_the_analysis(
    monkeypatch,
) -> None:
    """One broken producer must not cost every other role its claims."""

    import logiclab.repository_analysis as ra

    real = ra.execute_role
    calls: list[str] = []

    def flaky(role, task_id, index, report):
        if role is AgentRole.TEST_HISTORY_ANALYST:
            calls.append(task_id)
            raise RuntimeError("analyzer exploded reading Bearer SUPERSECRETVALUE123")
        return real(role, task_id, index, report)

    monkeypatch.setattr(ra, "execute_role", flaky)

    class _Snapshot:
        tree_digest = "sha256:" + "d" * 64
        blob_sha256 = BLOBS

    analysis = ra.RepositoryAnalysis(
        name="x", repository_url="https://github.com/acme/repo.git", commit="e" * 40
    )
    outcome = ra._run_agent_team(analysis, _Snapshot(), make_report())

    failed = [item for item in outcome.tasks if item.agent == "test_history_analyst"]
    assert failed and failed[0].status == "failed"
    # Retried up to the budget rather than dead-ending on the first error.
    assert len(calls) > 1
    # Every other producing role still delivered.
    assert outcome.claims
    assert {item.status for item in outcome.tasks} != {"failed"}
    # The crash message passes through the redactor before it is persisted.
    assert all("SUPERSECRETVALUE123" not in (item.output or "") for item in outcome.tasks)
    assert any("REDACTED" in (item.output or "") for item in outcome.tasks)


class _Snapshot:
    tree_digest = "sha256:" + "d" * 64
    blob_sha256 = BLOBS


def _team(monkeypatch=None, failing_role: AgentRole | None = None, proposer=None):
    import logiclab.repository_analysis as ra

    if failing_role is not None and monkeypatch is not None:
        real = ra.execute_role

        def flaky(role, task_id, index, report):
            if role is failing_role:
                raise RuntimeError("producer exploded")
            return real(role, task_id, index, report)

        monkeypatch.setattr(ra, "execute_role", flaky)

    analysis = ra.RepositoryAnalysis(
        name="x", repository_url="https://github.com/acme/repo.git", commit="e" * 40
    )
    return ra._run_agent_team(
        analysis, _Snapshot(), make_report(with_endpoint=True), proposer=proposer
    )


def test_next_actions_reach_the_persisted_task_view() -> None:
    """The observation only counts if it survives all the way to the report."""

    outcome = _team()
    by_agent = {item.agent: item for item in outcome.tasks}

    scout = by_agent["build_runtime_scout"]
    assert scout.status == "partial"
    assert any("sandbox manifest" in item for item in scout.next_actions)

    # A role that succeeded has nothing to unblock.
    assert by_agent["repo_surveyor"].next_actions == []


def test_a_blocked_task_names_the_upstream_that_stopped_it(monkeypatch) -> None:
    outcome = _team(monkeypatch, failing_role=AgentRole.REPO_SURVEYOR)
    by_id = {item.id: item for item in outcome.tasks}

    assert by_id["survey"].status == "failed"
    blocked = [item for item in outcome.tasks if item.status == "blocked"]
    assert blocked, "a failed root should block its dependents"
    for task in blocked:
        assert task.output, f"{task.id} is blocked with no explanation"
        assert task.next_actions, f"{task.id} is blocked with no next action"
    # The direct dependent points at the real culprit by name.
    assert "survey" in by_id["architecture"].output


def test_enabling_the_proposer_does_not_strip_role_guidance() -> None:
    """A model extension must not delete the deterministic role's own next steps."""

    from logiclab.proposals import ProposalSet

    class _Proposer:
        def propose(self, role, index, report):
            from logiclab.harness import BudgetUsage
            from logiclab.proposals import ClaimProposer

            class _Client:
                @staticmethod
                def structured_chat(model, system, user, response_model):
                    return ProposalSet(proposals=[])

            del BudgetUsage, ClaimProposer
            return _real_proposer().propose(role, index, report)

    def _real_proposer():
        from logiclab.proposals import ClaimProposer, ProposedClaim

        class _Client:
            @staticmethod
            def structured_chat(model, system, user, response_model):
                return ProposalSet(
                    proposals=[
                        ProposedClaim(
                            kind="behavior",
                            subject="src/app.py",
                            predicate="enforces",
                            value="tenant isolation",
                            path=SOURCE_PATH,
                            start_line=1,
                            end_line=2,
                            rationale="checked before returning rows",
                        )
                    ]
                )

        return ClaimProposer(client=_Client(), model="m")

    outcome = _team(proposer=_Proposer())
    by_agent = {item.agent: item for item in outcome.tasks}

    for role in ("security_domain_mapper", "twin_synthesizer"):
        task = by_agent[role]
        assert task.status == "partial"
        assert task.next_actions, f"{role} lost its guidance once the proposer ran"
