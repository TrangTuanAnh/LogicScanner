from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from logiclab.harness import (
    AgentError,
    AgentResult,
    AgentResultStatus,
    AgentRole,
    Blackboard,
    BlackboardValidationError,
    BudgetUsage,
    Claim,
    ClaimKind,
    ClaimProvenance,
    ClaimScope,
    ContextChannel,
    ContextRequest,
    DependencyPolicy,
    EpistemicStatus,
    InvalidTaskTransition,
    SourceRef,
    StopReason,
    StopRules,
    TaskBudget,
    TaskDAG,
    TaskKind,
    TaskScope,
    TaskSpec,
    TaskStatus,
    ToolError,
    ToolObservation,
    ToolStatus,
    default_role_team,
)


COMMIT = "a" * 40
SHA256 = "b" * 64


def source_ref(ref_id: str = "CODE-1") -> SourceRef:
    return SourceRef(
        ref_id=ref_id,
        artifact_id="ART-1",
        sha256=SHA256,
        path="src/app.py",
        start_line=10,
        end_line=20,
    )


def provenance(
    *refs: SourceRef, role: AgentRole = AgentRole.ARCHITECTURE_MAPPER
) -> ClaimProvenance:
    return ClaimProvenance(
        snapshot_id="SNAP-1",
        repository_url="https://github.com/acme/repo.git",
        commit=COMMIT,
        producer_role=role,
        producer_run_id="ARUN-1",
        tool_name="symbol_definition",
        tool_version="1.0",
        source_refs=refs or (source_ref(),),
    )


def claim(
    claim_id: str,
    value: object,
    *,
    kind: ClaimKind = ClaimKind.ENTRY_POINT,
    predicate: str = "EXPOSES_HTTP_ROUTE",
    status: EpistemicStatus = EpistemicStatus.OBSERVED,
    config_profile: str | None = "default",
    supersedes_claim_id: str | None = None,
) -> Claim:
    return Claim(
        claim_id=claim_id,
        snapshot_id="SNAP-1",
        kind=kind,
        subject_ref="SYM-controller.update",
        predicate=predicate,
        value=value,
        epistemic_status=status,
        scope=ClaimScope(module_id="api", config_profile=config_profile),
        support_refs=("CODE-1",),
        provenance=provenance(),
        supersedes_claim_id=supersedes_claim_id,
    )


def task(
    task_id: str,
    kind: TaskKind,
    role: AgentRole,
    *,
    depends_on: tuple[str, ...] = (),
    dependency_policy: DependencyPolicy = DependencyPolicy.STRICT,
) -> TaskSpec:
    return TaskSpec(
        task_id=task_id,
        engagement_id="ENG-1",
        snapshot_id="SNAP-1",
        kind=kind,
        role=role,
        scope=TaskScope(module_ids=("api",)),
        context=ContextRequest(
            purpose=kind,
            channels=(ContextChannel.SYMBOLIC, ContextChannel.GRAPH),
            anchor_refs=("MOD-api",),
            max_context_tokens=4_000,
        ),
        budget=TaskBudget(max_context_tokens=8_000, max_tool_calls=20, max_wall_seconds=300),
        depends_on=depends_on,
        dependency_policy=dependency_policy,
    )


def test_task_spec_derives_stable_idempotency_key_from_semantic_input() -> None:
    first = task("TASK-1", TaskKind.MAP_ARCHITECTURE, AgentRole.ARCHITECTURE_MAPPER)
    second = task("TASK-2", TaskKind.MAP_ARCHITECTURE, AgentRole.ARCHITECTURE_MAPPER)
    changed = first.model_copy(
        update={"scope": TaskScope(module_ids=("worker",)), "idempotency_key": ""}
    )
    changed = TaskSpec.model_validate(changed.model_dump(mode="json"))

    assert first.idempotency_key == second.idempotency_key
    assert changed.idempotency_key != first.idempotency_key


def test_task_context_cannot_exceed_task_budget() -> None:
    with pytest.raises(ValidationError, match="context request exceeds task budget"):
        TaskSpec(
            task_id="TASK-1",
            engagement_id="ENG-1",
            snapshot_id="SNAP-1",
            kind=TaskKind.MAP_ARCHITECTURE,
            role=AgentRole.ARCHITECTURE_MAPPER,
            context=ContextRequest(
                purpose=TaskKind.MAP_ARCHITECTURE,
                channels=(ContextChannel.SYMBOLIC,),
                max_context_tokens=2_000,
            ),
            budget=TaskBudget(max_context_tokens=1_000),
        )


def test_tool_error_has_explicit_recovery_contract() -> None:
    observation = ToolObservation(
        tool_name="symbol_references",
        status=ToolStatus.ERROR,
        summary="Index is unavailable",
        next_actions=("BUILD_SYMBOL_INDEX",),
        artifacts=(),
        error=ToolError(
            code="INDEX_MISSING",
            root_cause_hint="No symbol index exists for this snapshot",
            safe_retry_instruction="Build the index once and retry",
            stop_condition="Stop after two identical failures",
        ),
    )
    assert observation.error is not None

    with pytest.raises(ValidationError, match="error observation requires a recovery contract"):
        ToolObservation(
            tool_name="symbol_references",
            status=ToolStatus.ERROR,
            summary="Index is unavailable",
        )


def test_agent_result_enforces_error_and_abstention_contracts() -> None:
    with pytest.raises(ValidationError, match="ABSTAIN result requires"):
        AgentResult(
            task_id="TASK-1",
            role=AgentRole.REPO_SURVEYOR,
            status=AgentResultStatus.ABSTAIN,
            summary="Cannot inspect generated source",
        )

    result = AgentResult(
        task_id="TASK-1",
        role=AgentRole.REPO_SURVEYOR,
        status=AgentResultStatus.PARTIAL,
        summary="Inventory completed with one unreadable subtree",
        missing_information=("vendor/generated",),
    )
    assert result.status is AgentResultStatus.PARTIAL


def test_blackboard_is_append_only_and_validates_provenance() -> None:
    board = Blackboard()
    original = claim("CLM-1", {"method": "PUT", "path": "/projects/{id}"})
    board.append_claim(original)

    assert board.append_claim(original).claim_id == "CLM-1"  # idempotent retry
    with pytest.raises(BlackboardValidationError, match="cannot be overwritten"):
        board.append_claim(claim("CLM-1", {"method": "POST", "path": "/projects"}))

    invalid = claim("CLM-2", True).model_copy(update={"support_refs": ("UNKNOWN",)})
    with pytest.raises(BlackboardValidationError, match="unknown provenance refs"):
        board.append_claim(invalid)


def test_blackboard_batch_is_atomic() -> None:
    board = Blackboard()
    valid = claim("CLM-1", True)
    invalid = claim("CLM-2", False).model_copy(update={"snapshot_id": "SNAP-OTHER"})

    with pytest.raises(BlackboardValidationError):
        board.append_claim_batch((valid, invalid))
    assert board.claims == ()


def test_reducer_detects_value_conflict_but_keeps_config_and_intent_separate() -> None:
    board = Blackboard()
    board.append_claim_batch(
        (
            claim("CLM-1", {"method": "PUT"}),
            claim("CLM-2", {"method": "POST"}),
            claim("CLM-3", {"method": "DELETE"}, config_profile="admin"),
            claim("CLM-4", "owners only", kind=ClaimKind.INTENT, predicate="ACCESS_POLICY"),
        )
    )

    view = board.reduce()
    assert len(view.conflicts) == 1
    assert view.conflicts[0].claim_ids == ("CLM-1", "CLM-2")
    assert set(view.disputed_claim_ids) == {"CLM-1", "CLM-2"}
    assert {item.claim_id for item in view.accepted_claims} == {"CLM-3", "CLM-4"}


def test_superseded_claim_is_not_part_of_active_twin() -> None:
    board = Blackboard()
    original = claim("CLM-1", "old")
    replacement = claim("CLM-2", "new", supersedes_claim_id="CLM-1")
    board.append_claim_batch((original, replacement))

    view = board.reduce()
    assert view.superseded_claim_ids == ("CLM-1",)
    assert tuple(item.claim_id for item in view.accepted_claims) == ("CLM-2",)


def test_task_dag_schedules_ready_work_and_enforces_transitions() -> None:
    dag = TaskDAG()
    inventory = task("TASK-1", TaskKind.INVENTORY_REPOSITORY, AgentRole.REPO_SURVEYOR)
    mapping = task(
        "TASK-2",
        TaskKind.MAP_ARCHITECTURE,
        AgentRole.ARCHITECTURE_MAPPER,
        depends_on=("TASK-1",),
    )
    dag.add_task(inventory)
    dag.add_task(mapping)

    assert tuple(item.task_id for item in dag.ready_tasks()) == ("TASK-1",)
    dag.transition("TASK-1", TaskStatus.RUNNING)
    dag.transition("TASK-1", TaskStatus.SUCCEEDED)
    assert tuple(item.task_id for item in dag.ready_tasks()) == ("TASK-2",)

    with pytest.raises(InvalidTaskTransition):
        dag.transition("TASK-2", TaskStatus.SUCCEEDED)


def test_task_dag_blocks_strict_dependents_and_allows_tolerant_partial_dependency() -> None:
    strict = TaskDAG()
    strict.add_task(task("ROOT", TaskKind.INVENTORY_REPOSITORY, AgentRole.REPO_SURVEYOR))
    strict.add_task(
        task(
            "CHILD",
            TaskKind.MAP_ARCHITECTURE,
            AgentRole.ARCHITECTURE_MAPPER,
            depends_on=("ROOT",),
        )
    )
    strict.transition("ROOT", TaskStatus.RUNNING)
    strict.transition("ROOT", TaskStatus.PARTIAL)
    assert strict.status("CHILD") is TaskStatus.BLOCKED

    tolerant = TaskDAG()
    tolerant.add_task(task("ROOT", TaskKind.INVENTORY_REPOSITORY, AgentRole.REPO_SURVEYOR))
    tolerant.add_task(
        task(
            "CHILD",
            TaskKind.SYNTHESIZE_TWIN,
            AgentRole.TWIN_SYNTHESIZER,
            depends_on=("ROOT",),
            dependency_policy=DependencyPolicy.TOLERANT,
        )
    )
    tolerant.transition("ROOT", TaskStatus.RUNNING)
    tolerant.transition("ROOT", TaskStatus.PARTIAL)
    assert tolerant.status("CHILD") is TaskStatus.READY


def test_task_dag_rejects_duplicate_idempotency_key() -> None:
    dag = TaskDAG()
    dag.add_task(task("TASK-1", TaskKind.MAP_ARCHITECTURE, AgentRole.ARCHITECTURE_MAPPER))
    with pytest.raises(ValueError, match="idempotency key"):
        dag.add_task(task("TASK-2", TaskKind.MAP_ARCHITECTURE, AgentRole.ARCHITECTURE_MAPPER))


def test_stop_rules_cover_budget_retry_policy_snapshot_and_no_progress() -> None:
    budget = TaskBudget(
        max_context_tokens=100,
        max_tool_calls=5,
        max_wall_seconds=60,
        max_retries=2,
        max_probe_rounds=2,
    )
    assessment = StopRules.evaluate(
        budget,
        BudgetUsage(context_tokens=100, tool_calls=2, wall_seconds=10),
    )
    assert assessment.stop
    assert StopReason.CONTEXT_BUDGET_EXHAUSTED in assessment.reasons

    assessment = StopRules.evaluate(
        budget,
        BudgetUsage(retries=2, probe_rounds=2),
        policy_denied=True,
        snapshot_matches=False,
        recent_coverage_gains=(0.0, 0.005),
    )
    assert {
        StopReason.MAX_RETRIES,
        StopReason.MAX_PROBE_ROUNDS,
        StopReason.POLICY_DENIED,
        StopReason.SNAPSHOT_MISMATCH,
        StopReason.NO_COVERAGE_GAIN,
    }.issubset(set(assessment.reasons))


def test_default_role_team_is_unique_and_covers_every_task_kind() -> None:
    team = default_role_team()
    assert len({member.role for member in team.members}) == len(team.members)
    covered = {kind for member in team.members for kind in member.task_kinds}
    assert covered == set(TaskKind)


def test_claim_content_hash_is_stable_across_observation_times() -> None:
    """Reproducibility: the same evidence must hash the same in every run."""

    early = claim("CLM-time", "value")
    later = Claim(
        claim_id="CLM-time",
        snapshot_id="SNAP-1",
        kind=ClaimKind.ENTRY_POINT,
        predicate="EXPOSES_HTTP_ROUTE",
        subject_ref="SYM-controller.update",
        value="value",
        epistemic_status=EpistemicStatus.OBSERVED,
        scope=ClaimScope(module_id="api", config_profile="default"),
        support_refs=("CODE-1",),
        provenance=provenance().model_copy(
            update={"created_at": datetime(2000, 1, 1, tzinfo=timezone.utc)}
        ),
    )

    assert early.provenance.created_at != later.provenance.created_at
    assert early.content_hash == later.content_hash


def test_claim_content_hash_still_tracks_real_evidence_changes() -> None:
    assert claim("CLM-a", "one").content_hash != claim("CLM-a", "two").content_hash
    assert (
        claim("CLM-a", "one").content_hash
        != claim("CLM-a", "one", predicate="OTHER").content_hash
    )


def test_task_dag_accumulates_usage_and_applies_stop_rules() -> None:
    dag = TaskDAG((task("T-1", TaskKind.MAP_ARCHITECTURE, AgentRole.ARCHITECTURE_MAPPER),))
    dag.claim_next()

    dag.record_usage("T-1", BudgetUsage(tool_calls=8))
    dag.record_usage("T-1", BudgetUsage(tool_calls=9))

    assert dag.usage_for("T-1").tool_calls == 17
    assert dag.aggregate_usage().tool_calls == 17
    assert dag.assess_stop("T-1").stop is False

    dag.record_usage("T-1", BudgetUsage(tool_calls=3))
    assessment = dag.assess_stop("T-1")

    assert assessment.stop is True
    assert StopReason.TOOL_BUDGET_EXHAUSTED in assessment.reasons


def test_completing_a_task_records_its_reported_usage() -> None:
    dag = TaskDAG((task("T-1", TaskKind.MAP_ARCHITECTURE, AgentRole.ARCHITECTURE_MAPPER),))
    dag.claim_next()

    dag.complete_task(
        "T-1",
        AgentResult(
            task_id="T-1",
            role=AgentRole.ARCHITECTURE_MAPPER,
            status=AgentResultStatus.COMPLETE,
            summary="done",
            usage=BudgetUsage(tool_calls=4, context_tokens=100),
        ),
    )

    assert dag.usage_for("T-1").tool_calls == 4
    assert dag.usage_for("T-1").context_tokens == 100


def test_an_error_result_counts_as_a_spent_retry() -> None:
    dag = TaskDAG((task("T-1", TaskKind.MAP_ARCHITECTURE, AgentRole.ARCHITECTURE_MAPPER),))
    dag.claim_next()

    dag.complete_task(
        "T-1",
        AgentResult(
            task_id="T-1",
            role=AgentRole.ARCHITECTURE_MAPPER,
            status=AgentResultStatus.ERROR,
            summary="boom",
            error=AgentError(
                code="E",
                root_cause_hint="h",
                safe_retry_instruction="r",
                stop_condition="s",
            ),
        ),
    )

    assert dag.status("T-1") is TaskStatus.RETRYABLE
    assert dag.usage_for("T-1").retries == 1


def sibling_task(task_id: str, kind: TaskKind, role: AgentRole, module: str) -> TaskSpec:
    """A task that is semantically distinct, so its idempotency key differs."""

    return TaskSpec(
        task_id=task_id,
        engagement_id="ENG-1",
        snapshot_id="SNAP-1",
        kind=kind,
        role=role,
        scope=TaskScope(module_ids=(module,)),
        budget=TaskBudget(max_tool_calls=20),
    )


def test_dag_enforces_role_max_parallelism_when_dispatching() -> None:
    # TWIN_SYNTHESIZER has max_parallelism 1 in the default role team.
    specs = (
        sibling_task("T-1", TaskKind.SYNTHESIZE_TWIN, AgentRole.TWIN_SYNTHESIZER, "api"),
        sibling_task("T-2", TaskKind.SYNTHESIZE_TWIN, AgentRole.TWIN_SYNTHESIZER, "worker"),
    )
    dag = TaskDAG(specs)

    assert len(dag.ready_tasks()) == 2
    first = dag.claim_next()

    assert first is not None
    assert dag.running_counts()[AgentRole.TWIN_SYNTHESIZER] == 1
    # Still ready by dependency, but no longer dispatchable by capacity.
    assert len(dag.ready_tasks()) == 1
    assert dag.dispatchable_tasks() == ()
    assert dag.claim_next() is None


def test_parallel_roles_may_dispatch_up_to_their_declared_limit() -> None:
    specs = tuple(
        sibling_task(
            f"T-{index}", TaskKind.MAP_ARCHITECTURE, AgentRole.ARCHITECTURE_MAPPER, f"mod-{index}"
        )
        for index in range(6)
    )
    dag = TaskDAG(specs)

    claimed = [dag.claim_next() for _ in range(5)]

    # ARCHITECTURE_MAPPER declares max_parallelism 4.
    assert sum(1 for item in claimed if item is not None) == 4
    assert claimed[4] is None


def test_reappending_the_same_assertion_is_idempotent_not_fatal() -> None:
    """Two records of one assertion differ only in created_at; that is not a conflict."""

    board = Blackboard()
    first = claim("CLM-dup", "value")
    second = Claim(
        claim_id="CLM-dup",
        snapshot_id="SNAP-1",
        kind=ClaimKind.ENTRY_POINT,
        predicate="EXPOSES_HTTP_ROUTE",
        subject_ref="SYM-controller.update",
        value="value",
        epistemic_status=EpistemicStatus.OBSERVED,
        scope=ClaimScope(module_id="api", config_profile="default"),
        support_refs=("CODE-1",),
        provenance=provenance().model_copy(
            update={"created_at": datetime(2001, 5, 5, tzinfo=timezone.utc)}
        ),
    )
    board.append_claim(first)

    board.append_claim(second)

    assert len(board.claims) == 1


def test_reappending_a_different_assertion_under_one_id_still_fails() -> None:
    board = Blackboard()
    board.append_claim(claim("CLM-x", "one"))

    with pytest.raises(BlackboardValidationError, match="append-only"):
        board.append_claim(claim("CLM-x", "two"))


def test_a_rejected_completion_banks_no_budget() -> None:
    dag = TaskDAG((task("T-1", TaskKind.MAP_ARCHITECTURE, AgentRole.ARCHITECTURE_MAPPER),))
    dag.claim_next()
    result = AgentResult(
        task_id="T-1",
        role=AgentRole.ARCHITECTURE_MAPPER,
        status=AgentResultStatus.COMPLETE,
        summary="done",
        usage=BudgetUsage(tool_calls=5),
    )
    dag.complete_task("T-1", result)

    with pytest.raises(InvalidTaskTransition):
        dag.complete_task("T-1", result)

    # A duplicated completion must not inflate usage past the single real run.
    assert dag.usage_for("T-1").tool_calls == 5


def test_a_rejected_error_completion_does_not_fabricate_a_retry() -> None:
    dag = TaskDAG((task("T-1", TaskKind.MAP_ARCHITECTURE, AgentRole.ARCHITECTURE_MAPPER),))
    dag.claim_next()
    error = AgentResult(
        task_id="T-1",
        role=AgentRole.ARCHITECTURE_MAPPER,
        status=AgentResultStatus.ERROR,
        summary="boom",
        error=AgentError(
            code="E", root_cause_hint="h", safe_retry_instruction="r", stop_condition="s"
        ),
    )
    dag.complete_task("T-1", error)
    assert dag.usage_for("T-1").retries == 1

    # RETRYABLE -> RETRYABLE is illegal; the rejected call must not spend a retry.
    with pytest.raises(InvalidTaskTransition):
        dag.complete_task("T-1", error)

    assert dag.usage_for("T-1").retries == 1
    assert dag.assess_stop("T-1").stop is False


def test_aggregate_usage_sums_across_distinct_tasks() -> None:
    dag = TaskDAG(
        (
            sibling_task("T-1", TaskKind.MAP_ARCHITECTURE, AgentRole.ARCHITECTURE_MAPPER, "a"),
            sibling_task("T-2", TaskKind.MAP_ARCHITECTURE, AgentRole.ARCHITECTURE_MAPPER, "b"),
        )
    )
    dag.record_usage("T-1", BudgetUsage(tool_calls=3))
    dag.record_usage("T-2", BudgetUsage(tool_calls=4))

    assert dag.usage_for("T-1").tool_calls == 3
    assert dag.aggregate_usage().tool_calls == 7
