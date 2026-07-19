import pytest

from logiclab.harness import AgentResultStatus, AgentRole, Blackboard, ClaimKind, EpistemicStatus
from logiclab.ollama import ModelContractError
from logiclab.proposals import (
    ClaimProposer,
    ProposalSet,
    ProposedClaim,
    ProposerPolicy,
    build_proposer,
)
from logiclab.roles import adjudicate, execute_role
from tests.test_roles import SOURCE_PATH, make_index, make_report


class FakeClient:
    """Stands in for a local Ollama endpoint without any network access."""

    def __init__(self, result: ProposalSet | Exception) -> None:
        self.result = result
        self.calls: list[dict] = []

    def structured_chat(self, model, system, user, response_model):
        self.calls.append({"model": model, "system": system, "user": user})
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def proposal(
    path: str = SOURCE_PATH,
    kind: str = "behavior",
    subject: str = "src/app.py",
    value: str = "enforces tenant isolation",
) -> ProposedClaim:
    return ProposedClaim(
        kind=kind,
        subject=subject,
        predicate="enforces",
        value=value,
        path=path,
        start_line=1,
        end_line=2,
        rationale="the handler checks the tenant id before returning rows",
    )


def make_proposer(result, policy: ProposerPolicy | None = None) -> ClaimProposer:
    return ClaimProposer(client=FakeClient(result), model="test-model", policy=policy)


def test_admitted_proposals_are_always_inferred_never_observed() -> None:
    proposer = make_proposer(ProposalSet(proposals=[proposal()]))

    outcome = proposer.propose(AgentRole.SECURITY_DOMAIN_MAPPER, make_index(), make_report())

    assert len(outcome.claims) == 1
    claim = outcome.claims[0]
    assert claim.epistemic_status is EpistemicStatus.INFERRED
    assert claim.kind is ClaimKind.BEHAVIOR
    assert claim.provenance.producer_role is AgentRole.SECURITY_DOMAIN_MAPPER
    assert claim.provenance.source_refs[0].path == SOURCE_PATH
    assert len(claim.provenance.source_refs[0].sha256) == 64


def test_a_proposal_citing_an_unshown_file_is_rejected() -> None:
    proposer = make_proposer(ProposalSet(proposals=[proposal(path="/etc/passwd")]))

    outcome = proposer.propose(AgentRole.SECURITY_DOMAIN_MAPPER, make_index(), make_report())

    assert outcome.claims == ()
    assert any("evidence allow-list" in item for item in outcome.rejected)


def test_a_proposal_citing_an_unmaterialized_file_is_rejected() -> None:
    # A path the model was never shown, and which carries no snapshot digest.
    proposer = make_proposer(ProposalSet(proposals=[proposal(path="vendor/blob.min.js")]))

    outcome = proposer.propose(AgentRole.SECURITY_DOMAIN_MAPPER, make_index(), make_report())

    assert outcome.claims == ()
    assert outcome.rejected


@pytest.mark.parametrize("kind", ["symbol", "module", "runtime", "capability", "nonsense"])
def test_structural_claim_kinds_are_not_proposable(kind: str) -> None:
    proposer = make_proposer(ProposalSet(proposals=[proposal(kind=kind)]))

    outcome = proposer.propose(AgentRole.SECURITY_DOMAIN_MAPPER, make_index(), make_report())

    assert outcome.claims == ()
    assert any("not proposable" in item for item in outcome.rejected)


def test_proposal_count_is_capped_by_policy() -> None:
    many = ProposalSet(
        proposals=[proposal(value=f"claim number {index}") for index in range(10)]
    )
    proposer = make_proposer(many, policy=ProposerPolicy(max_proposals=3))

    outcome = proposer.propose(AgentRole.SECURITY_DOMAIN_MAPPER, make_index(), make_report())

    assert len(outcome.claims) == 3
    assert any("budget exhausted" in item for item in outcome.rejected)


def test_identical_proposals_are_deduplicated() -> None:
    proposer = make_proposer(ProposalSet(proposals=[proposal(), proposal()]))

    outcome = proposer.propose(AgentRole.SECURITY_DOMAIN_MAPPER, make_index(), make_report())

    assert len(outcome.claims) == 1
    assert any("duplicate" in item for item in outcome.rejected)


def test_the_model_only_ever_sees_materialized_analyzable_paths() -> None:
    client = FakeClient(ProposalSet(proposals=[]))
    proposer = ClaimProposer(client=client, model="test-model")

    proposer.propose(AgentRole.SECURITY_DOMAIN_MAPPER, make_index(), make_report())

    allowed = client.calls[0]["user"]["allowed_paths"]
    assert SOURCE_PATH in allowed
    assert all(path in make_index().blob_sha256 for path in allowed)


def test_no_model_call_is_made_when_nothing_can_be_cited() -> None:
    client = FakeClient(ProposalSet(proposals=[proposal()]))
    proposer = ClaimProposer(client=client, model="test-model")

    outcome = proposer.propose(
        AgentRole.SECURITY_DOMAIN_MAPPER, make_index(blob_sha256={}), make_report()
    )

    assert outcome.claims == ()
    assert client.calls == []


def test_a_proposal_records_its_model_round_trip_as_budget_usage() -> None:
    proposer = make_proposer(ProposalSet(proposals=[proposal()]))

    outcome = proposer.propose(AgentRole.SECURITY_DOMAIN_MAPPER, make_index(), make_report())

    assert outcome.usage.tool_calls == 1
    assert outcome.usage.probe_rounds == 1


def test_build_proposer_requires_a_model_name() -> None:
    with pytest.raises(ModelContractError):
        build_proposer(base_url="http://127.0.0.1:11434", model="   ")


def test_an_inferred_proposal_loses_to_a_derived_claim_it_contradicts() -> None:
    """The whole point of the gate: where they genuinely disagree, a guess loses.

    A conflict only exists inside one (kind, subject, predicate, scope) group, so
    the contradiction is built in exactly that shape.
    """

    index = make_index()
    report = make_report()
    proposed = make_proposer(
        ProposalSet(proposals=[proposal(value="the handler is unauthenticated")])
    ).propose(AgentRole.SECURITY_DOMAIN_MAPPER, index, report)

    assert proposed.claims
    inferred = proposed.claims[0]
    derived = index.build_claim(
        role=AgentRole.SECURITY_DOMAIN_MAPPER,
        kind=inferred.kind,
        subject_ref=inferred.subject_ref,
        predicate=inferred.predicate,
        value="the handler requires a bearer token",
        refs=(index.source_ref("derived-1", SOURCE_PATH, 1, 2),),
        scope=inferred.scope,
        epistemic_status=EpistemicStatus.DERIVED,
    )

    board = Blackboard()
    board.append_claim_batch((derived, inferred))
    adjudication = adjudicate(board)

    assert adjudication.accepted_claim_ids == (derived.claim_id,)
    assert adjudication.rejected_claim_ids == (inferred.claim_id,)


def test_a_failing_model_degrades_the_role_without_failing_the_analysis() -> None:
    from logiclab.harness import TaskDAG, TaskKind, TaskScope, TaskSpec
    from logiclab.repository_analysis import _extend_with_proposals

    index = make_index()
    report = make_report()
    spec = TaskSpec(
        task_id="twin",
        engagement_id="E",
        snapshot_id="S",
        kind=TaskKind.SYNTHESIZE_TWIN,
        role=AgentRole.TWIN_SYNTHESIZER,
        scope=TaskScope(module_ids=("component-1",)),
    )
    dag = TaskDAG((spec,))
    dag.claim_next()
    baseline = execute_role(AgentRole.TWIN_SYNTHESIZER, "twin", index, report)
    proposer = make_proposer(ModelContractError("ollama is down"))

    result, notes = _extend_with_proposals(
        proposer, AgentRole.TWIN_SYNTHESIZER, baseline, index, report, dag
    )

    assert result.status is AgentResultStatus.PARTIAL
    assert result.claims == baseline.claims
    assert any("unavailable" in note for note in notes)


def test_one_malformed_span_does_not_discard_the_whole_batch() -> None:
    """A bad proposal is rejected; the good ones in the same response survive."""

    bad_backwards = proposal(value="backwards span").model_copy(
        update={"start_line": 50, "end_line": 10}
    )
    bad_partial = proposal(value="half a span").model_copy(
        update={"start_line": None, "end_line": 7}
    )
    good = proposal(value="a well formed claim")
    proposer = make_proposer(ProposalSet(proposals=[bad_backwards, bad_partial, good]))

    outcome = proposer.propose(AgentRole.SECURITY_DOMAIN_MAPPER, make_index(), make_report())

    assert [item.value for item in outcome.claims] == ["a well formed claim"]
    assert sum("not well formed" in item for item in outcome.rejected) == 2


def test_secrets_are_redacted_from_every_model_supplied_field() -> None:
    leaky = ProposedClaim(
        kind="behavior",
        subject="Authorization: Bearer SUPERSECRETTOKEN123",
        predicate="Authorization: Bearer SUPERSECRETTOKEN123",
        value="Authorization: Bearer SUPERSECRETTOKEN123",
        path=SOURCE_PATH,
        start_line=1,
        end_line=2,
        rationale="leaks a credential in every field",
    )
    proposer = make_proposer(ProposalSet(proposals=[leaky]))

    outcome = proposer.propose(AgentRole.SECURITY_DOMAIN_MAPPER, make_index(), make_report())

    claim = outcome.claims[0]
    assert "SUPERSECRETTOKEN123" not in claim.subject_ref
    assert "SUPERSECRETTOKEN123" not in claim.predicate
    assert "SUPERSECRETTOKEN123" not in str(claim.value)


def test_rejection_notes_are_bounded_so_diagnostics_cannot_explode() -> None:
    flood = ProposalSet(
        proposals=[
            proposal(path="/etc/passwd", value=f"rejected {index}") for index in range(200)
        ]
    )
    proposer = make_proposer(flood)

    outcome = proposer.propose(AgentRole.SECURITY_DOMAIN_MAPPER, make_index(), make_report())

    assert outcome.claims == ()
    assert len(outcome.rejected) <= 51
    assert any("not itemised" in item for item in outcome.rejected)


def test_an_oversized_response_is_a_contract_violation() -> None:
    with pytest.raises(Exception):
        ProposalSet(proposals=[proposal() for _ in range(501)])


def test_proposals_never_upgrade_a_role_that_abstained_on_evidence() -> None:
    from logiclab.harness import TaskDAG, TaskKind, TaskScope, TaskSpec
    from logiclab.repository_analysis import _extend_with_proposals

    index = make_index()
    # No endpoints in the report, so the security role abstains.
    report = make_report(with_endpoint=False)
    baseline = execute_role(AgentRole.SECURITY_DOMAIN_MAPPER, "sec", index, report)
    assert baseline.status is AgentResultStatus.ABSTAIN

    spec = TaskSpec(
        task_id="sec",
        engagement_id="E",
        snapshot_id="S",
        kind=TaskKind.MAP_SECURITY_DOMAIN,
        role=AgentRole.SECURITY_DOMAIN_MAPPER,
        scope=TaskScope(module_ids=("component-1",)),
    )
    dag = TaskDAG((spec,))
    dag.claim_next()
    proposer = make_proposer(ProposalSet(proposals=[proposal()]))

    result, notes = _extend_with_proposals(
        proposer, AgentRole.SECURITY_DOMAIN_MAPPER, baseline, index, report, dag
    )

    assert result.status is AgentResultStatus.ABSTAIN
    assert not result.claims
    assert any("abstained on evidence" in note for note in notes)


def test_proposals_extend_a_successful_role_and_mark_it_non_reproducible() -> None:
    from logiclab.harness import TaskDAG, TaskKind, TaskScope, TaskSpec
    from logiclab.intelligence import UnderstandingLevel
    from logiclab.repository_analysis import _extend_with_proposals

    index = make_index()
    report = make_report(with_endpoint=True, understanding=UnderstandingLevel.U4)
    baseline = execute_role(AgentRole.SECURITY_DOMAIN_MAPPER, "sec", index, report)
    assert baseline.status is AgentResultStatus.COMPLETE

    spec = TaskSpec(
        task_id="sec",
        engagement_id="E",
        snapshot_id="S",
        kind=TaskKind.MAP_SECURITY_DOMAIN,
        role=AgentRole.SECURITY_DOMAIN_MAPPER,
        scope=TaskScope(module_ids=("component-1",)),
    )
    dag = TaskDAG((spec,))
    dag.claim_next()
    proposer = make_proposer(ProposalSet(proposals=[proposal()]))

    result, _ = _extend_with_proposals(
        proposer, AgentRole.SECURITY_DOMAIN_MAPPER, baseline, index, report, dag
    )

    assert result.status is AgentResultStatus.PARTIAL
    assert len(result.claims) == len(baseline.claims) + 1
    assert any("not reproducible" in item for item in result.missing_information)
    assert dag.usage_for("sec").tool_calls == 1


def test_a_failing_model_degrades_a_complete_role_to_partial() -> None:
    from logiclab.harness import TaskDAG, TaskKind, TaskScope, TaskSpec
    from logiclab.intelligence import UnderstandingLevel
    from logiclab.repository_analysis import _extend_with_proposals

    index = make_index()
    report = make_report(with_endpoint=True, understanding=UnderstandingLevel.U4)
    baseline = execute_role(AgentRole.SECURITY_DOMAIN_MAPPER, "sec", index, report)
    assert baseline.status is AgentResultStatus.COMPLETE

    spec = TaskSpec(
        task_id="sec",
        engagement_id="E",
        snapshot_id="S",
        kind=TaskKind.MAP_SECURITY_DOMAIN,
        role=AgentRole.SECURITY_DOMAIN_MAPPER,
        scope=TaskScope(module_ids=("component-1",)),
    )
    dag = TaskDAG((spec,))
    dag.claim_next()
    proposer = make_proposer(ModelContractError("ollama is down"))

    result, notes = _extend_with_proposals(
        proposer, AgentRole.SECURITY_DOMAIN_MAPPER, baseline, index, report, dag
    )

    assert result.status is AgentResultStatus.PARTIAL
    assert result.claims == baseline.claims
    assert any("unavailable" in note for note in notes)
