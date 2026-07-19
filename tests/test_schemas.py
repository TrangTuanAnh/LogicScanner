from uuid import uuid4

import pytest
from pydantic import ValidationError

from logiclab.schemas import (
    FindingStatus,
    Hypothesis,
    RepositorySpec,
    assert_status_transition,
)


def test_repository_requires_full_commit_sha() -> None:
    with pytest.raises(ValidationError):
        RepositorySpec(url="https://github.com/acme/repo.git", commit="main")


def test_hypothesis_requires_source_references() -> None:
    with pytest.raises(ValidationError):
        Hypothesis(
            id=uuid4(),
            invariant_id=uuid4(),
            title="Missing trust check",
            rationale="A route forwards untrusted data.",
            candidate_entry_point="POST /flow",
            experiment_kind="trust_laundering",
            source_refs=[],
        )


def test_finding_state_machine_rejects_skips() -> None:
    assert_status_transition(FindingStatus.HYPOTHESIS, FindingStatus.OBSERVED_ANOMALY)
    with pytest.raises(ValueError, match="Invalid finding transition"):
        assert_status_transition(FindingStatus.HYPOTHESIS, FindingStatus.SECURITY_CONFIRMED)
