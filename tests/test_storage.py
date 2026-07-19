from pathlib import Path

from uuid import uuid4

from logiclab.schemas import (
    Engagement,
    Finding,
    Invariant,
    RepositorySpec,
    RunStatus,
    Verification,
    VerificationDecision,
)
from logiclab.storage import Storage


TARGET_URL = "https://github.com/TrangTuanAnh/tls-anomaly-detection-ids.git"
TARGET_COMMIT = "bc593b186b50f5c832a92f6ea1cbad88747d78ac"


def make_storage(tmp_path: Path) -> Storage:
    storage = Storage(f"sqlite:///{tmp_path / 'logiclab.db'}")
    storage.create_schema()
    return storage


def make_engagement() -> Engagement:
    return Engagement(
        name="tls-ids",
        repository=RepositorySpec(url=TARGET_URL, commit=TARGET_COMMIT),
    )


def test_storage_round_trips_engagement_and_run(tmp_path: Path) -> None:
    storage = make_storage(tmp_path)
    engagement = storage.create_engagement(make_engagement())
    run = storage.create_run(engagement.id)
    assert storage.get_engagement(engagement.id) == engagement
    assert storage.get_run(run.id).status == RunStatus.QUEUED

    updated = storage.update_run(run.id, RunStatus.RUNNING)
    assert updated.status == RunStatus.RUNNING


def test_storage_round_trips_finding(tmp_path: Path) -> None:
    storage = make_storage(tmp_path)
    engagement = storage.create_engagement(make_engagement())
    invariant = Invariant(
        title="Rejected requests do not mutate state",
        expression="http.rejected implies db.diff == empty",
        expected_outcome={"nonce_delta": 0},
        evidence_refs=["backend/main.py:236"],
    )
    finding = Finding(
        engagement_id=engagement.id,
        hypothesis_id=invariant.id,
        title="Nonce inserted before HMAC verification",
        invariant=invariant,
    )
    storage.save_finding(finding)
    assert storage.get_finding(finding.id) == finding
    assert storage.list_findings(engagement.id) == [finding]


def test_storage_round_trips_independent_verification(tmp_path: Path) -> None:
    verification = Verification(
        hypothesis_id=uuid4(),
        decision=VerificationDecision.CONFIRMED,
        rationale="three independent replays",
        supporting_evidence_ids=[uuid4()],
        model="independent-verifier",
    )
    storage = make_storage(tmp_path)

    storage.save_verification(verification)

    assert storage.get_verification(verification.id) == verification
