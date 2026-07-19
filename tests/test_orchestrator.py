from dataclasses import dataclass
from pathlib import Path
from logiclab.artifacts import ArtifactStore
from logiclab.experiments import HttpObservation, LabSession
from logiclab.orchestrator import Orchestrator
from logiclab.schemas import (
    Engagement,
    ExperimentKind,
    FactKind,
    Hypothesis,
    HypothesisSet,
    Invariant,
    RunStatus,
    StaticFact,
    Verification,
    VerificationDecision,
)
from logiclab.storage import Storage
from logiclab.workspace import AnalysisResult


class FakeWorkspace:
    def __init__(self, root: Path) -> None:
        self.root = root

    def prepare(self, engagement: Engagement) -> Path:
        return self.root


class FakeRegistry:
    def scan(self, root: Path) -> AnalysisResult:
        return AnalysisResult(
            facts=[
                StaticFact(
                    kind=FactKind.ENTRY_POINT,
                    subject="POST /flow",
                    source_path="python-real-time-service/main.py",
                    line=204,
                )
            ],
            excluded_paths=[],
            analyzed_paths=["python-real-time-service/main.py"],
        )


class FakeHunter:
    def generate(self, facts: list[StaticFact]) -> HypothesisSet:
        invariant = Invariant(
            title="ingress is authenticated",
            expression="untrusted requests cannot create a flow event",
            expected_outcome={"status": 401},
            evidence_refs=["python-real-time-service/main.py:204"],
        )
        return HypothesisSet(
            invariants=[invariant],
            hypotheses=[
                Hypothesis(
                    invariant_id=invariant.id,
                    title="trust laundering",
                    rationale="test",
                    candidate_entry_point="POST /flow",
                    experiment_kind=ExperimentKind.TRUST_LAUNDERING,
                    source_refs=["python-real-time-service/main.py:204"],
                ),
                Hypothesis(
                    invariant_id=invariant.id,
                    title="nonce order",
                    rationale="test",
                    candidate_entry_point="POST /api/events",
                    experiment_kind=ExperimentKind.HMAC_NONCE_MUTATION,
                    source_refs=["python-real-time-service/main.py:204"],
                ),
            ],
        )


class FakeVerifier:
    model = "verifier"

    def verify(self, hypothesis, evidence):
        return Verification(
            hypothesis_id=hypothesis.id,
            decision=VerificationDecision.CONFIRMED,
            rationale="three stable replays",
            supporting_evidence_ids=[item.id for item in evidence],
            model=self.model,
        )


@dataclass
class FakeLab(LabSession):
    flows: int = 0
    nonces: int = 0

    def activate_profile(self, kind: ExperimentKind) -> None:
        self.kind = kind

    def reset(self) -> None:
        self.flows = 0
        self.nonces = 0

    def row_count(self, table: str, marker_ip: str | None = None) -> int:
        return self.flows if table == "flow_events" else self.nonces

    def submit_untrusted_flow(self, marker_ip: str) -> HttpObservation:
        self.flows += 1
        return HttpObservation(200, {"ok": True})

    def submit_bad_hmac(self) -> HttpObservation:
        # Matches the real target's current HMAC runtime failure.
        return HttpObservation(500, {"detail": "Pydantic incompatibility"})

    def stop(self) -> None:
        pass

    def close(self) -> None:
        pass


def test_orchestrator_confirms_only_stable_observed_findings(tmp_path: Path) -> None:
    storage = Storage(f"sqlite:///{tmp_path / 'logiclab.db'}")
    storage.create_schema()
    orchestrator = Orchestrator(
        storage=storage,
        artifacts=ArtifactStore(tmp_path / "artifacts"),
        workspace=FakeWorkspace(tmp_path),
        registry=FakeRegistry(),
        hunter=FakeHunter(),
        verifier=FakeVerifier(),
        lab_factory=lambda root, blueprint: FakeLab(),
    )
    engagement = Engagement(
        name="test",
        repository={
            "url": "https://github.com/TrangTuanAnh/tls-anomaly-detection-ids.git",
            "commit": "bc593b186b50f5c832a92f6ea1cbad88747d78ac",
        },
    )
    findings = orchestrator.scan(engagement, blueprint={"services": []})

    assert len(findings) == 2
    assert {finding.status.value for finding in findings} == {"SECURITY_CONFIRMED", "INCONCLUSIVE"}
    assert storage.get_run(orchestrator.last_run_id).status.value == "COMPLETED"
    confirmed = next(item for item in findings if item.status.value == "SECURITY_CONFIRMED")
    assert confirmed.verification_id is not None
    assert storage.get_verification(confirmed.verification_id).decision is VerificationDecision.CONFIRMED


def test_replay_links_new_evidence_to_the_existing_finding(tmp_path: Path) -> None:
    storage = Storage(f"sqlite:///{tmp_path / 'logiclab.db'}")
    storage.create_schema()
    orchestrator = Orchestrator(
        storage=storage,
        artifacts=ArtifactStore(tmp_path / "artifacts"),
        workspace=FakeWorkspace(tmp_path),
        registry=FakeRegistry(),
        hunter=FakeHunter(),
        verifier=FakeVerifier(),
        lab_factory=lambda root, blueprint: FakeLab(),
    )
    engagement = Engagement(
        name="test",
        repository={
            "url": "https://github.com/TrangTuanAnh/tls-anomaly-detection-ids.git",
            "commit": "bc593b186b50f5c832a92f6ea1cbad88747d78ac",
        },
    )
    findings = orchestrator.scan(engagement, blueprint={"services": []})
    original = next(item for item in findings if item.experiment_kind is ExperimentKind.TRUST_LAUNDERING)
    replay = storage.create_run(engagement.id, finding_id=original.id)

    orchestrator.execute_existing_run(replay.id, blueprint={"services": []})

    updated = storage.get_finding(original.id)
    assert len(updated.evidence_ids) == len(original.evidence_ids) + engagement.limits.replay_count
    assert storage.get_run(replay.id).status is RunStatus.COMPLETED
