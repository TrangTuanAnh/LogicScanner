from dataclasses import dataclass, field
from pathlib import Path
from uuid import uuid4

from logiclab.artifacts import ArtifactStore
from logiclab.experiments import ExperimentRunner, HttpObservation, LabSession
from logiclab.schemas import Experiment, ExperimentKind


@dataclass
class FakeLab(LabSession):
    flow_events: int = 0
    nonces: int = 0
    resets: int = 0
    profiles: list[ExperimentKind] = field(default_factory=list)

    def activate_profile(self, kind: ExperimentKind) -> None:
        self.profiles.append(kind)

    def reset(self) -> None:
        self.flow_events = 0
        self.nonces = 0
        self.resets += 1

    def row_count(self, table: str, marker_ip: str | None = None) -> int:
        return self.flow_events if table == "flow_events" else self.nonces

    def submit_untrusted_flow(self, marker_ip: str) -> HttpObservation:
        self.flow_events += 1
        return HttpObservation(status_code=200, body={"ok": True, "accepted": 1})

    def submit_bad_hmac(self) -> HttpObservation:
        self.nonces += 1
        return HttpObservation(status_code=401, body={"detail": "Bad signature"})


def test_trust_laundering_experiment_replays_stably(tmp_path: Path) -> None:
    lab = FakeLab()
    experiment = Experiment(
        hypothesis_id=uuid4(), kind=ExperimentKind.TRUST_LAUNDERING, replay_count=3
    )
    result = ExperimentRunner(lab, ArtifactStore(tmp_path)).run(experiment)
    assert result.observed is True
    assert result.stable is True
    assert lab.resets == 3
    assert {item.artifact.sha256 for item in result.evidence}.__len__() == 1


def test_hmac_experiment_requires_401_and_nonce_mutation(tmp_path: Path) -> None:
    lab = FakeLab()
    experiment = Experiment(
        hypothesis_id=uuid4(), kind=ExperimentKind.HMAC_NONCE_MUTATION, replay_count=3
    )
    result = ExperimentRunner(lab, ArtifactStore(tmp_path)).run(experiment)
    assert result.observed is True
    assert all(item.type.value == "database_diff" for item in result.evidence)
