from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from logiclab.artifacts import ArtifactStore
from logiclab.schemas import ArtifactRef, Evidence, EvidenceType, Experiment, ExperimentKind


@dataclass(frozen=True)
class HttpObservation:
    status_code: int
    body: dict[str, Any]


class LabSession(ABC):
    @abstractmethod
    def activate_profile(self, kind: ExperimentKind) -> None: ...

    @abstractmethod
    def reset(self) -> None: ...

    @abstractmethod
    def row_count(self, table: str, marker_ip: str | None = None) -> int: ...

    @abstractmethod
    def submit_untrusted_flow(self, marker_ip: str) -> HttpObservation: ...

    @abstractmethod
    def submit_bad_hmac(self) -> HttpObservation: ...


@dataclass(frozen=True)
class ExperimentResult:
    evidence: list[Evidence]
    observed: bool
    stable: bool


class ExperimentRunner:
    def __init__(self, lab: LabSession, artifacts: ArtifactStore) -> None:
        self.lab = lab
        self.artifacts = artifacts

    def run(self, experiment: Experiment) -> ExperimentResult:
        self.lab.activate_profile(experiment.kind)
        evidence: list[Evidence] = []
        observations: list[dict[str, Any]] = []
        for run_index in range(1, experiment.replay_count + 1):
            self.lab.reset()
            if experiment.kind == ExperimentKind.TRUST_LAUNDERING:
                observed, observation = self._run_trust_laundering(experiment)
            elif experiment.kind == ExperimentKind.HMAC_NONCE_MUTATION:
                observed, observation = self._run_hmac_nonce_mutation(experiment)
            else:  # defensive boundary for future schema versions
                raise ValueError(f"unsupported experiment kind: {experiment.kind}")
            observations.append(observation)
            stored = self.artifacts.put_json("evidence", observation)
            evidence.append(
                Evidence(
                    experiment_id=experiment.id,
                    run_index=run_index,
                    type=EvidenceType.DATABASE_DIFF,
                    summary=observation["summary"],
                    artifact=ArtifactRef(
                        path=str(stored.path), sha256=stored.sha256, size=stored.size
                    ),
                    source_refs=observation["source_refs"],
                )
            )
            if not observed:
                # Keep the remaining replays: a partial failure must become evidence, not a hidden abort.
                continue
        observed_all = all(item["expected"] == item["observed"] for item in observations)
        stable = len({item.artifact.sha256 for item in evidence}) == 1
        return ExperimentResult(evidence=evidence, observed=observed_all, stable=stable)

    def _run_trust_laundering(self, experiment: Experiment) -> tuple[bool, dict[str, Any]]:
        before = self.lab.row_count("flow_events", marker_ip=experiment.marker_ip)
        response = self.lab.submit_untrusted_flow(experiment.marker_ip)
        after = self.lab.row_count("flow_events", marker_ip=experiment.marker_ip)
        observed = {
            "http_status": response.status_code,
            "flow_event_delta": after - before,
        }
        expected = {"http_status": 200, "flow_event_delta": 1}
        return observed == expected, {
            "experiment_kind": experiment.kind.value,
            "marker_ip": experiment.marker_ip,
            "expected": expected,
            "observed": observed,
            "summary": "Tested whether an unauthenticated /flow request was accepted and persisted downstream.",
            "source_refs": [
                "python-real-time-service/main.py:204",
                "python-real-time-service/main.py:149",
            ],
        }

    def _run_hmac_nonce_mutation(self, experiment: Experiment) -> tuple[bool, dict[str, Any]]:
        before = self.lab.row_count("request_nonces")
        response = self.lab.submit_bad_hmac()
        after = self.lab.row_count("request_nonces")
        observed = {
            "http_status": response.status_code,
            "nonce_delta": after - before,
        }
        expected = {"http_status": 401, "nonce_delta": 1}
        return observed == expected, {
            "experiment_kind": experiment.kind.value,
            "expected": expected,
            "observed": observed,
            "summary": "Tested whether a rejected HMAC request persisted a nonce before signature verification.",
            "source_refs": ["backend/main.py:236", "backend/main.py:253"],
        }
