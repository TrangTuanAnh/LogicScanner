from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from uuid import UUID

from logiclab.artifacts import ArtifactStore
from logiclab.experiments import ExperimentRunner, LabSession
from logiclab.regression import RegressionGenerator
from logiclab.schemas import (
    ArtifactRef,
    Engagement,
    Experiment,
    Finding,
    FindingStatus,
    Hypothesis,
    Invariant,
    LabBlueprint,
    RunStatus,
    VerificationDecision,
    assert_status_transition,
)
from logiclab.storage import Storage
from logiclab.workspace import AnalyzerRegistry, TargetWorkspace


class Orchestrator:
    """Foreground workflow coordinator for a bounded LogicLab engagement."""

    def __init__(
        self,
        storage: Storage,
        artifacts: ArtifactStore,
        workspace: TargetWorkspace,
        registry: AnalyzerRegistry,
        hunter: object,
        verifier: object,
        lab_factory: Callable[[Path, LabBlueprint], LabSession],
        regression_generator: RegressionGenerator | None = None,
    ) -> None:
        self.storage = storage
        self.artifacts = artifacts
        self.workspace = workspace
        self.registry = registry
        self.hunter = hunter
        self.verifier = verifier
        self.lab_factory = lab_factory
        self.regressions = regression_generator or RegressionGenerator(artifacts)
        self.last_run_id: UUID | None = None

    def scan(
        self, engagement: Engagement, blueprint: LabBlueprint | dict[str, object]
    ) -> list[Finding]:
        """Create an engagement and execute its complete bounded scan."""
        if isinstance(blueprint, dict):
            blueprint = LabBlueprint.model_validate(blueprint)
        self.storage.create_engagement(engagement)
        run = self.storage.create_run(engagement.id)
        return self._execute(engagement, blueprint, run.id)

    def execute_existing_run(
        self, run_id: UUID, blueprint: LabBlueprint | dict[str, object]
    ) -> list[Finding]:
        if isinstance(blueprint, dict):
            blueprint = LabBlueprint.model_validate(blueprint)
        run = self.storage.get_run(run_id)
        if run.status is not RunStatus.QUEUED:
            raise ValueError(f"run {run_id} is not queued")
        engagement = self.storage.get_engagement(run.engagement_id)
        return self._execute(engagement, blueprint, run.id, replay_finding_id=run.finding_id)

    def _execute(
        self,
        engagement: Engagement,
        blueprint: LabBlueprint,
        run_id: UUID,
        replay_finding_id: UUID | None = None,
    ) -> list[Finding]:
        self.last_run_id = run_id
        self.storage.update_run(run_id, RunStatus.RUNNING)
        lab: LabSession | None = None
        try:
            target_root = self.workspace.prepare(engagement)
            if replay_finding_id is not None:
                return self._replay(
                    target_root,
                    blueprint,
                    replay_finding_id,
                    run_id,
                    engagement.limits.replay_count,
                )
            analysis = self.registry.scan(target_root)
            self.artifacts.put_json(
                "static-facts",
                {
                    "facts": [fact.model_dump(mode="json") for fact in analysis.facts],
                    "excluded_paths": analysis.excluded_paths,
                    "analyzed_paths": analysis.analyzed_paths,
                },
            )
            hypotheses = self.hunter.generate(analysis.facts)  # type: ignore[attr-defined]
            self._require_golden_experiments(hypotheses.hypotheses)
            lab = self.lab_factory(target_root, blueprint)
            runner = ExperimentRunner(lab, self.artifacts)
            findings = [
                self._run_hypothesis(engagement, hypothesis, hypotheses.invariants, runner)
                for hypothesis in hypotheses.hypotheses
            ]
            self.storage.update_run(run_id, RunStatus.COMPLETED)
            return findings
        except Exception as exc:
            self.storage.update_run(run_id, RunStatus.FAILED, error=self._safe_error(exc))
            raise
        finally:
            if lab is not None:
                stop = getattr(lab, "stop", None)
                if callable(stop):
                    stop()
                close = getattr(lab, "close", None)
                if callable(close):
                    close()

    def _run_hypothesis(
        self,
        engagement: Engagement,
        hypothesis: Hypothesis,
        invariants: list[Invariant],
        runner: ExperimentRunner,
    ) -> Finding:
        invariant = next(item for item in invariants if item.id == hypothesis.invariant_id)
        experiment = Experiment(
            hypothesis_id=hypothesis.id,
            kind=hypothesis.experiment_kind,
            replay_count=engagement.limits.replay_count,
        )
        result = runner.run(experiment)
        for evidence in result.evidence:
            self.storage.save_evidence(evidence)

        finding = Finding(
            engagement_id=engagement.id,
            hypothesis_id=hypothesis.id,
            experiment_kind=hypothesis.experiment_kind,
            title=hypothesis.title,
            invariant=invariant,
            evidence_ids=[item.id for item in result.evidence],
        )
        if not result.observed or not result.stable:
            return self._save_with_status(finding, FindingStatus.INCONCLUSIVE)

        finding = self._save_with_status(finding, FindingStatus.OBSERVED_ANOMALY)
        finding = self._save_with_status(finding, FindingStatus.REPRODUCIBLE_ANOMALY)
        finding = self._save_with_status(finding, FindingStatus.SUPPORTED_POLICY_VIOLATION)
        verification = self.verifier.verify(hypothesis, result.evidence)  # type: ignore[attr-defined]
        self.storage.save_verification(verification)
        status = {
            VerificationDecision.CONFIRMED: FindingStatus.SECURITY_CONFIRMED,
            VerificationDecision.CONFIGURATION_DEPENDENT: FindingStatus.CONFIGURATION_DEPENDENT,
            VerificationDecision.INCONCLUSIVE: FindingStatus.INCONCLUSIVE,
            VerificationDecision.REJECTED: FindingStatus.REJECTED,
        }[verification.decision]
        regression = self.regressions.generate(experiment.kind)
        finding = finding.model_copy(
            update={
                "verification_id": verification.id,
                "regression_artifact": ArtifactRef(
                    path=str(regression.path), sha256=regression.sha256, size=regression.size
                ),
            }
        )
        return self._save_with_status(finding, status)

    def _replay(
        self,
        target_root: Path,
        blueprint: LabBlueprint,
        finding_id: UUID,
        run_id: UUID,
        replay_count: int,
    ) -> list[Finding]:
        """Re-run only the persisted experiment kind, retaining prior finding state."""
        finding = self.storage.get_finding(finding_id)
        lab = self.lab_factory(target_root, blueprint)
        try:
            experiment = Experiment(
                hypothesis_id=finding.hypothesis_id,
                kind=finding.experiment_kind,
                replay_count=replay_count,
            )
            result = ExperimentRunner(lab, self.artifacts).run(experiment)
            for evidence in result.evidence:
                self.storage.save_evidence(evidence)
            finding = finding.model_copy(
                update={"evidence_ids": [*finding.evidence_ids, *(item.id for item in result.evidence)]}
            )
            self.storage.save_finding(finding)
            self.storage.update_run(run_id, RunStatus.COMPLETED)
            return [finding]
        finally:
            stop = getattr(lab, "stop", None)
            if callable(stop):
                stop()
            close = getattr(lab, "close", None)
            if callable(close):
                close()

    def _save_with_status(self, finding: Finding, status: FindingStatus) -> Finding:
        assert_status_transition(finding.status, status)
        updated = finding.model_copy(update={"status": status})
        return self.storage.save_finding(updated)

    @staticmethod
    def _require_golden_experiments(hypotheses: list[Hypothesis]) -> None:
        kinds = {hypothesis.experiment_kind.value for hypothesis in hypotheses}
        expected = {"trust_laundering", "hmac_nonce_mutation"}
        if kinds != expected:
            raise ValueError("Hunter must return exactly the two approved experiment kinds")

    @staticmethod
    def _safe_error(exc: Exception) -> str:
        return str(exc)[:500]
