from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from typer.testing import CliRunner

from logiclab import cli
from logiclab.cli import app
from logiclab.config import Settings
from logiclab.schemas import Engagement, Run


def test_cli_exposes_public_commands() -> None:
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in (
        "analysis-worker",
        "doctor",
        "scan",
        "serve",
        "worker",
        "replay",
        "findings",
    ):
        assert command in result.output


class Closable:
    def close(self) -> None:
        pass


def test_doctor_reports_local_dependencies(monkeypatch, tmp_path: Path) -> None:
    class FakeOllama:
        def __init__(self, *args) -> None:
            pass

        def model_names(self):
            return {"qwen3-coder:30b", "gpt-oss:20b"}

        def close(self) -> None:
            pass

    settings = Settings(database_url=f"sqlite:///{tmp_path / 'db.sqlite'}")
    monkeypatch.setattr(cli, "_settings", lambda: settings)
    monkeypatch.setattr(cli.shutil, "which", lambda _: "present")
    monkeypatch.setattr(cli, "OllamaClient", FakeOllama)
    result = CliRunner().invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "ollama: ok" in result.output


def test_scan_command_delegates_to_foreground_orchestrator(monkeypatch, tmp_path: Path) -> None:
    engagement_path = Path("engagements/tls-ids.yaml")
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'db.sqlite'}",
        legacy_runtime_enabled=True,
    )
    fake = SimpleNamespace(
        last_run_id=uuid4(),
        scan=lambda engagement, blueprint: [
            SimpleNamespace(id=uuid4(), status=SimpleNamespace(value="INCONCLUSIVE"), title="test")
        ],
    )
    monkeypatch.setattr(cli, "_settings", lambda: settings)
    monkeypatch.setattr(cli, "_orchestrator", lambda *_: (fake, Closable(), Closable()))
    result = CliRunner().invoke(app, ["scan", str(engagement_path)])
    assert result.exit_code == 0
    assert "INCONCLUSIVE test" in result.output


def test_analysis_worker_reports_empty_durable_queue(monkeypatch, tmp_path: Path) -> None:
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'analysis-worker.db'}")
    monkeypatch.setattr(cli, "_settings", lambda: settings)

    result = CliRunner().invoke(app, ["analysis-worker"])

    assert result.exit_code == 0
    assert "no queued repository analyses" in result.output


def test_worker_and_replay_execute_queued_runs(monkeypatch, tmp_path: Path) -> None:
    engagement = Engagement(
        name="tls",
        repository={
            "url": "https://github.com/TrangTuanAnh/tls-anomaly-detection-ids.git",
            "commit": "bc593b186b50f5c832a92f6ea1cbad88747d78ac",
        },
    )
    finding = SimpleNamespace(id=uuid4(), engagement_id=engagement.id)
    run = Run(engagement_id=engagement.id, finding_id=finding.id)

    class FakeStorage:
        def __init__(self, *args) -> None:
            self.created = []

        def upgrade_schema(self) -> None:
            pass

        def list_queued_runs(self, limit: int):
            return [run]

        def get_engagement(self, engagement_id):
            return engagement

        def get_finding(self, finding_id):
            return finding

        def create_run(self, engagement_id, finding_id=None):
            self.created.append((engagement_id, finding_id))
            return run

    fake_storage = FakeStorage()
    executed = []
    fake_orchestrator = SimpleNamespace(
        execute_existing_run=lambda run_id, blueprint: executed.append(run_id)
    )
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'db.sqlite'}",
        legacy_runtime_enabled=True,
    )
    monkeypatch.setattr(cli, "_settings", lambda: settings)
    monkeypatch.setattr(cli, "Storage", lambda _: fake_storage)
    monkeypatch.setattr(
        cli, "_orchestrator_for_engagement", lambda *_: (fake_orchestrator, Closable(), Closable())
    )

    worker = CliRunner().invoke(app, ["worker", "--blueprint", "engagements/tls-ids-lab.yaml"])
    replay = CliRunner().invoke(
        app, ["replay", str(finding.id), "--blueprint", "engagements/tls-ids-lab.yaml"]
    )
    assert worker.exit_code == 0
    assert replay.exit_code == 0
    assert executed == [run.id, run.id]
