from __future__ import annotations

import shutil
from pathlib import Path
from typing import Annotated
from uuid import UUID

import typer
import uvicorn
from sqlalchemy.engine import make_url

from logiclab.api import create_app
from logiclab.artifacts import ArtifactStore
from logiclab.config import LEGACY_TARGET_COMMIT, LEGACY_TARGET_URL, Settings
from logiclab.lab import TargetLab
from logiclab.ollama import Hunter, ModelContractError, OllamaClient, Verifier
from logiclab.orchestrator import Orchestrator
from logiclab.profiles import load_blueprint, load_engagement
from logiclab.repository_analysis import (
    RepositoryAnalysisStatus,
    default_repository_analysis_manager,
)
from logiclab.schemas import Engagement, LabBlueprint, ModelPolicy
from logiclab.storage import Storage
from logiclab.workspace import AnalyzerRegistry, TargetWorkspace


app = typer.Typer(help="LogicLab local-first security-logic experiment engine.")
findings_app = typer.Typer(help="Inspect persisted findings.")
app.add_typer(findings_app, name="findings")


def _settings() -> Settings:
    return Settings()


def _orchestrator_for_engagement(
    settings: Settings, engagement: Engagement, blueprint: LabBlueprint
) -> tuple[Orchestrator, OllamaClient, OllamaClient]:
    if (
        engagement.repository.url != LEGACY_TARGET_URL
        or engagement.repository.commit != LEGACY_TARGET_COMMIT
    ):
        raise ModelContractError("legacy runtime is pinned to its reviewed target commit")
    storage = Storage(settings.database_url)
    storage.upgrade_schema()
    hunter_client = OllamaClient(engagement.models.base_url, engagement.models.timeout_seconds)
    verifier_client = OllamaClient(engagement.models.base_url, engagement.models.timeout_seconds)
    try:
        names = hunter_client.model_names()
        missing = {engagement.models.hunter_model, engagement.models.verifier_model} - names
        if missing:
            raise ModelContractError(
                "required Ollama models are unavailable: " + ", ".join(sorted(missing))
            )
    except Exception:
        hunter_client.close()
        verifier_client.close()
        raise
    orchestrator = Orchestrator(
        storage=storage,
        artifacts=ArtifactStore(settings.artifact_root),
        workspace=TargetWorkspace(settings.workspace_root),
        registry=AnalyzerRegistry.default(),
        hunter=Hunter(hunter_client, engagement.models.hunter_model),
        verifier=Verifier(verifier_client, engagement.models.verifier_model),
        lab_factory=lambda target_root, _: TargetLab(
            target_root, blueprint, settings.target_db_password
        ),
    )
    return orchestrator, hunter_client, verifier_client


def _orchestrator(
    settings: Settings, engagement_path: Path, blueprint_path: Path
) -> tuple[Orchestrator, OllamaClient, OllamaClient]:
    return _orchestrator_for_engagement(
        settings, load_engagement(engagement_path), load_blueprint(blueprint_path)
    )


def _default_blueprint(engagement_path: Path, settings: Settings) -> Path:
    adjacent = engagement_path.with_name(f"{engagement_path.stem}-lab.yaml")
    return adjacent if adjacent.is_file() else settings.default_lab_blueprint


@app.command()
def doctor() -> None:
    """Report local prerequisites without running a target command."""
    settings = _settings()
    tools = {name: shutil.which(name) is not None for name in ("git", "docker")}
    typer.echo(f"git: {'ok' if tools['git'] else 'missing'}")
    typer.echo(f"docker: {'ok' if tools['docker'] else 'missing'}")
    try:
        client = OllamaClient("http://127.0.0.1:11434", 5)
        models = client.model_names()
        client.close()
        required = {ModelPolicy().hunter_model, ModelPolicy().verifier_model}
        missing = required - models
        if missing:
            typer.echo("ollama: missing required models: " + ", ".join(sorted(missing)))
            tools["ollama"] = False
        else:
            typer.echo(f"ollama: ok ({len(models)} models)")
            tools["ollama"] = True
    except Exception:
        typer.echo("ollama: unavailable at http://127.0.0.1:11434")
        tools["ollama"] = False
    typer.echo(
        f"control-db: {make_url(settings.database_url).render_as_string(hide_password=True)}"
    )
    if not all(tools.values()):
        raise typer.Exit(code=1)


@app.command()
def scan(
    engagement: Annotated[Path, typer.Argument(exists=True, readable=True)],
    blueprint: Annotated[Path | None, typer.Option()] = None,
) -> None:
    """Run clone, facts, model hypotheses, lab experiments and verification foreground."""
    settings = _settings()
    blueprint_path = blueprint or _default_blueprint(engagement, settings)
    if not blueprint_path.is_file():
        raise typer.BadParameter(f"lab blueprint not found: {blueprint_path}")
    hunter_client: OllamaClient | None = None
    verifier_client: OllamaClient | None = None
    try:
        orchestrator, hunter_client, verifier_client = _orchestrator(
            settings, engagement, blueprint_path
        )
        findings = orchestrator.scan(load_engagement(engagement), load_blueprint(blueprint_path))
        typer.echo(f"run: {orchestrator.last_run_id}")
        for finding in findings:
            typer.echo(f"{finding.id} {finding.status.value} {finding.title}")
    finally:
        if hunter_client is not None:
            hunter_client.close()
        if verifier_client is not None:
            verifier_client.close()


@app.command()
def serve() -> None:
    """Serve the local bearer-token protected REST API."""
    settings = _settings()
    uvicorn.run(create_app(settings), host=settings.api_host, port=settings.api_port)


@app.command("analysis-worker")
def analysis_worker(
    once: Annotated[bool, typer.Option(help="Process at most one queued analysis.")] = True,
) -> None:
    """Resume durable repository-analysis jobs left in the control database."""
    settings = _settings()
    storage = Storage(settings.database_url)
    storage.upgrade_schema()
    manager = default_repository_analysis_manager(storage, settings.workspace_root)
    queued = storage.list_repository_analyses_by_status(
        RepositoryAnalysisStatus.QUEUED.value,
        limit=1 if once else 100,
    )
    if not queued:
        typer.echo("no queued repository analyses")
        return
    for analysis in queued:
        completed = manager.process(analysis.id)
        typer.echo(f"{completed.id} {completed.status.value}")


@app.command()
def worker(
    blueprint: Annotated[Path | None, typer.Option()] = None,
    once: Annotated[bool, typer.Option(help="Process at most one queued run.")] = True,
) -> None:
    """Process queued API runs using the fixed TLS IDS blueprint."""
    settings = _settings()
    if not settings.legacy_runtime_enabled:
        raise typer.BadParameter(
            "legacy runtime is disabled; set LOGICLAB_LEGACY_RUNTIME_ENABLED=true explicitly"
        )
    blueprint_path = blueprint or settings.default_lab_blueprint
    lab_blueprint = load_blueprint(blueprint_path)
    storage = Storage(settings.database_url)
    storage.upgrade_schema()
    queued = storage.list_queued_runs(limit=1 if once else 100)
    if not queued:
        typer.echo("no queued runs")
        return
    # The engagement defines the approved Ollama endpoint and model pair.
    for run in queued:
        engagement = storage.get_engagement(run.engagement_id)
        hunter_client: OllamaClient | None = None
        verifier_client: OllamaClient | None = None
        try:
            orchestrator, hunter_client, verifier_client = _orchestrator_for_engagement(
                settings, engagement, lab_blueprint
            )
            orchestrator.execute_existing_run(run.id, lab_blueprint)
            typer.echo(f"completed: {run.id}")
        finally:
            if hunter_client is not None:
                hunter_client.close()
            if verifier_client is not None:
                verifier_client.close()


@app.command()
def replay(
    finding_id: UUID,
    blueprint: Annotated[Path | None, typer.Option()] = None,
) -> None:
    """Execute a clean replay of one persisted finding."""
    settings = _settings()
    if not settings.legacy_runtime_enabled:
        raise typer.BadParameter(
            "legacy runtime is disabled; set LOGICLAB_LEGACY_RUNTIME_ENABLED=true explicitly"
        )
    blueprint_path = blueprint or settings.default_lab_blueprint
    storage = Storage(settings.database_url)
    storage.upgrade_schema()
    try:
        finding = storage.get_finding(finding_id)
    except KeyError as exc:
        raise typer.BadParameter(str(exc)) from exc
    run = storage.create_run(finding.engagement_id, finding_id=finding.id)
    engagement = storage.get_engagement(finding.engagement_id)
    lab_blueprint = load_blueprint(blueprint_path)
    hunter_client: OllamaClient | None = None
    verifier_client: OllamaClient | None = None
    try:
        orchestrator, hunter_client, verifier_client = _orchestrator_for_engagement(
            settings, engagement, lab_blueprint
        )
        orchestrator.execute_existing_run(run.id, lab_blueprint)
        typer.echo(f"completed replay: {run.id}")
    finally:
        if hunter_client is not None:
            hunter_client.close()
        if verifier_client is not None:
            verifier_client.close()


@findings_app.command("show")
def findings_show(finding_id: UUID) -> None:
    """Print one persisted finding as JSON."""
    storage = Storage(_settings().database_url)
    storage.upgrade_schema()
    try:
        typer.echo(storage.get_finding(finding_id).model_dump_json(indent=2))
    except KeyError as exc:
        raise typer.BadParameter(str(exc)) from exc
