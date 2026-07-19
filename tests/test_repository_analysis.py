from __future__ import annotations

from pathlib import Path

from dulwich import porcelain
from fastapi.testclient import TestClient

from logiclab.api import create_app
from logiclab.config import Settings
from logiclab.intelligence import AnalysisStatus
from logiclab.repository_analysis import (
    RepositoryAnalysis,
    RepositoryAnalysisManager,
    RepositoryAnalysisRequest,
    RepositoryAnalysisStatus,
)
from logiclab.snapshots import GitSnapshotMaterializer, SnapshotPolicyError
from logiclab.storage import Storage


class LocalFetcher:
    def __init__(self, source: Path, destination_root: Path) -> None:
        self.source = source
        self.destination_root = destination_root

    def fetch(self, repository_url: str, commit: str, snapshot_key: str):
        return GitSnapshotMaterializer().materialize(
            self.source, commit, self.destination_root / snapshot_key
        )


class BrokenFetcher:
    def fetch(self, repository_url: str, commit: str, snapshot_key: str):
        raise SnapshotPolicyError("repository was denied by static fetch policy")


def make_repository(root: Path, *, include_binary_omission: bool = False) -> tuple[Path, str]:
    source = root / "repository"
    source.mkdir()
    repository = porcelain.init(source)
    (source / "pyproject.toml").write_text("[project]\nname='universal'\n", encoding="utf-8")
    (source / "app.py").write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/health')\n"
        "def health(): return {'status': 'ok'}\n"
        "@app.post('/items')\n"
        "def create_item(): return {'created': True}\n"
        "def helper(): return 'helper'\n",
        encoding="utf-8",
    )
    tracked = [b"pyproject.toml", b"app.py"]
    if include_binary_omission:
        (source / "firmware.bin").write_bytes(b"\x00\x01\x02")
        tracked.append(b"firmware.bin")
    porcelain.add(repository, paths=tracked)
    commit = porcelain.commit(
        repository,
        message=b"universal fixture",
        author=b"LogicLab <logiclab@example.invalid>",
        committer=b"LogicLab <logiclab@example.invalid>",
    )
    return source, commit.decode("ascii")


def request(commit: str) -> RepositoryAnalysisRequest:
    return RepositoryAnalysisRequest(
        name="Universal fixture",
        repository_url="https://github.com/acme/universal.git",
        commit=commit,
    )


def test_manager_persists_static_report_agent_dag_and_provenance(tmp_path: Path) -> None:
    source, commit = make_repository(tmp_path)
    storage = Storage(f"sqlite:///{tmp_path / 'control.db'}")
    storage.create_schema()
    manager = RepositoryAnalysisManager(
        storage=storage,
        fetcher=LocalFetcher(source, tmp_path / "snapshots"),
    )

    analysis = manager.create(request(commit))
    response = analysis.to_response()

    assert analysis.status is RepositoryAnalysisStatus.READY
    assert analysis.report is not None
    assert response.capabilities.understanding.label == "U2"
    assert response.capabilities.runtime.label in {"R0", "R1"}
    assert response.capabilities.coverage.score == 100
    assert {item.agent for item in response.agent_tasks} >= {
        "repo_surveyor",
        "architecture_mapper",
        "twin_synthesizer",
        "independent_skeptic",
    }
    assert any(item.predicate == "declares" for item in response.claims)
    assert all(item.source_refs for item in response.claims)
    assert analysis.disputed_claim_ids == []
    assert {item.status for item in response.claims} == {"derived"}
    assert response.snapshot_digest == analysis.snapshot_digest
    assert response.provenance
    assert all(source.sha256 for item in response.provenance for source in item.sources)
    assert storage.get_repository_analysis(analysis.id).snapshot_digest == analysis.snapshot_digest
    assert [item.id for item in storage.list_repository_analyses()] == [analysis.id]


def test_manager_propagates_snapshot_omissions_into_partial_coverage(
    tmp_path: Path,
) -> None:
    source, commit = make_repository(tmp_path, include_binary_omission=True)
    storage = Storage(f"sqlite:///{tmp_path / 'control.db'}")
    storage.create_schema()
    manager = RepositoryAnalysisManager(
        storage=storage,
        fetcher=LocalFetcher(source, tmp_path / "snapshots"),
    )

    analysis = manager.create(request(commit))
    response = analysis.to_response()

    assert analysis.status is RepositoryAnalysisStatus.NEEDS_REVIEW
    assert analysis.report is not None
    assert analysis.report.status is AnalysisStatus.PARTIAL
    assert analysis.report.coverage.snapshot_omissions == 1
    assert analysis.report.coverage.unsupported_files == 1
    assert analysis.report.coverage.analysis_percent < 100
    assert {item.path for item in analysis.report.unsupported_zones} == {"firmware.bin"}
    assert any(item.code == "snapshot.binary_skipped" for item in analysis.report.diagnostics)
    assert any(item.path == "firmware.bin" for item in response.diagnostics)


def test_manager_persists_policy_failure_as_safe_terminal_state(tmp_path: Path) -> None:
    storage = Storage(f"sqlite:///{tmp_path / 'control.db'}")
    storage.create_schema()
    manager = RepositoryAnalysisManager(storage=storage, fetcher=BrokenFetcher())

    analysis = manager.create(request("a" * 40))

    assert analysis.status is RepositoryAnalysisStatus.FAILED
    assert analysis.error_code == "SNAPSHOT_POLICY_DENIED"
    assert "denied" in (analysis.error_message or "")
    assert analysis.report is None


def test_repository_analysis_claim_is_atomic(tmp_path: Path) -> None:
    storage = Storage(f"sqlite:///{tmp_path / 'claims.db'}")
    storage.create_schema()
    analysis = storage.create_repository_analysis(
        RepositoryAnalysis(
            name="atomic",
            repository_url="https://github.com/acme/atomic.git",
            commit="a" * 40,
        )
    )

    first = storage.claim_repository_analysis(analysis.id)
    second = storage.claim_repository_analysis(analysis.id)

    assert first is not None
    assert first.status is RepositoryAnalysisStatus.FETCHING
    assert second is None


def test_repository_analysis_api_drives_the_static_vertical_slice(tmp_path: Path) -> None:
    source, commit = make_repository(tmp_path)
    database_url = f"sqlite:///{tmp_path / 'api.db'}"
    storage = Storage(database_url)
    storage.create_schema()
    manager = RepositoryAnalysisManager(
        storage=storage,
        fetcher=LocalFetcher(source, tmp_path / "snapshots"),
    )
    settings = Settings(
        database_url=database_url,
        api_token="universal-test-token",
        development_mode=True,
        artifact_root=tmp_path / "artifacts",
        workspace_root=tmp_path / "workspaces",
    )
    client = TestClient(create_app(settings, storage, analysis_manager=manager))
    headers = {"Authorization": "Bearer universal-test-token"}

    created = client.post(
        "/v1/repository-analyses",
        headers=headers,
        json=request(commit).model_dump(mode="json"),
    )
    assert created.status_code == 202
    analysis_id = created.json()["id"]
    assert created.json()["status"] == "queued"

    detail = client.get(f"/v1/repository-analyses/{analysis_id}", headers=headers)
    assert detail.status_code == 200
    assert detail.json()["status"] == "ready"

    collection = client.get("/v1/repository-analyses", headers=headers)
    assert collection.status_code == 200
    assert collection.json()["total"] == 1
    assert collection.json()["items"][0]["id"] == analysis_id
    detail = client.get(f"/v1/repository-analyses/{analysis_id}", headers=headers)
    assert detail.json()["capabilities"]["understanding"]["label"] == "U2"
