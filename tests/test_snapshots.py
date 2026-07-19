import subprocess
from pathlib import Path

import pytest
from dulwich import porcelain
from dulwich.objects import Blob, Commit, Tree
from dulwich.repo import Repo

from logiclab.snapshots import (
    FetchLimits,
    GitSnapshotFetcher,
    GitSnapshotMaterializer,
    SnapshotLimits,
    SnapshotPolicyError,
    validate_repository_url,
)

GIT_MODE_REGULAR = 0o100644
GIT_MODE_SYMLINK = 0o120000
GIT_MODE_GITLINK = 0o160000
PUBLIC_ADDRESS = [(2, 1, 6, "", ("93.184.216.34", 443))]


def build_commit(root: Path, entries: list[tuple[bytes, int, bytes]]) -> tuple[Path, str]:
    """Create a repository whose root tree contains exactly the requested entries.

    Entries are written as raw Git objects so tests can pin file modes that
    porcelain would never produce on Windows, such as symlinks and gitlinks.
    """

    source = root / "source"
    source.mkdir()
    repository: Repo = porcelain.init(source)
    tree = Tree()
    for name, mode, payload in entries:
        blob = Blob.from_string(payload)
        repository.object_store.add_object(blob)
        tree.add(name, mode, blob.id)
    repository.object_store.add_object(tree)

    commit = Commit()
    commit.tree = tree.id
    commit.author = commit.committer = b"LogicLab Test <logiclab@example.invalid>"
    commit.commit_time = commit.author_time = 1700000000
    commit.commit_timezone = commit.author_timezone = 0
    commit.encoding = b"utf-8"
    commit.message = b"fixture"
    repository.object_store.add_object(commit)
    return source, commit.id.decode("ascii")


def make_repository(root: Path) -> tuple[Path, str]:
    source = root / "source"
    source.mkdir()
    repository = porcelain.init(source)
    (source / "pyproject.toml").write_text("[project]\nname='sample'\n", encoding="utf-8")
    (source / "src").mkdir()
    (source / "src" / "app.py").write_text("def hello():\n    return 'world'\n", encoding="utf-8")
    (source / "model.bin").write_bytes(b"\x00\x01\x02")
    porcelain.add(repository, paths=[b"pyproject.toml", b"src/app.py", b"model.bin"])
    commit = porcelain.commit(
        repository,
        message=b"fixture",
        author=b"LogicLab Test <logiclab@example.invalid>",
        committer=b"LogicLab Test <logiclab@example.invalid>",
    )
    return source, commit.decode("ascii")


def test_repository_url_policy_accepts_known_https_forges() -> None:
    assert validate_repository_url("https://github.com/acme/repo.git") == (
        "https://github.com/acme/repo.git"
    )
    assert validate_repository_url("https://gitlab.com/acme/repo.git").startswith("https://")


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/acme/repo.git",
        "https://user:secret@github.com/acme/repo.git",
        "https://127.0.0.1/acme/repo.git",
        "https://localhost/acme/repo.git",
        "file:///tmp/repo",
        "https://example.invalid/acme/repo.git",
    ],
)
def test_repository_url_policy_rejects_ssrf_and_unapproved_forges(url: str) -> None:
    with pytest.raises(SnapshotPolicyError):
        validate_repository_url(url)


def test_materializer_reads_pinned_tree_without_checking_out_binary_content(tmp_path: Path) -> None:
    source, commit = make_repository(tmp_path)
    result = GitSnapshotMaterializer().materialize(source, commit, tmp_path / "snapshot")

    assert result.commit == commit
    assert result.tree_digest.startswith("sha256:")
    assert result.materialized_paths == ["pyproject.toml", "src/app.py"]
    assert result.blob_sha256["src/app.py"] == result.blob_sha256["src/app.py"].lower()
    assert len(result.blob_sha256["src/app.py"]) == 64
    assert (result.root / "src" / "app.py").read_text(encoding="utf-8").startswith("def hello")
    assert not (result.root / "model.bin").exists()
    assert any(item.code == "BINARY_SKIPPED" for item in result.diagnostics)


def test_materializer_is_deterministic_and_enforces_limits(tmp_path: Path) -> None:
    source, commit = make_repository(tmp_path)
    materializer = GitSnapshotMaterializer()
    first = materializer.materialize(source, commit, tmp_path / "one")
    second = materializer.materialize(source, commit, tmp_path / "two")
    assert first.tree_digest == second.tree_digest

    with pytest.raises(SnapshotPolicyError, match="file limit"):
        GitSnapshotMaterializer(SnapshotLimits(max_files=1)).materialize(
            source, commit, tmp_path / "limited"
        )


def test_materializer_requires_exact_full_commit(tmp_path: Path) -> None:
    source, _ = make_repository(tmp_path)
    with pytest.raises(SnapshotPolicyError, match="40-character"):
        GitSnapshotMaterializer().materialize(source, "HEAD", tmp_path / "snapshot")


def test_fetcher_rejects_non_public_dns_before_starting_git(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "logiclab.snapshots.socket.getaddrinfo",
        lambda *_args, **_kwargs: [(2, 1, 6, "", ("127.0.0.1", 443))],
    )
    fetcher = GitSnapshotFetcher(tmp_path / "snapshots", fetch_limits=FetchLimits(max_seconds=1))

    with pytest.raises(SnapshotPolicyError, match="non-public"):
        fetcher.fetch("https://github.com/acme/repo.git", "a" * 40, "analysis-1")

    assert not (tmp_path / "snapshots" / "analysis-1").exists()


def test_fetcher_validates_commit_before_dns(monkeypatch, tmp_path: Path) -> None:
    resolver_called = False

    def resolver(*_args, **_kwargs):
        nonlocal resolver_called
        resolver_called = True
        return []

    monkeypatch.setattr("logiclab.snapshots.socket.getaddrinfo", resolver)
    fetcher = GitSnapshotFetcher(tmp_path / "snapshots")

    with pytest.raises(SnapshotPolicyError, match="40-character"):
        fetcher.fetch("https://github.com/acme/repo.git", "HEAD", "analysis-1")

    assert resolver_called is False


def test_materializer_never_writes_symlinks_or_submodules(tmp_path: Path) -> None:
    source, commit = build_commit(
        tmp_path,
        [
            (b"app.py", GIT_MODE_REGULAR, b"value = 1\n"),
            (b"escape.txt", GIT_MODE_SYMLINK, b"../../../../etc/passwd"),
            (b"vendor", GIT_MODE_GITLINK, b"unused"),
        ],
    )
    result = GitSnapshotMaterializer().materialize(source, commit, tmp_path / "snapshot")

    assert result.materialized_paths == ["app.py"]
    assert not (result.root / "escape.txt").exists()
    assert not (result.root / "vendor").exists()
    codes = {item.code for item in result.diagnostics}
    assert "SYMLINK_SKIPPED" in codes
    assert "NON_REGULAR_SKIPPED" in codes


@pytest.mark.parametrize(
    "name",
    [b".env", b"id_rsa", b"server.pem", b"private.key", b".env.production", b".npmrc"],
)
def test_materializer_excludes_secret_sensitive_files(tmp_path: Path, name: bytes) -> None:
    source, commit = build_commit(
        tmp_path,
        [(b"app.py", GIT_MODE_REGULAR, b"value = 1\n"), (name, GIT_MODE_REGULAR, b"SECRET=abc\n")],
    )
    result = GitSnapshotMaterializer().materialize(source, commit, tmp_path / "snapshot")

    assert result.materialized_paths == ["app.py"]
    assert not (result.root / name.decode()).exists()
    assert any(item.code == "SENSITIVE_PATH_SKIPPED" for item in result.diagnostics)


def test_materializer_skips_oversized_blobs_without_failing_the_snapshot(tmp_path: Path) -> None:
    source, commit = build_commit(
        tmp_path,
        [
            (b"app.py", GIT_MODE_REGULAR, b"value = 1\n"),
            (b"huge.txt", GIT_MODE_REGULAR, b"a" * 4096),
        ],
    )
    result = GitSnapshotMaterializer(SnapshotLimits(max_file_bytes=1024)).materialize(
        source, commit, tmp_path / "snapshot"
    )

    assert result.materialized_paths == ["app.py"]
    assert any(item.code == "OVERSIZED_SKIPPED" for item in result.diagnostics)


@pytest.mark.parametrize(
    ("name", "message"),
    [
        (b"..", "unsafe repository path"),
        (b"con.txt", "platform-unsafe path"),
        (b"stream:data", "platform-unsafe path"),
    ],
)
def test_materializer_rejects_hostile_paths(tmp_path: Path, name: bytes, message: str) -> None:
    source, commit = build_commit(tmp_path, [(name, GIT_MODE_REGULAR, b"payload\n")])

    with pytest.raises(SnapshotPolicyError, match=message):
        GitSnapshotMaterializer().materialize(source, commit, tmp_path / "snapshot")


def test_materializer_rejects_case_colliding_paths(tmp_path: Path) -> None:
    source, commit = build_commit(
        tmp_path,
        [(b"App.py", GIT_MODE_REGULAR, b"one\n"), (b"app.py", GIT_MODE_REGULAR, b"two\n")],
    )

    with pytest.raises(SnapshotPolicyError, match="case-colliding"):
        GitSnapshotMaterializer().materialize(source, commit, tmp_path / "snapshot")


def test_materializer_enforces_total_byte_and_path_budgets(tmp_path: Path) -> None:
    source, commit = build_commit(
        tmp_path,
        [(b"a.py", GIT_MODE_REGULAR, b"a" * 512), (b"b.py", GIT_MODE_REGULAR, b"b" * 512)],
    )

    with pytest.raises(SnapshotPolicyError, match="total byte limit"):
        GitSnapshotMaterializer(SnapshotLimits(max_total_bytes=600)).materialize(
            source, commit, tmp_path / "bytes"
        )

    with pytest.raises(SnapshotPolicyError, match="tree entry limit"):
        GitSnapshotMaterializer(SnapshotLimits(max_tree_entries=1)).materialize(
            source, commit, tmp_path / "entries"
        )

    with pytest.raises(SnapshotPolicyError, match="path limit"):
        GitSnapshotMaterializer(SnapshotLimits(max_path_length=2)).materialize(
            source, commit, tmp_path / "paths"
        )


def test_materializer_refuses_a_non_empty_destination(tmp_path: Path) -> None:
    source, commit = build_commit(tmp_path, [(b"app.py", GIT_MODE_REGULAR, b"value = 1\n")])
    destination = tmp_path / "snapshot"
    destination.mkdir()
    (destination / "leftover.txt").write_text("stale", encoding="utf-8")

    with pytest.raises(SnapshotPolicyError, match="must be empty"):
        GitSnapshotMaterializer().materialize(source, commit, destination)


def test_materializer_rejects_a_commit_missing_from_the_object_store(tmp_path: Path) -> None:
    source, _ = build_commit(tmp_path, [(b"app.py", GIT_MODE_REGULAR, b"value = 1\n")])

    with pytest.raises(SnapshotPolicyError, match="unavailable in repository object store"):
        GitSnapshotMaterializer().materialize(source, "b" * 40, tmp_path / "snapshot")


@pytest.mark.parametrize("key", ["../escape", "with space", "-leading", "a" * 129, ""])
def test_fetcher_rejects_unsafe_snapshot_keys(monkeypatch, tmp_path: Path, key: str) -> None:
    monkeypatch.setattr(
        "logiclab.snapshots.socket.getaddrinfo", lambda *_a, **_k: PUBLIC_ADDRESS
    )
    fetcher = GitSnapshotFetcher(tmp_path / "snapshots")

    with pytest.raises(SnapshotPolicyError, match="unsafe snapshot key"):
        fetcher.fetch("https://github.com/acme/repo.git", "a" * 40, key)


def test_fetcher_refuses_to_reuse_an_existing_snapshot_key(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "logiclab.snapshots.socket.getaddrinfo", lambda *_a, **_k: PUBLIC_ADDRESS
    )
    root = tmp_path / "snapshots"
    fetcher = GitSnapshotFetcher(root)
    (root / "analysis-1" / "tree").mkdir(parents=True)

    with pytest.raises(SnapshotPolicyError, match="already exists"):
        fetcher.fetch("https://github.com/acme/repo.git", "a" * 40, "analysis-1")


def test_fetcher_reports_missing_git_and_removes_the_partial_snapshot(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        "logiclab.snapshots.socket.getaddrinfo", lambda *_a, **_k: PUBLIC_ADDRESS
    )
    monkeypatch.setattr("logiclab.snapshots.shutil.which", lambda _name: None)
    root = tmp_path / "snapshots"
    fetcher = GitSnapshotFetcher(root)

    with pytest.raises(SnapshotPolicyError, match="Git is required"):
        fetcher.fetch("https://github.com/acme/repo.git", "a" * 40, "analysis-1")

    assert not (root / "analysis-1").exists()


def test_fetcher_resolution_failure_is_a_policy_error(monkeypatch, tmp_path: Path) -> None:
    def failing_resolver(*_args, **_kwargs):
        raise OSError("dns down")

    monkeypatch.setattr("logiclab.snapshots.socket.getaddrinfo", failing_resolver)
    fetcher = GitSnapshotFetcher(tmp_path / "snapshots")

    with pytest.raises(SnapshotPolicyError, match="could not be resolved"):
        fetcher.fetch("https://github.com/acme/repo.git", "a" * 40, "analysis-1")


def test_fetcher_kills_a_fetch_that_exceeds_its_wall_time(monkeypatch, tmp_path: Path) -> None:
    class NeverExitingProcess:
        pid = 424242
        returncode = None

        def poll(self) -> None:
            return None

    terminated: list[object] = []
    monkeypatch.setattr(
        "logiclab.snapshots.socket.getaddrinfo", lambda *_a, **_k: PUBLIC_ADDRESS
    )
    monkeypatch.setattr("logiclab.snapshots.shutil.which", lambda _name: "git")
    monkeypatch.setattr(
        "logiclab.snapshots.subprocess.run",
        lambda *_a, **_k: subprocess.CompletedProcess(args=[], returncode=0),
    )
    monkeypatch.setattr(
        "logiclab.snapshots.subprocess.Popen", lambda *_a, **_k: NeverExitingProcess()
    )
    monkeypatch.setattr(
        GitSnapshotFetcher, "_terminate_process_tree", staticmethod(terminated.append)
    )
    root = tmp_path / "snapshots"
    fetcher = GitSnapshotFetcher(
        root, fetch_limits=FetchLimits(max_seconds=0.05, poll_seconds=0.01)
    )

    with pytest.raises(SnapshotPolicyError, match="wall-time limit"):
        fetcher.fetch("https://github.com/acme/repo.git", "a" * 40, "analysis-1")

    assert len(terminated) == 1
    assert not (root / "analysis-1").exists()


def test_fetcher_kills_a_fetch_that_exceeds_its_disk_quota(monkeypatch, tmp_path: Path) -> None:
    class NeverExitingProcess:
        pid = 424243
        returncode = None

        def poll(self) -> None:
            return None

    terminated: list[object] = []
    monkeypatch.setattr(
        "logiclab.snapshots.socket.getaddrinfo", lambda *_a, **_k: PUBLIC_ADDRESS
    )
    monkeypatch.setattr("logiclab.snapshots.shutil.which", lambda _name: "git")
    monkeypatch.setattr(
        "logiclab.snapshots.subprocess.run",
        lambda *_a, **_k: subprocess.CompletedProcess(args=[], returncode=0),
    )
    monkeypatch.setattr(
        "logiclab.snapshots.subprocess.Popen", lambda *_a, **_k: NeverExitingProcess()
    )
    monkeypatch.setattr(
        GitSnapshotFetcher, "_terminate_process_tree", staticmethod(terminated.append)
    )
    monkeypatch.setattr(GitSnapshotFetcher, "_directory_bytes", staticmethod(lambda _root: 10_000))
    fetcher = GitSnapshotFetcher(
        tmp_path / "snapshots", fetch_limits=FetchLimits(max_fetch_bytes=1024, poll_seconds=0.01)
    )

    with pytest.raises(SnapshotPolicyError, match="disk quota"):
        fetcher.fetch("https://github.com/acme/repo.git", "a" * 40, "analysis-1")

    assert len(terminated) == 1


def test_fetcher_surfaces_a_failed_pinned_fetch(monkeypatch, tmp_path: Path) -> None:
    class FailedProcess:
        pid = 424244
        returncode = 128

        def poll(self) -> int:
            return 128

    monkeypatch.setattr(
        "logiclab.snapshots.socket.getaddrinfo", lambda *_a, **_k: PUBLIC_ADDRESS
    )
    monkeypatch.setattr("logiclab.snapshots.shutil.which", lambda _name: "git")
    monkeypatch.setattr(
        "logiclab.snapshots.subprocess.run",
        lambda *_a, **_k: subprocess.CompletedProcess(args=[], returncode=0),
    )
    monkeypatch.setattr("logiclab.snapshots.subprocess.Popen", lambda *_a, **_k: FailedProcess())
    root = tmp_path / "snapshots"
    fetcher = GitSnapshotFetcher(root)

    with pytest.raises(SnapshotPolicyError, match="pinned commit fetch failed"):
        fetcher.fetch("https://github.com/acme/repo.git", "a" * 40, "analysis-1")

    assert not (root / "analysis-1").exists()


def test_directory_bytes_counts_regular_files_only(tmp_path: Path) -> None:
    root = tmp_path / "objects"
    (root / "nested").mkdir(parents=True)
    (root / "nested" / "a.pack").write_bytes(b"x" * 100)
    (root / "b.idx").write_bytes(b"y" * 50)

    assert GitSnapshotFetcher._directory_bytes(root) == 150
