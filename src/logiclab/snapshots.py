from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import shutil
import socket
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit, urlunsplit

from dulwich.objects import Blob, Commit, Tree
from dulwich.repo import Repo
from pydantic import BaseModel, ConfigDict, Field


FULL_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
DEFAULT_FORGE_HOSTS = frozenset({"github.com", "gitlab.com", "bitbucket.org", "codeberg.org"})
_WINDOWS_RESERVED = {
    "aux",
    "con",
    "nul",
    "prn",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}
_SENSITIVE_NAMES = {".env", ".npmrc", ".pypirc", "id_rsa", "id_ed25519"}
_SENSITIVE_SUFFIXES = {".key", ".p12", ".pfx", ".pem"}


class SnapshotPolicyError(ValueError):
    """Raised when repository input crosses the static-ingestion policy."""


class SnapshotDiagnostic(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    path: str | None = None
    detail: str


class SnapshotResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    root: Path
    commit: str
    tree_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    materialized_paths: list[str]
    blob_sha256: dict[str, str] = Field(default_factory=dict)
    diagnostics: list[SnapshotDiagnostic]


@dataclass(frozen=True)
class SnapshotLimits:
    max_files: int = 100_000
    max_tree_entries: int = 200_000
    max_file_bytes: int = 1_000_000
    max_total_bytes: int = 250_000_000
    max_path_length: int = 512
    max_path_depth: int = 40

    def __post_init__(self) -> None:
        if (
            min(
                self.max_files,
                self.max_tree_entries,
                self.max_file_bytes,
                self.max_total_bytes,
                self.max_path_length,
                self.max_path_depth,
            )
            < 1
        ):
            raise ValueError("snapshot limits must be positive")


@dataclass(frozen=True)
class FetchLimits:
    max_seconds: float = 120.0
    max_fetch_bytes: int = 512_000_000
    poll_seconds: float = 0.1

    def __post_init__(self) -> None:
        if min(self.max_seconds, self.max_fetch_bytes, self.poll_seconds) <= 0:
            raise ValueError("fetch limits must be positive")


def validate_repository_url(value: str, allowed_hosts: frozenset[str] = DEFAULT_FORGE_HOSTS) -> str:
    """Validate a public HTTPS forge URL without performing a network lookup.

    DNS pinning and connect-time address validation belong to the isolated fetcher.
    The control-plane contract remains intentionally narrower than an arbitrary URL.
    """

    parsed = urlsplit(value.strip())
    if parsed.scheme != "https" or parsed.username or parsed.password:
        raise SnapshotPolicyError("repository URL must be credential-free HTTPS")
    if parsed.port not in {None, 443}:
        raise SnapshotPolicyError("repository URL must use port 443")
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if not hostname or hostname not in allowed_hosts:
        raise SnapshotPolicyError("repository host is not allowlisted")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        if not address.is_global:
            raise SnapshotPolicyError("repository URL resolves to a non-public literal address")
    if not parsed.path or parsed.path == "/":
        raise SnapshotPolicyError("repository URL must identify a repository")
    return urlunsplit(("https", hostname, parsed.path.rstrip("/"), "", ""))


class GitSnapshotMaterializer:
    """Materialize regular text blobs from an exact Git tree without checkout.

    Git hooks, filters, submodules, and symlinks are never evaluated. Repository
    content remains untrusted and is only copied into a dedicated snapshot root.
    """

    def __init__(self, limits: SnapshotLimits | None = None) -> None:
        self.limits = limits or SnapshotLimits()

    def materialize(self, repository_path: Path, commit: str, destination: Path) -> SnapshotResult:
        if not FULL_SHA_RE.fullmatch(commit):
            raise SnapshotPolicyError("snapshot requires a full 40-character commit SHA")
        repository = Repo(str(repository_path.resolve()))
        try:
            commit_object = repository[commit.lower().encode("ascii")]
        except KeyError as exc:
            raise SnapshotPolicyError("commit is unavailable in repository object store") from exc
        if not isinstance(commit_object, Commit):
            raise SnapshotPolicyError("pinned object is not a commit")
        tree = repository[commit_object.tree]
        if not isinstance(tree, Tree):
            raise SnapshotPolicyError("commit does not reference a Git tree")

        root = destination.resolve()
        if root.exists() and any(root.iterdir()):
            raise SnapshotPolicyError("snapshot destination must be empty")
        root.mkdir(parents=True, exist_ok=True)

        diagnostics: list[SnapshotDiagnostic] = []
        materialized: list[str] = []
        blob_sha256: dict[str, str] = {}
        seen_casefolded: set[str] = set()
        digest = hashlib.sha256()
        state = {"files": 0, "entries": 0, "bytes": 0}
        self._walk(
            repository,
            tree,
            PurePosixPath(),
            root,
            diagnostics,
            materialized,
            blob_sha256,
            seen_casefolded,
            digest,
            state,
        )
        return SnapshotResult(
            root=root,
            commit=commit.lower(),
            tree_digest="sha256:" + digest.hexdigest(),
            materialized_paths=sorted(materialized),
            blob_sha256=dict(sorted(blob_sha256.items())),
            diagnostics=diagnostics,
        )

    def _walk(
        self,
        repository: Repo,
        tree: Tree,
        prefix: PurePosixPath,
        root: Path,
        diagnostics: list[SnapshotDiagnostic],
        materialized: list[str],
        blob_sha256: dict[str, str],
        seen_casefolded: set[str],
        digest: "hashlib._Hash",
        state: dict[str, int],
    ) -> None:
        for entry in tree.items():
            state["entries"] += 1
            if state["entries"] > self.limits.max_tree_entries:
                raise SnapshotPolicyError("snapshot tree entry limit exceeded")
            try:
                name = entry.path.decode("utf-8")
            except UnicodeDecodeError:
                diagnostics.append(
                    SnapshotDiagnostic(
                        code="PATH_ENCODING_SKIPPED",
                        detail="Git path is not valid UTF-8",
                    )
                )
                continue
            relative = prefix / name
            normalized = self._validate_path(relative, seen_casefolded)
            digest.update(normalized.encode("utf-8"))
            digest.update(str(entry.mode).encode("ascii"))
            digest.update(entry.sha)

            if stat.S_ISDIR(entry.mode):
                child = repository[entry.sha]
                if isinstance(child, Tree):
                    self._walk(
                        repository,
                        child,
                        relative,
                        root,
                        diagnostics,
                        materialized,
                        blob_sha256,
                        seen_casefolded,
                        digest,
                        state,
                    )
                continue
            state["files"] += 1
            if state["files"] > self.limits.max_files:
                raise SnapshotPolicyError("snapshot file limit exceeded")
            if stat.S_ISLNK(entry.mode):
                diagnostics.append(
                    SnapshotDiagnostic(
                        code="SYMLINK_SKIPPED",
                        path=normalized,
                        detail="Repository symlinks are never materialized",
                    )
                )
                continue
            if not stat.S_ISREG(entry.mode):
                diagnostics.append(
                    SnapshotDiagnostic(
                        code="NON_REGULAR_SKIPPED",
                        path=normalized,
                        detail="Only regular Git blobs are materialized",
                    )
                )
                continue
            blob = repository[entry.sha]
            if not isinstance(blob, Blob):
                diagnostics.append(
                    SnapshotDiagnostic(
                        code="INVALID_BLOB_SKIPPED",
                        path=normalized,
                        detail="Tree entry did not resolve to a blob",
                    )
                )
                continue
            if blob.raw_length() > self.limits.max_file_bytes:
                diagnostics.append(
                    SnapshotDiagnostic(
                        code="OVERSIZED_SKIPPED",
                        path=normalized,
                        detail="Blob exceeds per-file analysis limit",
                    )
                )
                continue
            data = blob.data
            if self._is_sensitive(relative):
                diagnostics.append(
                    SnapshotDiagnostic(
                        code="SENSITIVE_PATH_SKIPPED",
                        path=normalized,
                        detail="Secret-sensitive file is excluded from analysis",
                    )
                )
                continue
            if self._is_binary(data):
                diagnostics.append(
                    SnapshotDiagnostic(
                        code="BINARY_SKIPPED",
                        path=normalized,
                        detail="Binary blob is excluded from text analysis",
                    )
                )
                continue
            state["bytes"] += len(data)
            if state["bytes"] > self.limits.max_total_bytes:
                raise SnapshotPolicyError("snapshot total byte limit exceeded")
            target = (root / Path(*relative.parts)).resolve()
            if not target.is_relative_to(root):
                raise SnapshotPolicyError("snapshot path escapes destination")
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as handle:
                handle.write(data)
            materialized.append(normalized)
            blob_sha256[normalized] = hashlib.sha256(data).hexdigest()

    def _validate_path(self, path: PurePosixPath, seen_casefolded: set[str]) -> str:
        normalized = path.as_posix()
        if path.is_absolute() or ".." in path.parts:
            raise SnapshotPolicyError("unsafe repository path")
        if (
            len(normalized) > self.limits.max_path_length
            or len(path.parts) > self.limits.max_path_depth
        ):
            raise SnapshotPolicyError("repository path limit exceeded")
        for part in path.parts:
            stem = part.rstrip(" .").split(".", 1)[0].casefold()
            if not part or ":" in part or stem in _WINDOWS_RESERVED:
                raise SnapshotPolicyError("repository contains a platform-unsafe path")
        folded = normalized.casefold()
        if folded in seen_casefolded:
            raise SnapshotPolicyError("repository contains a case-colliding path")
        seen_casefolded.add(folded)
        return normalized

    @staticmethod
    def _is_sensitive(path: PurePosixPath) -> bool:
        name = path.name.lower()
        return (
            name in _SENSITIVE_NAMES
            or path.suffix.lower() in _SENSITIVE_SUFFIXES
            or name.startswith(".env.")
        )

    @staticmethod
    def _is_binary(data: bytes) -> bool:
        if b"\x00" in data[:8192]:
            return True
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            return True
        return False


class GitSnapshotFetcher:
    """Fetch one pinned commit under transfer gates, then materialize its text tree."""

    def __init__(
        self,
        root: Path,
        materializer: GitSnapshotMaterializer | None = None,
        allowed_hosts: frozenset[str] = DEFAULT_FORGE_HOSTS,
        fetch_limits: FetchLimits | None = None,
    ) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.materializer = materializer or GitSnapshotMaterializer()
        self.allowed_hosts = allowed_hosts
        self.fetch_limits = fetch_limits or FetchLimits()

    def fetch(self, repository_url: str, commit: str, snapshot_key: str) -> SnapshotResult:
        safe_url = validate_repository_url(repository_url, self.allowed_hosts)
        if not FULL_SHA_RE.fullmatch(commit):
            raise SnapshotPolicyError("snapshot requires a full 40-character commit SHA")
        self._require_public_dns(safe_url)
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", snapshot_key):
            raise SnapshotPolicyError("unsafe snapshot key")
        folder = (self.root / snapshot_key).resolve()
        if not folder.is_relative_to(self.root):
            raise SnapshotPolicyError("snapshot folder escapes storage root")
        objects = folder / "objects.git"
        checkout = folder / "tree"
        if objects.exists() or checkout.exists():
            raise SnapshotPolicyError("snapshot key already exists")
        folder.mkdir(parents=True, exist_ok=False)
        try:
            self._fetch_commit(safe_url, commit.lower(), objects)
            return self.materializer.materialize(objects, commit, checkout)
        except Exception:
            shutil.rmtree(folder, ignore_errors=True)
            raise

    @staticmethod
    def _require_public_dns(repository_url: str) -> None:
        hostname = urlsplit(repository_url).hostname
        if hostname is None:
            raise SnapshotPolicyError("repository URL has no hostname")
        try:
            answers = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise SnapshotPolicyError("repository hostname could not be resolved") from exc
        addresses = {item[4][0].split("%", 1)[0] for item in answers}
        if not addresses or any(not ipaddress.ip_address(item).is_global for item in addresses):
            raise SnapshotPolicyError("repository hostname resolved to a non-public address")

    def _fetch_commit(self, repository_url: str, commit: str, destination: Path) -> None:
        git = shutil.which("git")
        if git is None:
            raise SnapshotPolicyError("Git is required for bounded repository fetches")
        environment = {
            key: value
            for key, value in os.environ.items()
            if key.upper()
            in {
                "COMSPEC",
                "LANG",
                "LC_ALL",
                "PATH",
                "PATHEXT",
                "SYSTEMROOT",
                "TEMP",
                "TMP",
                "WINDIR",
            }
        }
        environment.update(
            {
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_TERMINAL_PROMPT": "0",
            }
        )
        common = [
            git,
            "-c",
            "credential.helper=",
            "-c",
            "protocol.file.allow=never",
            "-c",
            "protocol.ext.allow=never",
        ]
        try:
            subprocess.run(
                [*common, "init", "--bare", str(destination)],
                check=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=environment,
                timeout=min(15.0, self.fetch_limits.max_seconds),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise SnapshotPolicyError("unable to initialize the bounded Git object store") from exc

        command = [
            *common,
            "-c",
            "http.followRedirects=false",
            "-c",
            "http.lowSpeedLimit=1024",
            "-c",
            "http.lowSpeedTime=20",
            "-C",
            str(destination),
            "fetch",
            "--depth=1",
            "--no-tags",
            repository_url,
            commit,
        ]
        process_options: dict[str, object] = {}
        if os.name == "nt":
            process_options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            process_options["start_new_session"] = True
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=environment,
                **process_options,
            )
        except OSError as exc:
            raise SnapshotPolicyError("unable to start the bounded Git fetch") from exc
        deadline = time.monotonic() + self.fetch_limits.max_seconds
        violation: str | None = None
        while process.poll() is None:
            if time.monotonic() >= deadline:
                violation = "repository fetch exceeded its wall-time limit"
                break
            if self._directory_bytes(destination) > self.fetch_limits.max_fetch_bytes:
                violation = "repository fetch exceeded its disk quota"
                break
            time.sleep(self.fetch_limits.poll_seconds)
        if violation is not None:
            self._terminate_process_tree(process)
            raise SnapshotPolicyError(violation)
        if process.returncode != 0:
            raise SnapshotPolicyError("pinned commit fetch failed")
        if self._directory_bytes(destination) > self.fetch_limits.max_fetch_bytes:
            raise SnapshotPolicyError("repository fetch exceeded its disk quota")

    @staticmethod
    def _directory_bytes(root: Path) -> int:
        total = 0
        for path in root.rglob("*"):
            try:
                if path.is_file() and not path.is_symlink():
                    total += path.stat().st_size
            except OSError:
                continue
        return total

    @staticmethod
    def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        else:
            try:
                os.killpg(process.pid, 9)
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
