"""Universal, deterministic and safe static repository discovery.

This module deliberately stops at static understanding.  It inventories an
untrusted local tree without following links, detects build components, and
emits a small normalized IR.  A malformed or unsupported file becomes an
explicit unsupported zone; it does not make the repository analysis crash.
"""

from __future__ import annotations

import ast
import hashlib
import os
import re
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator, model_validator


class IntelligenceModel(BaseModel):
    """Strict base contract for repository-intelligence data."""

    model_config = ConfigDict(extra="forbid", use_enum_values=False)


class AnalysisStatus(StrEnum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    ABSTAIN = "ABSTAIN"
    ERROR = "ERROR"


class UnderstandingLevel(StrEnum):
    """Progressive static-understanding capability."""

    U0 = "U0"  # inventory
    U1 = "U1"  # syntax/module structure
    U2 = "U2"  # symbols and relations
    U3 = "U3"  # security/domain twin
    U4 = "U4"  # validated context


class RuntimeLevel(StrEnum):
    """Progressive runtime capability; this module reaches at most R1."""

    R0 = "R0"  # static only
    R1 = "R1"  # a known build plan can be derived
    R2 = "R2"  # build verified
    R3 = "R3"  # boot/reset verified
    R4 = "R4"  # experiment ready


class DiagnosticSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class InventoryEntryKind(StrEnum):
    FILE = "file"
    SYMLINK = "symlink"


class IRNodeKind(StrEnum):
    MODULE = "module"
    EXTERNAL_MODULE = "external_module"
    CLASS = "class"
    INTERFACE = "interface"
    FUNCTION = "function"
    METHOD = "method"
    ENDPOINT = "endpoint"
    SYMBOL = "symbol"


class EvidenceSpan(IntelligenceModel):
    path: str = Field(validation_alias=AliasChoices("path", "source_path"))
    start_line: int = Field(ge=1)
    end_line: int | None = Field(default=None, ge=1)
    start_column: int | None = Field(default=None, ge=0)
    end_column: int | None = Field(default=None, ge=0)

    @field_validator("path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        if not value or "\\" in value:
            raise ValueError("evidence path must be a non-empty POSIX-relative path")
        path = PurePosixPath(value)
        if path.is_absolute() or value == "." or ".." in path.parts:
            raise ValueError("evidence path must stay inside the repository")
        if path.parts and path.parts[0].endswith(":"):
            raise ValueError("evidence path must not be a drive-qualified path")
        normalized = path.as_posix()
        if normalized != value:
            raise ValueError("evidence path must be normalized")
        return value

    @model_validator(mode="after")
    def validate_span(self) -> EvidenceSpan:
        if self.end_line is None:
            self.end_line = self.start_line
        if self.end_line < self.start_line:
            raise ValueError("end_line must be greater than or equal to start_line")
        if (
            self.end_line == self.start_line
            and self.start_column is not None
            and self.end_column is not None
            and self.end_column < self.start_column
        ):
            raise ValueError("end_column must not precede start_column")
        return self

    @property
    def source_path(self) -> str:
        return self.path


class Diagnostic(IntelligenceModel):
    code: str = Field(min_length=1)
    message: str = Field(min_length=1)
    severity: DiagnosticSeverity = DiagnosticSeverity.WARNING
    path: str | None = None
    evidence: EvidenceSpan | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class UnsupportedZone(IntelligenceModel):
    path: str
    reason: str
    language: str | None = None


class InventoryLimits(IntelligenceModel):
    max_files: int = Field(default=20_000, ge=1, le=1_000_000)
    max_total_bytes: int = Field(default=512 * 1024 * 1024, ge=1, le=8 * 1024 * 1024 * 1024)
    max_file_bytes: int = Field(default=2 * 1024 * 1024, ge=1, le=512 * 1024 * 1024)
    max_depth: int = Field(default=32, ge=0, le=256)
    max_source_lines_per_file: int = Field(default=100_000, ge=1, le=2_000_000)
    max_ir_nodes: int = Field(default=250_000, ge=1, le=2_000_000)
    max_ir_edges: int = Field(default=500_000, ge=1, le=4_000_000)
    max_claims: int = Field(default=250_000, ge=1, le=2_000_000)


class InventoryEntry(IntelligenceModel):
    path: str
    kind: InventoryEntryKind
    size: int = Field(default=0, ge=0)
    language: str | None = None
    is_manifest: bool = False
    analyzable: bool = True
    skip_reason: str | None = None


class RepositoryInventory(IntelligenceModel):
    entries: list[InventoryEntry] = Field(default_factory=list)
    total_bytes: int = Field(default=0, ge=0)
    truncated: bool = False
    skipped_paths: list[str] = Field(default_factory=list)
    excluded_paths: list[str] = Field(default_factory=list)
    diagnostics: list[Diagnostic] = Field(default_factory=list)


class BuildManifest(IntelligenceModel):
    path: str
    ecosystem: str
    build_system: str


class CapabilityProfile(IntelligenceModel):
    understanding: UnderstandingLevel
    runtime: RuntimeLevel
    reasons: list[str] = Field(default_factory=list)


class Component(IntelligenceModel):
    id: str
    name: str
    root_path: str
    ecosystems: list[str] = Field(default_factory=list)
    languages: list[str] = Field(default_factory=list)
    manifests: list[BuildManifest] = Field(default_factory=list)
    build_systems: list[str] = Field(default_factory=list)
    understanding_level: UnderstandingLevel = UnderstandingLevel.U0
    runtime_level: RuntimeLevel = RuntimeLevel.R0
    status: AnalysisStatus = AnalysisStatus.COMPLETE

    @property
    def capability(self) -> CapabilityProfile:
        return CapabilityProfile(
            understanding=self.understanding_level,
            runtime=self.runtime_level,
        )

    @property
    def path(self) -> str:
        return self.root_path


class IRNode(IntelligenceModel):
    id: str
    kind: IRNodeKind
    name: str
    component_id: str
    qualified_name: str | None = None
    language: str | None = None
    evidence: list[EvidenceSpan] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)


class IREdge(IntelligenceModel):
    id: str
    source: str = Field(validation_alias=AliasChoices("source", "source_id"))
    target: str = Field(validation_alias=AliasChoices("target", "target_id"))
    kind: str
    evidence: list[EvidenceSpan] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)

    @property
    def source_id(self) -> str:
        return self.source

    @property
    def target_id(self) -> str:
        return self.target


class Claim(IntelligenceModel):
    id: str
    subject: str
    predicate: str
    object: str
    component_id: str
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    evidence: list[EvidenceSpan] = Field(min_length=1)


class Coverage(IntelligenceModel):
    inventory_files: int = Field(ge=0)
    source_files: int = Field(ge=0)
    analyzed_source_files: int = Field(ge=0)
    unsupported_files: int = Field(ge=0)
    snapshot_omissions: int = Field(default=0, ge=0)
    manifest_files: int = Field(ge=0)
    total_bytes: int = Field(ge=0)
    analysis_percent: float = Field(ge=0.0, le=100.0)


class RepositoryIntelligenceReport(IntelligenceModel):
    repository_name: str
    status: AnalysisStatus
    understanding_level: UnderstandingLevel
    runtime_level: RuntimeLevel
    languages: list[str] = Field(default_factory=list)
    ecosystems: list[str] = Field(default_factory=list)
    components: list[Component] = Field(default_factory=list)
    inventory: RepositoryInventory
    nodes: list[IRNode] = Field(default_factory=list)
    edges: list[IREdge] = Field(default_factory=list)
    claims: list[Claim] = Field(default_factory=list)
    diagnostics: list[Diagnostic] = Field(default_factory=list)
    unsupported_zones: list[UnsupportedZone] = Field(default_factory=list)
    coverage: Coverage

    @property
    def capabilities(self) -> CapabilityProfile:
        reasons: list[str] = []
        if self.understanding_level < UnderstandingLevel.U3:
            reasons.append("security/domain twin has not been validated")
        if self.runtime_level < RuntimeLevel.R2:
            reasons.append("build and runtime have not been executed")
        return CapabilityProfile(
            understanding=self.understanding_level,
            runtime=self.runtime_level,
            reasons=reasons,
        )

    @property
    def capability(self) -> CapabilityProfile:
        return self.capabilities

    @property
    def ir_nodes(self) -> list[IRNode]:
        return self.nodes

    @property
    def ir_edges(self) -> list[IREdge]:
        return self.edges


_SOURCE_EXTENSIONS: dict[str, str] = {
    ".py": "Python",
    ".pyi": "Python",
    ".java": "Java",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".scala": "Scala",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".go": "Go",
    ".rs": "Rust",
    ".cs": "C#",
    ".fs": "F#",
    ".fsx": "F#",
    ".vb": "Visual Basic",
    ".rb": "Ruby",
    ".php": "PHP",
    ".ex": "Elixir",
    ".exs": "Elixir",
    ".dart": "Dart",
    ".c": "C",
    ".h": "C",
    ".cc": "C++",
    ".cpp": "C++",
    ".cxx": "C++",
    ".hpp": "C++",
    ".hh": "C++",
    ".swift": "Swift",
    ".sh": "Shell",
    ".bash": "Shell",
    ".zsh": "Shell",
    ".sql": "SQL",
}

_IGNORED_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "node_modules",
        "vendor",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "target",
    }
)

_NON_SOURCE_SUFFIXES = frozenset(
    {
        ".md",
        ".markdown",
        ".rst",
        ".txt",
        ".json",
        ".jsonl",
        ".yaml",
        ".yml",
        ".toml",
        ".xml",
        ".ini",
        ".cfg",
        ".conf",
        ".lock",
        ".csv",
        ".tsv",
        ".html",
        ".css",
        ".scss",
        ".less",
        ".svg",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".ico",
        ".pdf",
        ".woff",
        ".woff2",
        ".ttf",
        ".map",
        ".pem",
        ".crt",
    }
)

_KNOWN_BINARY_SUFFIXES = frozenset(
    {".bin", ".exe", ".dll", ".so", ".dylib", ".class", ".jar", ".war", ".a", ".o"}
)


def _stable_id(prefix: str, *parts: str) -> str:
    material = "\x1f".join(parts).encode("utf-8", errors="surrogatepass")
    return f"{prefix}_{hashlib.sha256(material).hexdigest()[:20]}"


def _relative_join(parent: str, name: str) -> str:
    return (PurePosixPath(parent) / name).as_posix() if parent else name


def _detect_language(path: PurePosixPath) -> str | None:
    if path.name == "Dockerfile" or path.name.startswith("Dockerfile."):
        return "Dockerfile"
    return _SOURCE_EXTENSIONS.get(path.suffix.lower())


def _manifest_descriptor(path: PurePosixPath) -> tuple[str, str] | None:
    name = path.name
    lowered = name.lower()
    suffix = path.suffix.lower()
    exact: dict[str, tuple[str, str]] = {
        "pom.xml": ("jvm", "maven"),
        "build.gradle": ("jvm", "gradle"),
        "build.gradle.kts": ("jvm", "gradle"),
        "settings.gradle": ("jvm", "gradle"),
        "settings.gradle.kts": ("jvm", "gradle"),
        "package.json": ("javascript", "npm"),
        "yarn.lock": ("javascript", "yarn"),
        "pnpm-lock.yaml": ("javascript", "pnpm"),
        "bun.lock": ("javascript", "bun"),
        "bun.lockb": ("javascript", "bun"),
        "pyproject.toml": ("python", "python-packaging"),
        "setup.py": ("python", "python-packaging"),
        "setup.cfg": ("python", "python-packaging"),
        "pipfile": ("python", "pipenv"),
        "poetry.lock": ("python", "poetry"),
        "uv.lock": ("python", "uv"),
        "go.mod": ("go", "go"),
        "go.work": ("go", "go"),
        "cargo.toml": ("rust", "cargo"),
        "gemfile": ("ruby", "bundler"),
        "composer.json": ("php", "composer"),
        "mix.exs": ("elixir", "mix"),
        "pubspec.yaml": ("dart", "pub"),
        "module.bazel": ("bazel", "bazel"),
        "workspace": ("bazel", "bazel"),
        "workspace.bazel": ("bazel", "bazel"),
        "build": ("bazel", "bazel"),
        "build.bazel": ("bazel", "bazel"),
        "cmakelists.txt": ("native", "cmake"),
        "makefile": ("native", "make"),
        "gnumakefile": ("native", "make"),
        "flake.nix": ("nix", "nix"),
        "default.nix": ("nix", "nix"),
        "shell.nix": ("nix", "nix"),
        "docker-compose.yml": ("container", "docker-compose"),
        "docker-compose.yaml": ("container", "docker-compose"),
        "compose.yml": ("container", "docker-compose"),
        "compose.yaml": ("container", "docker-compose"),
    }
    if lowered in exact:
        return exact[lowered]
    if re.fullmatch(r"requirements(?:[-_.][a-z0-9_-]+)?\.txt", lowered):
        return ("python", "pip")
    if suffix in {".csproj", ".fsproj", ".vbproj", ".sln"}:
        return ("dotnet", "dotnet")
    if suffix == ".gemspec":
        return ("ruby", "rubygems")
    return None


def safe_inventory(
    repository_root: str | os.PathLike[str],
    *,
    limits: InventoryLimits | None = None,
) -> RepositoryInventory:
    """Inventory a local tree deterministically without following any symlink."""

    limits = limits or InventoryLimits()
    root = Path(repository_root)
    try:
        root_stat = root.lstat()
    except OSError as error:
        raise ValueError(f"repository root cannot be inspected: {error}") from error
    if root.is_symlink():
        raise ValueError("repository root must not be a symlink")
    if not root.is_dir() or not root_stat:
        raise ValueError("repository root must be a directory")
    root = root.resolve(strict=True)

    entries: list[InventoryEntry] = []
    diagnostics: list[Diagnostic] = []
    skipped_paths: list[str] = []
    excluded_paths: list[str] = []
    total_bytes = 0
    truncated = False
    stopped = False

    def add_limit_diagnostic(code: str, message: str, path: str) -> None:
        if any(item.code == code for item in diagnostics):
            return
        diagnostics.append(
            Diagnostic(code=code, message=message, severity=DiagnosticSeverity.WARNING, path=path)
        )

    def walk(directory: Path, parent: str, depth: int) -> None:
        nonlocal total_bytes, truncated, stopped
        if stopped:
            return
        try:
            children = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as error:
            relative = parent or "."
            skipped_paths.append(relative)
            diagnostics.append(
                Diagnostic(
                    code="inventory.unreadable_directory",
                    message=f"directory could not be read: {error}",
                    severity=DiagnosticSeverity.WARNING,
                    path=relative,
                )
            )
            return

        for child in children:
            if stopped:
                return
            relative = _relative_join(parent, child.name)
            try:
                if child.is_symlink():
                    if len(entries) >= limits.max_files:
                        truncated = stopped = True
                        skipped_paths.append(relative)
                        add_limit_diagnostic(
                            "inventory.max_files", "inventory file limit reached", relative
                        )
                        return
                    try:
                        size = child.stat(follow_symlinks=False).st_size
                    except OSError:
                        size = 0
                    entries.append(
                        InventoryEntry(
                            path=relative,
                            kind=InventoryEntryKind.SYMLINK,
                            size=size,
                            analyzable=False,
                            skip_reason="symlink is never dereferenced",
                        )
                    )
                    diagnostics.append(
                        Diagnostic(
                            code="inventory.symlink",
                            message="symlink recorded but not followed",
                            severity=DiagnosticSeverity.WARNING,
                            path=relative,
                        )
                    )
                    continue

                if child.is_dir(follow_symlinks=False):
                    if child.name.lower() in _IGNORED_DIRECTORIES:
                        excluded_paths.append(relative)
                        diagnostics.append(
                            Diagnostic(
                                code="inventory.excluded_directory",
                                message="dependency, VCS, cache, or generated directory excluded",
                                severity=DiagnosticSeverity.INFO,
                                path=relative,
                            )
                        )
                        continue
                    if depth >= limits.max_depth:
                        truncated = True
                        skipped_paths.append(relative)
                        add_limit_diagnostic(
                            "inventory.max_depth", "inventory depth limit reached", relative
                        )
                        continue
                    walk(Path(child.path), relative, depth + 1)
                    continue

                if not child.is_file(follow_symlinks=False):
                    skipped_paths.append(relative)
                    diagnostics.append(
                        Diagnostic(
                            code="inventory.special_file",
                            message="special filesystem entry was not opened",
                            severity=DiagnosticSeverity.WARNING,
                            path=relative,
                        )
                    )
                    continue

                if len(entries) >= limits.max_files:
                    truncated = stopped = True
                    skipped_paths.append(relative)
                    add_limit_diagnostic(
                        "inventory.max_files", "inventory file limit reached", relative
                    )
                    return
                size = child.stat(follow_symlinks=False).st_size
                if total_bytes + size > limits.max_total_bytes:
                    truncated = stopped = True
                    skipped_paths.append(relative)
                    add_limit_diagnostic(
                        "inventory.max_total_bytes", "inventory byte limit reached", relative
                    )
                    return
                total_bytes += size
                pure_path = PurePosixPath(relative)
                descriptor = _manifest_descriptor(pure_path)
                too_large = size > limits.max_file_bytes
                entries.append(
                    InventoryEntry(
                        path=relative,
                        kind=InventoryEntryKind.FILE,
                        size=size,
                        language=_detect_language(pure_path),
                        is_manifest=descriptor is not None,
                        analyzable=not too_large,
                        skip_reason="file exceeds max_file_bytes" if too_large else None,
                    )
                )
                if too_large:
                    diagnostics.append(
                        Diagnostic(
                            code="inventory.max_file_bytes",
                            message="file is too large to analyze",
                            severity=DiagnosticSeverity.WARNING,
                            path=relative,
                            details={"size": size, "limit": limits.max_file_bytes},
                        )
                    )
            except OSError as error:
                skipped_paths.append(relative)
                diagnostics.append(
                    Diagnostic(
                        code="inventory.unreadable_entry",
                        message=f"filesystem entry could not be inspected: {error}",
                        severity=DiagnosticSeverity.WARNING,
                        path=relative,
                    )
                )

    walk(root, "", 0)
    entries.sort(key=lambda item: item.path)
    return RepositoryInventory(
        entries=entries,
        total_bytes=total_bytes,
        truncated=truncated,
        skipped_paths=sorted(set(skipped_paths)),
        excluded_paths=sorted(set(excluded_paths)),
        diagnostics=sorted(diagnostics, key=lambda item: (item.path or "", item.code)),
    )


def inventory_repository(
    repository_root: str | os.PathLike[str],
    *,
    limits: InventoryLimits | None = None,
) -> RepositoryInventory:
    """Compatibility-named entry point for :func:`safe_inventory`."""

    return safe_inventory(repository_root, limits=limits)


def _ecosystem_for_language(language: str) -> str:
    mapping = {
        "Python": "python",
        "Java": "jvm",
        "Kotlin": "jvm",
        "Scala": "jvm",
        "JavaScript": "javascript",
        "TypeScript": "javascript",
        "Go": "go",
        "Rust": "rust",
        "C#": "dotnet",
        "F#": "dotnet",
        "Visual Basic": "dotnet",
        "Ruby": "ruby",
        "PHP": "php",
        "Elixir": "elixir",
        "Dart": "dart",
        "C": "native",
        "C++": "native",
        "Swift": "swift",
        "Shell": "shell",
        "SQL": "database",
        "Dockerfile": "container",
    }
    return mapping[language]


def _component_contains(component_root: str, path: str) -> bool:
    return component_root == "." or path == component_root or path.startswith(f"{component_root}/")


def _component_for_path(components: Iterable[Component], path: str) -> Component:
    candidates = [item for item in components if _component_contains(item.root_path, path)]
    if not candidates:
        raise LookupError(f"no component owns {path}")
    return max(
        candidates, key=lambda item: (len(PurePosixPath(item.root_path).parts), item.root_path)
    )


def _build_components(
    root: Path,
    inventory: RepositoryInventory,
) -> list[Component]:
    manifests_by_root: dict[str, list[BuildManifest]] = {}
    source_paths: list[str] = []
    for entry in inventory.entries:
        if entry.kind is not InventoryEntryKind.FILE:
            continue
        path = PurePosixPath(entry.path)
        if entry.language:
            source_paths.append(entry.path)
        descriptor = _manifest_descriptor(path)
        if descriptor:
            ecosystem, build_system = descriptor
            component_root = path.parent.as_posix()
            manifests_by_root.setdefault(component_root, []).append(
                BuildManifest(path=entry.path, ecosystem=ecosystem, build_system=build_system)
            )

    roots = set(manifests_by_root)
    if not roots:
        roots.add(".")
    if any(
        not any(_component_contains(candidate, path) for candidate in roots)
        for path in source_paths
    ):
        roots.add(".")

    components: list[Component] = []
    for component_root in sorted(roots):
        manifests = sorted(manifests_by_root.get(component_root, []), key=lambda item: item.path)
        name = root.name if component_root == "." else PurePosixPath(component_root).name
        components.append(
            Component(
                id=_stable_id("component", component_root),
                name=name,
                root_path=component_root,
                ecosystems=sorted({item.ecosystem for item in manifests}),
                manifests=manifests,
                build_systems=sorted({item.build_system for item in manifests}),
                runtime_level=RuntimeLevel.R1 if manifests else RuntimeLevel.R0,
            )
        )

    for entry in inventory.entries:
        if not entry.language or entry.kind is not InventoryEntryKind.FILE:
            continue
        component = _component_for_path(components, entry.path)
        component.languages = sorted(set(component.languages) | {entry.language})
        component.ecosystems = sorted(
            set(component.ecosystems) | {_ecosystem_for_language(entry.language)}
        )
    return components


def _span(
    path: str, line: int, column: int | None = None, end_column: int | None = None
) -> EvidenceSpan:
    return EvidenceSpan(
        path=path,
        start_line=max(1, line),
        end_line=max(1, line),
        start_column=column,
        end_column=end_column,
    )


def _node(
    *,
    kind: IRNodeKind,
    name: str,
    component: Component,
    path: str,
    line: int,
    language: str,
    qualified_name: str | None = None,
    attributes: dict[str, Any] | None = None,
) -> IRNode:
    qualified = qualified_name or name
    return IRNode(
        id=_stable_id("node", path, kind.value, qualified),
        kind=kind,
        name=name,
        component_id=component.id,
        qualified_name=qualified,
        language=language,
        evidence=[_span(path, line)],
        attributes=attributes or {},
    )


def _edge(source: IRNode, target: IRNode, kind: str, evidence: EvidenceSpan) -> IREdge:
    return IREdge(
        id=_stable_id("edge", source.id, kind, target.id, evidence.path, str(evidence.start_line)),
        source=source.id,
        target=target.id,
        kind=kind,
        evidence=[evidence],
    )


def _claim(module: IRNode, symbol: IRNode) -> Claim:
    evidence = symbol.evidence[0]
    return Claim(
        id=_stable_id("claim", module.id, "declares", symbol.name, str(evidence.start_line)),
        subject=module.id,
        predicate="declares",
        object=symbol.name,
        component_id=module.component_id,
        evidence=[evidence],
    )


def _attribute_name(node: ast.AST) -> str:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _literal_string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _python_endpoint(decorator: ast.AST) -> tuple[str, str] | None:
    if not isinstance(decorator, ast.Call):
        return None
    called = _attribute_name(decorator.func)
    action = called.rsplit(".", 1)[-1].lower()
    route = _literal_string(decorator.args[0]) if decorator.args else None
    if not route:
        return None
    if action in {"get", "post", "put", "patch", "delete", "head", "options"}:
        return action.upper(), route
    if action == "route":
        for keyword in decorator.keywords:
            if keyword.arg != "methods" or not isinstance(keyword.value, (ast.List, ast.Tuple)):
                continue
            methods = [_literal_string(item) for item in keyword.value.elts]
            first = next((method for method in methods if method), "ANY")
            return first.upper(), route
        return "ANY", route
    return None


def _analyze_python(
    text: str,
    path: str,
    component: Component,
) -> tuple[list[IRNode], list[IREdge], list[Claim]]:
    tree = ast.parse(text, filename=path)
    module_name = PurePosixPath(path).with_suffix("").as_posix().replace("/", ".")
    module = _node(
        kind=IRNodeKind.MODULE,
        name=module_name,
        component=component,
        path=path,
        line=1,
        language="Python",
        qualified_name=module_name,
    )
    nodes = [module]
    edges: list[IREdge] = []
    claims: list[Claim] = []
    node_by_ast: dict[ast.AST, IRNode] = {}
    parent_by_ast: dict[ast.AST, ast.AST] = {}
    external_by_name: dict[str, IRNode] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parent_by_ast[child] = parent

    def qualified_name(item: ast.AST, name: str) -> str:
        parents: list[str] = []
        current = parent_by_ast.get(item)
        while current is not None:
            if isinstance(current, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                parents.append(current.name)
            current = parent_by_ast.get(current)
        return ".".join([module_name, *reversed(parents), name])

    for item in ast.walk(tree):
        if isinstance(item, (ast.Import, ast.ImportFrom)):
            imported = (
                [alias.name for alias in item.names]
                if isinstance(item, ast.Import)
                else [item.module or "."]
            )
            for import_name in imported:
                external = external_by_name.get(import_name)
                if external is None:
                    external = _node(
                        kind=IRNodeKind.EXTERNAL_MODULE,
                        name=import_name,
                        component=component,
                        path=path,
                        line=item.lineno,
                        language="Python",
                        qualified_name=import_name,
                    )
                    external_by_name[import_name] = external
                    nodes.append(external)
                edges.append(_edge(module, external, "imports", _span(path, item.lineno)))
            continue

        if not isinstance(item, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if isinstance(item, ast.ClassDef):
            kind = IRNodeKind.CLASS
        else:
            current = parent_by_ast.get(item)
            while current is not None and not isinstance(current, ast.ClassDef):
                if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    break
                current = parent_by_ast.get(current)
            kind = IRNodeKind.METHOD if isinstance(current, ast.ClassDef) else IRNodeKind.FUNCTION
        symbol = _node(
            kind=kind,
            name=item.name,
            component=component,
            path=path,
            line=item.lineno,
            language="Python",
            qualified_name=qualified_name(item, item.name),
            attributes={"async": isinstance(item, ast.AsyncFunctionDef)},
        )
        node_by_ast[item] = symbol
        nodes.append(symbol)
        claims.append(_claim(module, symbol))
        owner = module
        current = parent_by_ast.get(item)
        while current is not None:
            if current in node_by_ast:
                owner = node_by_ast[current]
                break
            current = parent_by_ast.get(current)
        edges.append(_edge(owner, symbol, "declares", _span(path, item.lineno)))

        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in item.decorator_list:
                endpoint_data = _python_endpoint(decorator)
                if not endpoint_data:
                    continue
                method, route = endpoint_data
                endpoint = _node(
                    kind=IRNodeKind.ENDPOINT,
                    name=f"{method} {route}",
                    component=component,
                    path=path,
                    line=getattr(decorator, "lineno", item.lineno),
                    language="Python",
                    qualified_name=f"{qualified_name(item, item.name)}:{method}:{route}",
                    attributes={"method": method, "route": route, "handler": item.name},
                )
                nodes.append(endpoint)
                claims.append(_claim(module, endpoint))
                edges.append(_edge(symbol, endpoint, "handles", endpoint.evidence[0]))
    return nodes, edges, claims


_IMPORT_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "JavaScript": (
        re.compile(r"\bimport(?:[\s\S]*?\bfrom\s*)?['\"]([^'\"]+)['\"]"),
        re.compile(r"\brequire\(\s*['\"]([^'\"]+)['\"]\s*\)"),
    ),
    "TypeScript": (
        re.compile(r"\bimport(?:[\s\S]*?\bfrom\s*)?['\"]([^'\"]+)['\"]"),
        re.compile(r"\brequire\(\s*['\"]([^'\"]+)['\"]\s*\)"),
    ),
    "Go": (
        re.compile(r"\bimport\s+(?:[\w.]+\s+)?\"([^\"]+)\""),
        re.compile(r"^\s*(?:[\w.]+\s+)?\"([^\"]+)\"\s*$", re.MULTILINE),
    ),
    "Rust": (re.compile(r"^\s*use\s+([a-zA-Z_][\w:]*)", re.MULTILINE),),
    "Java": (re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+)", re.MULTILINE),),
    "Kotlin": (re.compile(r"^\s*import\s+([\w.]+)", re.MULTILINE),),
    "Scala": (re.compile(r"^\s*import\s+([\w.]+)", re.MULTILINE),),
    "C#": (re.compile(r"^\s*using\s+([\w.]+)", re.MULTILINE),),
    "F#": (re.compile(r"^\s*open\s+([\w.]+)", re.MULTILINE),),
    "Ruby": (re.compile(r"^\s*require(?:_relative)?\s+['\"]([^'\"]+)['\"]", re.MULTILINE),),
    "PHP": (re.compile(r"^\s*use\s+([\\\w]+)", re.MULTILINE),),
    "Elixir": (re.compile(r"^\s*(?:alias|import|use)\s+([\w.]+)", re.MULTILINE),),
    "Dart": (re.compile(r"^\s*import\s+['\"]([^'\"]+)['\"]", re.MULTILINE),),
}

_CLASS_PATTERNS: dict[str, re.Pattern[str]] = {
    "JavaScript": re.compile(r"\bclass\s+([A-Za-z_$][\w$]*)"),
    "TypeScript": re.compile(
        r"\b(?:export\s+)?(?:abstract\s+)?(?:class|interface)\s+([A-Za-z_$][\w$]*)"
    ),
    "Go": re.compile(r"^\s*type\s+([A-Z_a-z]\w*)\s+(?:struct|interface)\b", re.MULTILINE),
    "Rust": re.compile(r"^\s*(?:pub\s+)?(?:struct|enum|trait)\s+([A-Z_a-z]\w*)", re.MULTILINE),
    "Java": re.compile(r"\b(?:class|interface|enum|record)\s+([A-Z_a-z]\w*)"),
    "Kotlin": re.compile(r"\b(?:data\s+|sealed\s+)?(?:class|interface|object)\s+([A-Z_a-z]\w*)"),
    "Scala": re.compile(r"\b(?:case\s+)?(?:class|trait|object)\s+([A-Z_a-z]\w*)"),
    "C#": re.compile(r"\b(?:class|interface|struct|record|enum)\s+([A-Z_a-z]\w*)"),
    "Ruby": re.compile(r"^\s*(?:class|module)\s+([A-Z]\w*(?:::\w+)*)", re.MULTILINE),
    "PHP": re.compile(r"\b(?:class|interface|trait|enum)\s+([A-Z_a-z]\w*)", re.IGNORECASE),
    "Elixir": re.compile(r"^\s*defmodule\s+([A-Z][\w.]*)", re.MULTILINE),
    "Dart": re.compile(r"\b(?:class|mixin|enum|extension)\s+([A-Z_a-z]\w*)"),
    "C": re.compile(r"^\s*(?:typedef\s+)?struct\s+([A-Z_a-z]\w*)", re.MULTILINE),
    "C++": re.compile(r"\b(?:class|struct|enum)\s+([A-Z_a-z]\w*)"),
    "Swift": re.compile(r"\b(?:class|struct|protocol|enum|actor)\s+([A-Z_a-z]\w*)"),
}

_FUNCTION_PATTERNS: dict[str, re.Pattern[str]] = {
    "JavaScript": re.compile(r"\b(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)"),
    "TypeScript": re.compile(r"\b(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)"),
    "Go": re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Z_a-z]\w*)\s*\(", re.MULTILINE),
    "Rust": re.compile(
        r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Z_a-z]\w*)\s*\(",
        re.MULTILINE,
    ),
    "Java": re.compile(
        r"^\s*(?:(?:public|protected|private|static|final|abstract|synchronized|native)\s+)*"
        r"[\w$<>,.?\[\]]+\s+([A-Z_a-z$][\w$]*)\s*\(",
        re.MULTILINE,
    ),
    "Kotlin": re.compile(r"\bfun\s+([A-Z_a-z]\w*)\s*\("),
    "Scala": re.compile(r"\bdef\s+([A-Z_a-z]\w*)\s*\("),
    "C#": re.compile(
        r"^\s*(?:(?:public|protected|private|internal|static|virtual|override|abstract|async)\s+)*"
        r"[\w<>,.?\[\]]+\s+([A-Z_a-z][\w]*)\s*\(",
        re.MULTILINE,
    ),
    "Ruby": re.compile(r"^\s*def\s+(?:self\.)?([A-Z_a-z]\w*[!?=]?)", re.MULTILINE),
    "PHP": re.compile(r"\bfunction\s+([A-Z_a-z]\w*)\s*\(", re.IGNORECASE),
    "Elixir": re.compile(r"^\s*defp?\s+([A-Z_a-z]\w*[!?]?)", re.MULTILINE),
    "Dart": re.compile(
        r"^\s*(?:[\w<>?]+\s+)+([A-Z_a-z]\w*)\s*\([^;]*\)\s*(?:\{|=>)",
        re.MULTILINE,
    ),
    "Swift": re.compile(r"\bfunc\s+([A-Z_a-z]\w*)\s*\("),
}

_ENDPOINT_PATTERNS: tuple[tuple[re.Pattern[str], str | None], ...] = (
    (
        re.compile(
            r"\b(?:app|router)\.(get|post|put|patch|delete|head|options)\(\s*['\"]([^'\"]+)['\"]",
            re.IGNORECASE,
        ),
        None,
    ),
    (
        re.compile(r"\bRoute::(get|post|put|patch|delete)\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE),
        None,
    ),
    (re.compile(r"\bMap(Get|Post|Put|Patch|Delete)\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE), None),
    (
        re.compile(r"@(Get|Post|Put|Patch|Delete)Mapping\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE),
        None,
    ),
    (
        re.compile(r"\[(?:Http)(Get|Post|Put|Patch|Delete)\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE),
        None,
    ),
    (re.compile(r"\b(get|post|put|patch|delete)\s+['\"]([^'\"]+)['\"]", re.IGNORECASE), None),
    (re.compile(r"\bHandleFunc\(\s*['\"]([^'\"]+)['\"]"), "ANY"),
)


def _line_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _analyze_generic(
    text: str,
    path: str,
    language: str,
    component: Component,
) -> tuple[list[IRNode], list[IREdge], list[Claim]]:
    module_name = PurePosixPath(path).with_suffix("").as_posix().replace("/", ".")
    module = _node(
        kind=IRNodeKind.MODULE,
        name=module_name,
        component=component,
        path=path,
        line=1,
        language=language,
        qualified_name=module_name,
    )
    nodes = [module]
    edges: list[IREdge] = []
    claims: list[Claim] = []
    external_by_name: dict[str, IRNode] = {}

    for pattern in _IMPORT_PATTERNS.get(language, ()):
        for match in pattern.finditer(text):
            imported = match.group(1)
            line = _line_for_offset(text, match.start())
            external = external_by_name.get(imported)
            if external is None:
                external = _node(
                    kind=IRNodeKind.EXTERNAL_MODULE,
                    name=imported,
                    component=component,
                    path=path,
                    line=line,
                    language=language,
                    qualified_name=imported,
                )
                external_by_name[imported] = external
                nodes.append(external)
            edges.append(_edge(module, external, "imports", _span(path, line)))

    seen_symbols: set[tuple[IRNodeKind, str, int]] = set()
    for kind, pattern in (
        (IRNodeKind.CLASS, _CLASS_PATTERNS.get(language)),
        (IRNodeKind.FUNCTION, _FUNCTION_PATTERNS.get(language)),
    ):
        if pattern is None:
            continue
        for match in pattern.finditer(text):
            name = match.group(1)
            line = _line_for_offset(text, match.start())
            key = (kind, name, line)
            if key in seen_symbols:
                continue
            seen_symbols.add(key)
            symbol = _node(
                kind=kind,
                name=name,
                component=component,
                path=path,
                line=line,
                language=language,
                qualified_name=f"{module_name}.{name}",
            )
            nodes.append(symbol)
            claims.append(_claim(module, symbol))
            edges.append(_edge(module, symbol, "declares", symbol.evidence[0]))

    for pattern, fixed_method in _ENDPOINT_PATTERNS:
        for match in pattern.finditer(text):
            if fixed_method:
                method, route = fixed_method, match.group(1)
            else:
                method, route = match.group(1).upper(), match.group(2)
            line = _line_for_offset(text, match.start())
            endpoint = _node(
                kind=IRNodeKind.ENDPOINT,
                name=f"{method.upper()} {route}",
                component=component,
                path=path,
                line=line,
                language=language,
                qualified_name=f"{module_name}:{method.upper()}:{route}:{line}",
                attributes={"method": method.upper(), "route": route},
            )
            nodes.append(endpoint)
            claims.append(_claim(module, endpoint))
            edges.append(_edge(module, endpoint, "exposes", endpoint.evidence[0]))
    return nodes, edges, claims


def _safe_read(root: Path, entry: InventoryEntry) -> bytes:
    path = root.joinpath(*PurePosixPath(entry.path).parts)
    if path.is_symlink():
        raise OSError("entry became a symlink after inventory")
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(root):
        raise OSError("entry resolves outside repository root")
    if not resolved.is_file():
        raise OSError("entry is no longer a regular file")
    with resolved.open("rb") as stream:
        data = stream.read(entry.size + 1)
    if len(data) != entry.size:
        raise OSError("entry changed while it was being analyzed")
    return data


def _looks_binary(data: bytes) -> bool:
    sample = data[:8192]
    if b"\x00" in sample:
        return True
    if not sample:
        return False
    control = sum(byte < 9 or 13 < byte < 32 for byte in sample)
    return control / len(sample) > 0.10


def _unknown_file_is_relevant(path: PurePosixPath) -> bool:
    if path.suffix.lower() in _KNOWN_BINARY_SUFFIXES:
        return True
    if path.suffix.lower() in _NON_SOURCE_SUFFIXES:
        return False
    if not path.suffix and path.name.lower() in {
        "license",
        "copying",
        "notice",
        "readme",
        "authors",
        "changelog",
    }:
        return False
    return bool(path.suffix)


def analyze_repository(
    repository_root: str | os.PathLike[str],
    *,
    limits: InventoryLimits | None = None,
) -> RepositoryIntelligenceReport:
    """Build a normalized static-intelligence report for any local repository."""

    limits = limits or InventoryLimits()
    inventory = safe_inventory(repository_root, limits=limits)
    root = Path(repository_root).resolve(strict=True)
    components = _build_components(root, inventory)
    nodes: list[IRNode] = []
    edges: list[IREdge] = []
    claims: list[Claim] = []
    diagnostics = list(inventory.diagnostics)
    unsupported: list[UnsupportedZone] = []
    analyzed_paths: set[str] = set()
    syntactic_components: set[str] = set()
    semantic_components: set[str] = set()

    def add_unsupported(path: str, reason: str, language: str | None = None) -> None:
        unsupported.append(UnsupportedZone(path=path, reason=reason, language=language))

    for skipped in inventory.skipped_paths:
        add_unsupported(skipped, "tree zone excluded or unreadable")

    for entry in inventory.entries:
        if entry.kind is InventoryEntryKind.SYMLINK:
            add_unsupported(entry.path, entry.skip_reason or "symlink", entry.language)
            continue
        path = PurePosixPath(entry.path)
        language = entry.language
        if not entry.analyzable:
            if language or _unknown_file_is_relevant(path):
                add_unsupported(entry.path, entry.skip_reason or "not analyzable", language)
            continue
        if entry.is_manifest:
            continue
        if language is None:
            if _unknown_file_is_relevant(path):
                reason = (
                    "unsupported binary or compiled artifact"
                    if path.suffix.lower() in _KNOWN_BINARY_SUFFIXES
                    else "no analyzer for file type"
                )
                add_unsupported(entry.path, reason)
            continue

        component = _component_for_path(components, entry.path)
        try:
            data = _safe_read(root, entry)
        except OSError as error:
            diagnostics.append(
                Diagnostic(
                    code="source.read_error",
                    message=f"source could not be read safely: {error}",
                    severity=DiagnosticSeverity.WARNING,
                    path=entry.path,
                )
            )
            add_unsupported(entry.path, "source could not be read safely", language)
            continue
        if _looks_binary(data):
            diagnostics.append(
                Diagnostic(
                    code="source.binary",
                    message="source extension points to binary content",
                    severity=DiagnosticSeverity.WARNING,
                    path=entry.path,
                )
            )
            add_unsupported(entry.path, "binary content", language)
            continue
        text = data.decode("utf-8", errors="replace")
        if text.count("\n") + 1 > limits.max_source_lines_per_file:
            diagnostics.append(
                Diagnostic(
                    code="source.line_limit",
                    message="source exceeds the per-file line analysis limit",
                    severity=DiagnosticSeverity.ERROR,
                    path=entry.path,
                )
            )
            add_unsupported(entry.path, "source line limit exceeded", language)
            continue
        try:
            if language == "Python":
                file_nodes, file_edges, file_claims = _analyze_python(text, entry.path, component)
            else:
                file_nodes, file_edges, file_claims = _analyze_generic(
                    text, entry.path, language, component
                )
        except SyntaxError as error:
            line = max(1, error.lineno or 1)
            diagnostics.append(
                Diagnostic(
                    code="source.syntax_error",
                    message=error.msg,
                    severity=DiagnosticSeverity.WARNING,
                    path=entry.path,
                    evidence=_span(entry.path, line, max(0, (error.offset or 1) - 1)),
                )
            )
            add_unsupported(entry.path, "syntax could not be parsed", language)
            continue
        if (
            len(nodes) + len(file_nodes) > limits.max_ir_nodes
            or len(edges) + len(file_edges) > limits.max_ir_edges
            or len(claims) + len(file_claims) > limits.max_claims
        ):
            diagnostics.append(
                Diagnostic(
                    code="analysis.ir_limit",
                    message="normalized IR budget exhausted before this file could be added",
                    severity=DiagnosticSeverity.ERROR,
                    path=entry.path,
                )
            )
            add_unsupported(entry.path, "normalized IR budget exhausted", language)
            continue
        nodes.extend(file_nodes)
        edges.extend(file_edges)
        claims.extend(file_claims)
        analyzed_paths.add(entry.path)
        syntactic_components.add(component.id)
        if any(
            node.kind
            in {
                IRNodeKind.CLASS,
                IRNodeKind.INTERFACE,
                IRNodeKind.FUNCTION,
                IRNodeKind.METHOD,
                IRNodeKind.ENDPOINT,
            }
            for node in file_nodes
        ):
            semantic_components.add(component.id)

    unsupported.sort(key=lambda item: (item.path, item.reason))
    unsupported_paths = {item.path for item in unsupported}
    for component in components:
        if component.id in semantic_components:
            component.understanding_level = UnderstandingLevel.U2
        elif component.id in syntactic_components:
            component.understanding_level = UnderstandingLevel.U1
        component.status = (
            AnalysisStatus.PARTIAL
            if any(_component_contains(component.root_path, path) for path in unsupported_paths)
            else AnalysisStatus.COMPLETE
        )

    nodes.sort(
        key=lambda item: (
            item.evidence[0].path if item.evidence else "",
            item.evidence[0].start_line if item.evidence else 0,
            item.kind.value,
            item.id,
        )
    )
    edges.sort(key=lambda item: item.id)
    claims.sort(key=lambda item: item.id)
    diagnostics.sort(key=lambda item: (item.path or "", item.code, item.message))

    source_entries = [entry for entry in inventory.entries if entry.language]
    analysis_percent = (
        round(100.0 * len(analyzed_paths) / len(source_entries), 2) if source_entries else 100.0
    )
    understanding = max(
        (component.understanding_level for component in components),
        default=UnderstandingLevel.U0,
    )
    runtime = max((component.runtime_level for component in components), default=RuntimeLevel.R0)
    status = (
        AnalysisStatus.PARTIAL
        if inventory.truncated
        or unsupported
        or any(item.severity is DiagnosticSeverity.ERROR for item in diagnostics)
        else AnalysisStatus.COMPLETE
    )
    coverage = Coverage(
        inventory_files=sum(entry.kind is InventoryEntryKind.FILE for entry in inventory.entries),
        source_files=len(source_entries),
        analyzed_source_files=len(analyzed_paths),
        unsupported_files=len(unsupported_paths),
        manifest_files=sum(entry.is_manifest for entry in inventory.entries),
        total_bytes=inventory.total_bytes,
        analysis_percent=analysis_percent,
    )
    return RepositoryIntelligenceReport(
        repository_name=root.name,
        status=status,
        understanding_level=understanding,
        runtime_level=runtime,
        languages=sorted({entry.language for entry in source_entries if entry.language}),
        ecosystems=sorted(
            {ecosystem for component in components for ecosystem in component.ecosystems}
        ),
        components=components,
        inventory=inventory,
        nodes=nodes,
        edges=edges,
        claims=claims,
        diagnostics=diagnostics,
        unsupported_zones=unsupported,
        coverage=coverage,
    )


class RepositoryIntelligenceAnalyzer:
    """Reusable facade for callers that want configured inventory limits."""

    def __init__(self, limits: InventoryLimits | None = None) -> None:
        self.limits = limits or InventoryLimits()

    def analyze(self, repository_root: str | os.PathLike[str]) -> RepositoryIntelligenceReport:
        return analyze_repository(repository_root, limits=self.limits)


UniversalRepositoryAnalyzer = RepositoryIntelligenceAnalyzer
RepositoryComponent = Component
SourceEvidence = EvidenceSpan
UCapability = UnderstandingLevel
RCapability = RuntimeLevel
CapabilityU = UnderstandingLevel
CapabilityR = RuntimeLevel


__all__ = [
    "AnalysisStatus",
    "BuildManifest",
    "CapabilityProfile",
    "CapabilityR",
    "CapabilityU",
    "Claim",
    "Component",
    "Coverage",
    "Diagnostic",
    "DiagnosticSeverity",
    "EvidenceSpan",
    "InventoryEntry",
    "InventoryEntryKind",
    "InventoryLimits",
    "IREdge",
    "IRNode",
    "IRNodeKind",
    "RCapability",
    "RepositoryComponent",
    "RepositoryIntelligenceAnalyzer",
    "RepositoryIntelligenceReport",
    "RepositoryInventory",
    "RuntimeLevel",
    "SourceEvidence",
    "UCapability",
    "UnderstandingLevel",
    "UniversalRepositoryAnalyzer",
    "UnsupportedZone",
    "analyze_repository",
    "inventory_repository",
    "safe_inventory",
]
