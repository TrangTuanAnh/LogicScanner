from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from logiclab.analyzers import BashAnalyzer, ComposeAnalyzer, PythonAnalyzer, SqlAnalyzer
from logiclab.analyzers.base import AnalyzerAdapter
from logiclab.commands import CommandRunner
from logiclab.schemas import Engagement, StaticFact
from logiclab.security import CommandGate, ScopeGate, SecurityViolation


@dataclass(frozen=True)
class AnalysisResult:
    facts: list[StaticFact]
    excluded_paths: list[str]
    analyzed_paths: list[str]


class AnalyzerRegistry:
    excluded_names = {".git", ".venv", "venv", "node_modules", "__pycache__", "mysql-data"}
    excluded_extensions = {".env", ".h5", ".pkl", ".pyc", ".png", ".jpg", ".jpeg", ".gif"}
    max_source_bytes = 1_000_000

    def __init__(self, adapters: list[AnalyzerAdapter]) -> None:
        self.adapters = adapters

    @classmethod
    def default(cls) -> "AnalyzerRegistry":
        return cls([PythonAnalyzer(), SqlAnalyzer(), BashAnalyzer(), ComposeAnalyzer()])

    def scan(self, repository_root: Path) -> AnalysisResult:
        root = repository_root.resolve()
        facts: list[StaticFact] = []
        excluded: list[str] = []
        analyzed: list[str] = []
        for path in sorted(root.rglob("*")):
            if path.is_symlink():
                excluded.append(path.relative_to(root).as_posix())
                continue
            if not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            if any(part in self.excluded_names for part in path.relative_to(root).parts):
                excluded.append(relative)
                continue
            if path.name == ".env" or path.name.startswith(".env."):
                excluded.append(relative)
                continue
            if (
                path.suffix.lower() in self.excluded_extensions
                or path.stat().st_size > self.max_source_bytes
            ):
                excluded.append(relative)
                continue
            adapter = next(
                (candidate for candidate in self.adapters if candidate.supports(path)), None
            )
            if adapter is None:
                continue
            try:
                facts.extend(adapter.analyze(path, root))
                analyzed.append(relative)
            except (SyntaxError, UnicodeError, ValueError):
                excluded.append(relative)
        return AnalysisResult(facts=facts, excluded_paths=excluded, analyzed_paths=analyzed)


class TargetWorkspace:
    def __init__(
        self,
        root: Path,
        command_gate: CommandGate | None = None,
        runner: CommandRunner | None = None,
    ) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.command_gate = command_gate or CommandGate()
        self.runner = runner or CommandRunner()

    def prepare(self, engagement: Engagement) -> Path:
        destination = self.root / str(engagement.id) / "target"
        destination.parent.mkdir(parents=True, exist_ok=True)
        scope = ScopeGate(
            engagement.repository.url,
            engagement.repository.commit,
            destination.parent,
        )
        destination = scope.validate_clone(
            engagement.repository.url,
            engagement.repository.commit,
            destination,
        )
        if destination.exists():
            if not (destination / ".git").is_dir():
                raise SecurityViolation("existing target workspace is not a Git clone")
        else:
            self.runner.run(
                self.command_gate.build(
                    "git_clone",
                    url=engagement.repository.url,
                    commit=engagement.repository.commit,
                    destination=str(destination),
                )
            )
        self.runner.run(
            self.command_gate.build(
                "git_checkout",
                commit=engagement.repository.commit,
                cwd=str(destination),
            )
        )
        head = self.runner.run(
            self.command_gate.build("git_rev_parse", cwd=str(destination))
        ).stdout.strip()
        if head.lower() != engagement.repository.commit:
            raise SecurityViolation("checked-out target does not match pinned commit")
        return destination
