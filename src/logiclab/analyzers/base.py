from __future__ import annotations

from pathlib import Path
from typing import Protocol

from logiclab.schemas import StaticFact


class AnalyzerAdapter(Protocol):
    extensions: tuple[str, ...]

    def supports(self, path: Path) -> bool: ...

    def analyze(self, path: Path, repository_root: Path) -> list[StaticFact]: ...


def source_name(path: Path, repository_root: Path) -> str:
    resolved = path.resolve()
    root = repository_root.resolve()
    if not resolved.is_relative_to(root):
        raise ValueError("source path is outside repository root")
    return resolved.relative_to(root).as_posix()
