from __future__ import annotations

import re
from pathlib import Path

from logiclab.analyzers.base import source_name
from logiclab.schemas import FactKind, StaticFact


class BashAnalyzer:
    extensions = (".sh", ".bash")
    _env = re.compile(r"\$\{?([A-Z_][A-Z0-9_]*)")

    def supports(self, path: Path) -> bool:
        return path.suffix.lower() in self.extensions

    def analyze(self, path: Path, repository_root: Path) -> list[StaticFact]:
        text = path.read_text(encoding="utf-8", errors="replace")
        relative = source_name(path, repository_root)
        commands = [
            (number, line.strip())
            for number, line in enumerate(text.splitlines(), start=1)
            if line.strip() and not line.lstrip().startswith("#")
        ]
        facts: list[StaticFact] = []
        if commands:
            line, command = commands[0]
            facts.append(
                StaticFact(
                    kind=FactKind.COMMAND,
                    subject=command.split()[0],
                    source_path=relative,
                    line=line,
                    data={"command": command},
                )
            )
        variables = sorted(set(self._env.findall(text)))
        if variables:
            facts.append(
                StaticFact(
                    kind=FactKind.CONFIGURATION,
                    subject="environment",
                    source_path=relative,
                    data={"variables": variables},
                )
            )
        return facts
