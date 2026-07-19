from __future__ import annotations

import re
from pathlib import Path

from logiclab.analyzers.base import source_name
from logiclab.schemas import FactKind, StaticFact


class SqlAnalyzer:
    extensions = (".sql",)
    _create = re.compile(r"(?is)\bCREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?\s+`?([a-zA-Z0-9_]+)`?")
    _mutation = re.compile(r"(?is)\b(INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+`?([a-zA-Z0-9_]+)`?")

    def supports(self, path: Path) -> bool:
        return path.suffix.lower() in self.extensions

    def analyze(self, path: Path, repository_root: Path) -> list[StaticFact]:
        text = path.read_text(encoding="utf-8", errors="replace")
        relative = source_name(path, repository_root)
        facts = [
            StaticFact(
                kind=FactKind.DATA_MODEL,
                subject=match.group(1),
                source_path=relative,
                line=text[: match.start()].count("\n") + 1,
                data={"operation": "CREATE TABLE"},
            )
            for match in self._create.finditer(text)
        ]
        facts.extend(
            StaticFact(
                kind=FactKind.DB_MUTATION,
                subject=match.group(2),
                source_path=relative,
                line=text[: match.start()].count("\n") + 1,
                data={"operation": match.group(1).upper()},
            )
            for match in self._mutation.finditer(text)
        )
        return facts
