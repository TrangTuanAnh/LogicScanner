from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from logiclab.analyzers.base import source_name
from logiclab.schemas import FactKind, StaticFact


class ComposeAnalyzer:
    extensions = (".yml", ".yaml")

    def supports(self, path: Path) -> bool:
        return path.suffix.lower() in self.extensions and "compose" in path.name.lower()

    def analyze(self, path: Path, repository_root: Path) -> list[StaticFact]:
        relative = source_name(path, repository_root)
        document: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        facts: list[StaticFact] = []
        services = document.get("services") or {}
        for name, raw in services.items():
            config = raw or {}
            facts.append(
                StaticFact(
                    kind=FactKind.SERVICE,
                    subject=str(name),
                    source_path=relative,
                    data={
                        "image": config.get("image"),
                        "build": config.get("build"),
                        "network_mode": config.get("network_mode"),
                    },
                )
            )
            capabilities = config.get("cap_add") or []
            if capabilities:
                facts.append(
                    StaticFact(
                        kind=FactKind.CAPABILITY,
                        subject=str(name),
                        source_path=relative,
                        data={"cap_add": list(capabilities)},
                    )
                )
            networks = config.get("networks") or []
            if networks:
                names = list(networks) if isinstance(networks, list) else list(networks.keys())
                facts.append(
                    StaticFact(
                        kind=FactKind.TOPOLOGY,
                        subject=str(name),
                        source_path=relative,
                        data={"networks": names},
                    )
                )
        return facts
