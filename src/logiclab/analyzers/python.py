from __future__ import annotations

import ast
from pathlib import Path

from logiclab.analyzers.base import source_name
from logiclab.schemas import FactKind, StaticFact


def _qualified_name(node: ast.AST) -> str:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _string_constant(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


class PythonAnalyzer:
    extensions = (".py",)

    def supports(self, path: Path) -> bool:
        return path.suffix.lower() in self.extensions

    def analyze(self, path: Path, repository_root: Path) -> list[StaticFact]:
        relative = source_name(path, repository_root)
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=relative)
        facts: list[StaticFact] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for decorator in node.decorator_list:
                    if not isinstance(decorator, ast.Call):
                        continue
                    name = _qualified_name(decorator.func)
                    method = name.rsplit(".", 1)[-1].upper()
                    route = _string_constant(decorator.args[0]) if decorator.args else None
                    if method in {"GET", "POST", "PUT", "PATCH", "DELETE"} and route:
                        facts.append(
                            StaticFact(
                                kind=FactKind.ENTRY_POINT,
                                subject=f"{method} {route}",
                                source_path=relative,
                                line=node.lineno,
                                data={"function": node.name, "decorator": name},
                            )
                        )
            if isinstance(node, ast.Call):
                name = _qualified_name(node.func)
                lowered = name.lower()
                if any(
                    lowered.endswith(f".{method}")
                    for method in ("get", "post", "put", "patch", "delete")
                ) and any(client in lowered for client in ("requests.", "httpx.", "client.")):
                    url = _string_constant(node.args[0]) if node.args else None
                    facts.append(
                        StaticFact(
                            kind=FactKind.HTTP_EDGE,
                            subject=name,
                            source_path=relative,
                            line=node.lineno,
                            data={"url": url},
                        )
                    )
                if any(
                    token in lowered
                    for token in ("verify_hmac", "authenticate", "authorize", "permission")
                ):
                    facts.append(
                        StaticFact(
                            kind=FactKind.SECURITY_GUARD,
                            subject=name,
                            source_path=relative,
                            line=node.lineno,
                        )
                    )
                if lowered.endswith((".add", ".commit", ".delete", ".execute")):
                    facts.append(
                        StaticFact(
                            kind=FactKind.DB_MUTATION,
                            subject=name,
                            source_path=relative,
                            line=node.lineno,
                        )
                    )
        return facts
