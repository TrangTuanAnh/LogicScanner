from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from logiclab.security import SecurityViolation


@dataclass(frozen=True)
class StoredArtifact:
    path: Path
    sha256: str
    size: int


class ArtifactStore:
    _safe_namespace = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$")

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def put_json(self, namespace: str, value: object) -> StoredArtifact:
        data = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        return self._put(namespace, data, ".json")

    def put_text(self, namespace: str, value: str) -> StoredArtifact:
        return self._put(namespace, value.encode("utf-8"), ".txt")

    def put_python(self, namespace: str, source: str) -> StoredArtifact:
        """Store a generated regression test with a Python extension.

        The immutable content hash remains the artifact identity; the extension
        lets pytest and py_compile consume it without a mutable copy.
        """
        return self._put(namespace, source.encode("utf-8"), ".py")

    def _put(self, namespace: str, data: bytes, suffix: str) -> StoredArtifact:
        if not self._safe_namespace.fullmatch(namespace):
            raise SecurityViolation("unsafe artifact namespace")
        digest = hashlib.sha256(data).hexdigest()
        folder = (self.root / namespace).resolve()
        if not folder.is_relative_to(self.root):
            raise SecurityViolation("artifact path escapes store")
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f"{digest}{suffix}"
        if path.exists():
            if path.read_bytes() != data:
                raise RuntimeError("artifact hash collision")
        else:
            try:
                with path.open("xb") as handle:
                    handle.write(data)
            except FileExistsError:
                if path.read_bytes() != data:
                    raise RuntimeError("artifact hash collision")
        return StoredArtifact(path=path, sha256=digest, size=len(data))
