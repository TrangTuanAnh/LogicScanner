import hashlib
from pathlib import Path

import pytest

from logiclab.artifacts import ArtifactStore
from logiclab.security import SecurityViolation


def test_artifact_store_writes_content_addressed_immutable_files(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    artifact = store.put_json("evidence", {"b": 2, "a": 1})
    expected = hashlib.sha256(b'{"a":1,"b":2}').hexdigest()
    assert artifact.sha256 == expected
    assert artifact.path.read_bytes() == b'{"a":1,"b":2}'
    assert store.put_json("evidence", {"a": 1, "b": 2}).path == artifact.path


def test_artifact_store_rejects_unsafe_namespace(tmp_path: Path) -> None:
    with pytest.raises(SecurityViolation):
        ArtifactStore(tmp_path).put_text("../escape", "bad")
