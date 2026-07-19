from pathlib import Path

import pytest

from logiclab.security import CommandGate, Redactor, ScopeGate, SecurityViolation


TARGET_URL = "https://github.com/TrangTuanAnh/tls-anomaly-detection-ids.git"
TARGET_COMMIT = "bc593b186b50f5c832a92f6ea1cbad88747d78ac"


def test_scope_gate_accepts_only_pinned_target(tmp_path: Path) -> None:
    gate = ScopeGate(TARGET_URL, TARGET_COMMIT, tmp_path)
    destination = gate.validate_clone(TARGET_URL, TARGET_COMMIT, tmp_path / "target")
    assert destination == (tmp_path / "target").resolve()

    with pytest.raises(SecurityViolation):
        gate.validate_clone("https://github.com/other/repo.git", TARGET_COMMIT, tmp_path / "x")
    with pytest.raises(SecurityViolation):
        gate.validate_clone(TARGET_URL, "a" * 40, tmp_path / "x")
    with pytest.raises(SecurityViolation):
        gate.validate_clone(TARGET_URL, TARGET_COMMIT, tmp_path.parent / "escape")


def test_command_gate_builds_argv_without_shell() -> None:
    gate = CommandGate()
    spec = gate.build("git_clone", url=TARGET_URL, commit=TARGET_COMMIT, destination="C:/lab")
    assert spec.shell is False
    assert spec.argv[0] == "git"
    with pytest.raises(SecurityViolation):
        gate.build("shell", command="whoami")
    assert gate.build("git_rev_parse", cwd="C:/lab").argv == ("git", "rev-parse", "HEAD")


def test_command_gate_only_allows_safe_mysql_count_queries() -> None:
    gate = CommandGate()
    spec = gate.build(
        "mysql_count",
        container="mysql",
        user="user",
        password="test-password",
        database="tls_ids",
        table="flow_events",
        marker_ip="198.18.0.42",
    )
    assert "SELECT COUNT(*) FROM flow_events" in spec.argv[-1]
    assert "test-password" not in " ".join(spec.argv)
    assert spec.environment == (("MYSQL_PWD", "test-password"),)
    with pytest.raises(SecurityViolation):
        gate.build(
            "mysql_count",
            container="mysql",
            user="user",
            password="test-password",
            database="tls_ids",
            table="users; DROP TABLE users",
        )
    with pytest.raises(SecurityViolation):
        gate.build(
            "docker_exec_mysql",
            container="mysql",
            user="user",
            password="test-password",
            database="tls_ids",
            statement="TRUNCATE TABLE flow_events; DROP TABLE users;",
        )


def test_redactor_masks_secrets_recursively() -> None:
    value = {
        "token": "abc",
        "nested": {"password": "secret", "safe": "ok"},
        "text": "Authorization: Bearer top-secret",
        "url": "https://proxy-user:proxy-password@proxy.invalid/repo?token=query-secret",
    }
    redacted = Redactor().redact(value)
    assert redacted["token"] == "[REDACTED]"
    assert redacted["nested"]["password"] == "[REDACTED]"
    assert redacted["nested"]["safe"] == "ok"
    assert "top-secret" not in redacted["text"]
    assert "proxy-password" not in redacted["url"]
    assert "query-secret" not in redacted["url"]
