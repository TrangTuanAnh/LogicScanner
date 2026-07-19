from pathlib import Path

import httpx
import pytest

from logiclab.commands import CommandResult
from logiclab.lab import LabUnavailable, TargetLab
from logiclab.profiles import load_blueprint
from logiclab.schemas import ExperimentKind


class FakeRunner:
    def __init__(self) -> None:
        self.commands = []

    def run(self, spec):
        self.commands.append(spec)
        if spec.name == "mysql_count":
            return CommandResult(0, "1\n", "")
        return CommandResult(0, "", "")


class FakeHttp:
    def __init__(self) -> None:
        self.urls = []
        self.closed = False

    def get(self, url: str) -> httpx.Response:
        self.urls.append(url)
        return httpx.Response(200, json={"ok": True})

    def post(self, url: str, **kwargs) -> httpx.Response:
        self.urls.append(url)
        if url.endswith("/flow"):
            return httpx.Response(200, json={"ok": True, "accepted": 1})
        return httpx.Response(401, json={"detail": "bad signature"})

    def close(self) -> None:
        self.closed = True


def test_target_lab_renders_isolated_profile_and_uses_only_gated_commands(tmp_path: Path) -> None:
    root = tmp_path / "target"
    root.mkdir()
    (root / "docker-compose.sensor.yml").write_text("services: {}", encoding="utf-8")
    runner = FakeRunner()
    http = FakeHttp()
    blueprint = load_blueprint(Path("engagements/tls-ids-lab.yaml"))
    lab = TargetLab(root, blueprint, "logiclab-target-password", runner=runner, http_client=http)

    lab.activate_profile(ExperimentKind.TRUST_LAUNDERING)
    assert "REQUIRE_INGEST_HMAC=false" in lab.env_file.read_text(encoding="utf-8")
    lab.reset()
    assert lab.row_count("flow_events", "198.18.0.42") == 1
    assert lab.submit_untrusted_flow("198.18.0.42").status_code == 200

    lab.activate_profile(ExperimentKind.HMAC_NONCE_MUTATION)
    assert "REQUIRE_INGEST_HMAC=true" in lab.env_file.read_text(encoding="utf-8")
    assert lab.submit_bad_hmac().status_code == 401
    lab.stop()
    lab.close()

    assert http.closed is True
    assert {command.name for command in runner.commands} >= {
        "docker_compose",
        "docker_exec_mysql",
        "mysql_count",
    }


def test_target_lab_does_not_write_through_repository_generated_file_symlinks(
    tmp_path: Path,
) -> None:
    root = tmp_path / "target"
    root.mkdir()
    env_victim = tmp_path / "env-victim"
    override_victim = tmp_path / "override-victim"
    env_victim.write_text("env-safe", encoding="utf-8")
    override_victim.write_text("override-safe", encoding="utf-8")
    try:
        (root / ".env").symlink_to(env_victim)
        (root / "docker-compose.logiclab.yml").symlink_to(override_victim)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    blueprint = load_blueprint(Path("engagements/tls-ids-lab.yaml"))
    lab = TargetLab(root, blueprint, "logiclab-target-password", http_client=FakeHttp())
    try:
        lab._render_files(hmac_enabled=False)

        assert not lab.env_file.is_relative_to(root)
        assert not lab.override_file.is_relative_to(root)
        assert env_victim.read_text(encoding="utf-8") == "env-safe"
        assert override_victim.read_text(encoding="utf-8") == "override-safe"
        assert (root / ".env").is_symlink()
        assert (root / "docker-compose.logiclab.yml").is_symlink()
    finally:
        lab.close()


@pytest.mark.parametrize("generated_path", ["env_file", "override_file"])
def test_target_lab_refuses_symlink_at_trusted_generated_path(
    tmp_path: Path,
    generated_path: str,
) -> None:
    root = tmp_path / "target"
    root.mkdir()
    victim = tmp_path / "victim"
    victim.write_text("safe", encoding="utf-8")
    blueprint = load_blueprint(Path("engagements/tls-ids-lab.yaml"))
    lab = TargetLab(root, blueprint, "logiclab-target-password", http_client=FakeHttp())
    destination = getattr(lab, generated_path)
    try:
        try:
            destination.symlink_to(victim)
        except OSError as exc:
            pytest.skip(f"symlink creation is unavailable: {exc}")

        with pytest.raises(LabUnavailable, match="symlink"):
            lab._render_files(hmac_enabled=False)
        assert victim.read_text(encoding="utf-8") == "safe"
    finally:
        lab.close()
