from __future__ import annotations

import json
import os
import secrets
import stat
import tempfile
import time
from pathlib import Path
from typing import Any

import httpx

from logiclab.commands import CommandRunner
from logiclab.experiments import HttpObservation, LabSession
from logiclab.schemas import ExperimentKind, LabBlueprint
from logiclab.security import CommandGate


class LabUnavailable(RuntimeError):
    pass


class TargetLab(LabSession):
    """Isolated Docker lab for the pinned TLS IDS repository.

    Only MySQL, backend, and realtime services are started. The target's NFStream
    sniffer and firewall controller are never part of this compose invocation.
    """

    def __init__(
        self,
        target_root: Path,
        blueprint: LabBlueprint,
        target_password: str,
        command_gate: CommandGate | None = None,
        runner: CommandRunner | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        self.target_root = target_root.resolve()
        self.blueprint = blueprint
        self.target_password = target_password
        self.command_gate = command_gate or CommandGate()
        self.runner = runner or CommandRunner()
        self.http = http_client or httpx.Client(timeout=15.0)
        # Generated files contain credentials and must not be placed in the untrusted
        # checkout, where repository-controlled symlinks could redirect writes.
        self._generated_files = tempfile.TemporaryDirectory(
            prefix=".logiclab-generated-",
            dir=self.target_root.parent,
        )
        self.generated_root = Path(self._generated_files.name).resolve()
        self.env_file = self.generated_root / ".env"
        self.override_file = self.generated_root / "docker-compose.logiclab.yml"
        self.compose_file = self.target_root / blueprint.compose_file
        self._active_profile: ExperimentKind | None = None
        self._started = False
        self._hmac_secret = secrets.token_urlsafe(32)

    def activate_profile(self, kind: ExperimentKind) -> None:
        if self._active_profile == kind and self._started:
            return
        if self._started:
            self.stop()
        self._render_files(hmac_enabled=kind == ExperimentKind.HMAC_NONCE_MUTATION)
        self._compose("up", timeout_seconds=1200)
        self._wait_ready()
        self._active_profile = kind
        self._started = True

    def close(self) -> None:
        try:
            self.http.close()
        finally:
            self._generated_files.cleanup()

    def stop(self) -> None:
        if self._started:
            self._compose("down", timeout_seconds=300)
        self._started = False

    def reset(self) -> None:
        self._require_started()
        for table in self.blueprint.reset_tables:
            self.runner.run(
                self.command_gate.build(
                    "docker_exec_mysql",
                    container="flow-mysql",
                    user=self.blueprint.database.user,
                    password=self.target_password,
                    database=self.blueprint.database.database,
                    statement=f"TRUNCATE TABLE {table};",
                )
            )

    def row_count(self, table: str, marker_ip: str | None = None) -> int:
        self._require_started()
        result = self.runner.run(
            self.command_gate.build(
                "mysql_count",
                container="flow-mysql",
                user=self.blueprint.database.user,
                password=self.target_password,
                database=self.blueprint.database.database,
                table=table,
                marker_ip=marker_ip or "",
            )
        )
        try:
            return int(result.stdout.strip())
        except ValueError as exc:
            raise LabUnavailable(f"unexpected MySQL count output: {result.stdout!r}") from exc

    def submit_untrusted_flow(self, marker_ip: str) -> HttpObservation:
        self._require_started()
        payload = {
            "Timestamp": "2026-07-16T00:00:00Z",
            "Source IP": marker_ip,
            "Destination IP": "198.18.0.99",
            "Source Port": 44444,
            "Destination Port": 443,
            "Protocol": "TCP",
            "Flow Duration": 1000,
            "Total Length of Fwd Packets": 2048,
            "Total Length of Bwd Packets": 1024,
            "Packet Length Mean": 128,
            "Packet Length Std": 10,
        }
        response = self.http.post(self._realtime_url("/flow"), json=payload)
        self._wait_for_count("flow_events", marker_ip)
        return self._http_observation(response)

    def submit_bad_hmac(self) -> HttpObservation:
        self._require_started()
        payload = {
            "event_time": "2026-07-16T00:00:00Z",
            "src_ip": "198.18.0.77",
            "dst_ip": "198.18.0.99",
            "features_json": {},
            "is_anomaly": False,
        }
        headers = {
            "X-Timestamp": str(int(time.time())),
            "X-Nonce": f"logiclab-{secrets.token_hex(12)}",
            "X-Signature": "00" * 32,
        }
        response = self.http.post(self._backend_url("/api/events"), json=payload, headers=headers)
        return self._http_observation(response)

    def _compose(self, action: str, timeout_seconds: int) -> None:
        self.runner.run(
            self.command_gate.build(
                "docker_compose",
                action=action,
                env_file=str(self.env_file),
                compose_file=str(self.compose_file),
                override_file=str(self.override_file),
                project=self.blueprint.compose_project,
                cwd=str(self.target_root),
                timeout_seconds=timeout_seconds,
            )
        )

    def _render_files(self, hmac_enabled: bool) -> None:
        self.target_root.mkdir(parents=True, exist_ok=True)
        values = {
            "MYSQL_ROOT_PASSWORD": "logiclab-root-" + secrets.token_urlsafe(12),
            "MYSQL_DATABASE": self.blueprint.database.database,
            "MYSQL_USER": self.blueprint.database.user,
            "MYSQL_PASSWORD": self.target_password,
            "MYSQL_PUBLIC_BIND": "127.0.0.1",
            "MYSQL_PUBLIC_PORT": str(self.blueprint.database.port),
            "SENSOR_NET_SUBNET": "172.29.0.0/24",
            "MYSQL_IP": "172.29.0.10",
            "BACKEND_IP": "172.29.0.20",
            "RT_IP": "172.29.0.30",
            "INGEST_MODE": "url",
            "REQUIRE_INGEST_HMAC": str(hmac_enabled).lower(),
            "INGEST_HMAC_SECRET": self._hmac_secret,
            "INGEST_HMAC_MAX_AGE_SEC": "120",
            "AUTO_BLOCK": "false",
            "MLP_THRESHOLD": "0.0",
            "ISO_THRESHOLD": "-0.1",
            "CAPTURE_INTERFACE": "lo",
        }
        self._write_generated_file(
            self.env_file,
            "".join(f"{key}={value}\n" for key, value in values.items()),
        )
        self._write_generated_file(
            self.override_file,
            """services:
  backend:
    ports:
      - \"127.0.0.1:18000:8000\"
  python-realtime:
    ports:
      - \"127.0.0.1:19000:9000\"
""",
        )

    def _write_generated_file(self, destination: Path, content: str) -> None:
        """Atomically replace a regular generated file without following symlinks."""

        if self.generated_root.is_symlink() or not self.generated_root.is_dir():
            raise LabUnavailable("trusted generated-file directory is unavailable")
        if destination.parent != self.generated_root:
            raise LabUnavailable("generated-file destination escapes trusted directory")
        if destination.is_symlink():
            raise LabUnavailable(f"refusing to replace generated-file symlink: {destination.name}")
        if destination.exists() and not stat.S_ISREG(
            destination.stat(follow_symlinks=False).st_mode
        ):
            raise LabUnavailable(
                f"refusing to replace non-regular generated file: {destination.name}"
            )

        temporary = destination.with_name(f".{destination.name}.{secrets.token_hex(16)}.tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor: int | None = None
        try:
            descriptor = os.open(temporary, flags, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                descriptor = None
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            if destination.is_symlink():
                raise LabUnavailable(
                    f"refusing to replace generated-file symlink: {destination.name}"
                )
            os.replace(temporary, destination)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + 90
        errors: list[str] = []
        while time.monotonic() < deadline:
            try:
                backend = self.http.get(self._backend_url("/health"))
                realtime = self.http.get(self._realtime_url("/docs"))
                if backend.status_code == 200 and realtime.status_code == 200:
                    return
                errors = [f"backend={backend.status_code}", f"realtime={realtime.status_code}"]
            except httpx.HTTPError as exc:
                errors = [str(exc)]
            time.sleep(2)
        raise LabUnavailable("lab did not become ready: " + "; ".join(errors))

    def _wait_for_count(self, table: str, marker_ip: str) -> None:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.row_count(table, marker_ip) > 0:
                return
            time.sleep(0.5)

    def _backend_url(self, path: str) -> str:
        backend = next(service for service in self.blueprint.services if service.name == "backend")
        assert backend.base_url is not None
        return backend.base_url.rstrip("/") + path

    def _realtime_url(self, path: str) -> str:
        realtime = next(
            service for service in self.blueprint.services if service.name == "python-realtime"
        )
        assert realtime.base_url is not None
        return realtime.base_url.rstrip("/") + path

    @staticmethod
    def _http_observation(response: httpx.Response) -> HttpObservation:
        try:
            body: dict[str, Any] = response.json()
        except (ValueError, json.JSONDecodeError):
            body = {"raw": response.text[:500]}
        return HttpObservation(status_code=response.status_code, body=body)

    def _require_started(self) -> None:
        if not self._started:
            raise LabUnavailable("lab is not running")
