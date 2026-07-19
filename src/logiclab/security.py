from __future__ import annotations

import re
from ipaddress import ip_address
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class SecurityViolation(ValueError):
    """Raised when an operation crosses an engagement or command boundary."""


@dataclass(frozen=True)
class CommandSpec:
    name: str
    argv: tuple[str, ...]
    cwd: Path | None = None
    timeout_seconds: int = 300
    shell: bool = False
    environment: tuple[tuple[str, str], ...] = ()


class ScopeGate:
    def __init__(self, repository_url: str, commit: str, workspace_root: Path) -> None:
        self.repository_url = repository_url
        self.commit = commit.lower()
        self.workspace_root = workspace_root.resolve()

    def validate_clone(self, repository_url: str, commit: str, destination: Path) -> Path:
        if repository_url != self.repository_url:
            raise SecurityViolation("repository is outside engagement scope")
        if commit.lower() != self.commit:
            raise SecurityViolation("commit is outside engagement scope")
        resolved = destination.resolve()
        if not resolved.is_relative_to(self.workspace_root):
            raise SecurityViolation("destination escapes engagement workspace")
        return resolved


class CommandGate:
    """Maps typed operations to argument vectors; no raw shell is accepted."""

    def build(self, template: str, **params: str | int) -> CommandSpec:
        if template == "git_clone":
            return CommandSpec(
                name=template,
                argv=(
                    "git",
                    "clone",
                    "--filter=blob:none",
                    "--no-checkout",
                    str(params["url"]),
                    str(params["destination"]),
                ),
                timeout_seconds=300,
            )
        if template == "git_checkout":
            return CommandSpec(
                name=template,
                argv=("git", "checkout", "--detach", str(params["commit"])),
                cwd=Path(str(params["cwd"])),
                timeout_seconds=120,
            )
        if template == "git_rev_parse":
            return CommandSpec(
                name=template,
                argv=("git", "rev-parse", "HEAD"),
                cwd=Path(str(params["cwd"])),
                timeout_seconds=30,
            )
        if template == "docker_compose":
            action = str(params["action"])
            allowed_actions = {"build", "up", "down", "ps", "logs"}
            if action not in allowed_actions:
                raise SecurityViolation("docker compose action is not allowlisted")
            argv = [
                "docker",
                "compose",
                "--env-file",
                str(params["env_file"]),
                "-f",
                str(params["compose_file"]),
            ]
            override_file = params.get("override_file")
            if override_file:
                argv.extend(["-f", str(override_file)])
            argv.extend(["-p", str(params["project"]), action])
            if action == "up":
                argv.extend(["--build", "-d", "db", "backend", "python-realtime"])
            elif action == "down":
                argv.extend(["--remove-orphans"])
            return CommandSpec(
                name=template,
                argv=tuple(argv),
                cwd=Path(str(params["cwd"])),
                timeout_seconds=int(params.get("timeout_seconds", 900)),
            )
        if template == "docker_exec_mysql":
            statement = str(params["statement"])
            match = re.fullmatch(r"(?i)\s*TRUNCATE\s+TABLE\s+([a-z0-9_]+)\s*;?\s*", statement)
            if match is None or match.group(1).lower() not in {
                "flow_events",
                "request_nonces",
                "firewall_actions",
            }:
                raise SecurityViolation("SQL reset statement is not allowlisted")
            return CommandSpec(
                name=template,
                argv=(
                    "docker",
                    "exec",
                    "-e",
                    "MYSQL_PWD",
                    str(params["container"]),
                    "mysql",
                    "-N",
                    "-B",
                    "-u",
                    str(params["user"]),
                    str(params["database"]),
                    "-e",
                    statement,
                ),
                timeout_seconds=60,
                environment=(("MYSQL_PWD", str(params["password"])),),
            )
        if template == "mysql_count":
            table = str(params["table"])
            allowed_tables = {"flow_events", "request_nonces", "firewall_actions"}
            if table not in allowed_tables:
                raise SecurityViolation("database table is not allowlisted")
            statement = f"SELECT COUNT(*) FROM {table}"
            marker_ip = params.get("marker_ip")
            if marker_ip:
                try:
                    ip_address(str(marker_ip))
                except ValueError as exc:
                    raise SecurityViolation("marker IP is invalid") from exc
                if table != "flow_events":
                    raise SecurityViolation("marker IP filtering only applies to flow_events")
                statement += f" WHERE src_ip = '{marker_ip}'"
            statement += ";"
            return CommandSpec(
                name=template,
                argv=(
                    "docker",
                    "exec",
                    "-e",
                    "MYSQL_PWD",
                    str(params["container"]),
                    "mysql",
                    "-N",
                    "-B",
                    "-u",
                    str(params["user"]),
                    str(params["database"]),
                    "-e",
                    statement,
                ),
                timeout_seconds=60,
                environment=(("MYSQL_PWD", str(params["password"])),),
            )
        raise SecurityViolation(f"command template is not allowlisted: {template}")


class Redactor:
    _secret_keys = re.compile(r"(?i)(password|secret|token|authorization|api[_-]?key|cookie)")
    _bearer = re.compile(r"(?i)(authorization\s*:\s*bearer\s+|bearer\s+)[^\s,;]+")
    _url_credentials = re.compile(r"(?i)([a-z][a-z0-9+.-]*://)[^:/@\s]+:[^@/\s]+@")
    _query_secret = re.compile(r"(?i)([?&](?:password|secret|token|api[_-]?key)=)[^&#\s]+")

    def redact(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: "[REDACTED]" if self._secret_keys.search(str(key)) else self.redact(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [self.redact(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self.redact(item) for item in value)
        if isinstance(value, str):
            redacted = self._bearer.sub(lambda match: match.group(1) + "[REDACTED]", value)
            redacted = self._url_credentials.sub(
                lambda match: match.group(1) + "[REDACTED]@", redacted
            )
            return self._query_secret.sub(lambda match: match.group(1) + "[REDACTED]", redacted)
        return value
