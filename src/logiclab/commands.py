from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from typing import Mapping

from logiclab.security import CommandSpec, Redactor


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


class CommandExecutionError(RuntimeError):
    pass


class CommandRunner:
    _inherited_environment = {
        "COMSPEC",
        "LANG",
        "LC_ALL",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "WINDIR",
    }

    def __init__(self, redactor: Redactor | None = None) -> None:
        self.redactor = redactor or Redactor()

    def run(self, spec: CommandSpec, env: Mapping[str, str] | None = None) -> CommandResult:
        if spec.shell:
            raise CommandExecutionError("shell execution is prohibited")
        # Repository tools are an untrusted boundary. Inheriting the complete host
        # environment would expose cloud credentials, tokens, and proxy secrets to
        # Git and (eventually) build processes.
        process_env = {
            key: value
            for key, value in os.environ.items()
            if key.upper() in self._inherited_environment
        }
        process_env.update(
            {
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_TERMINAL_PROMPT": "0",
            }
        )
        if env:
            process_env.update(env)
        process_env.update(dict(spec.environment))
        try:
            completed = subprocess.run(
                list(spec.argv),
                cwd=spec.cwd,
                env=process_env,
                shell=False,
                capture_output=True,
                text=True,
                timeout=spec.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise CommandExecutionError(
                f"command {spec.name} failed to start or timed out"
            ) from exc
        result = CommandResult(
            returncode=completed.returncode,
            stdout=str(self.redactor.redact(completed.stdout)),
            stderr=str(self.redactor.redact(completed.stderr)),
        )
        if result.returncode != 0:
            message = (result.stderr or result.stdout).strip()
            raise CommandExecutionError(
                f"command {spec.name} failed ({result.returncode}): {message}"
            )
        return result
