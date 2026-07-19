import sys

import pytest

from logiclab.commands import CommandExecutionError, CommandRunner
from logiclab.security import CommandSpec


def test_command_runner_captures_output_and_redacts_secrets() -> None:
    result = CommandRunner().run(
        CommandSpec(
            name="test",
            argv=(sys.executable, "-c", "print('Authorization: Bearer secret-token')"),
            timeout_seconds=10,
        )
    )
    assert "secret-token" not in result.stdout


def test_command_runner_rejects_shell_and_nonzero_exit() -> None:
    with pytest.raises(CommandExecutionError):
        CommandRunner().run(CommandSpec(name="shell", argv=("echo", "x"), shell=True))
    with pytest.raises(CommandExecutionError, match=r"failed \(3\)"):
        CommandRunner().run(
            CommandSpec(name="failure", argv=(sys.executable, "-c", "raise SystemExit(3)"))
        )


def test_command_runner_does_not_inherit_unapproved_host_secrets(monkeypatch) -> None:
    monkeypatch.setenv("LOGICLAB_TEST_HOST_SECRET", "must-not-cross-boundary")
    result = CommandRunner().run(
        CommandSpec(
            name="clean-environment",
            argv=(
                sys.executable,
                "-c",
                "import os; print(os.getenv('LOGICLAB_TEST_HOST_SECRET', 'clean'))",
            ),
            timeout_seconds=10,
        )
    )
    assert result.stdout.strip() == "clean"


def test_command_runner_accepts_only_explicit_extra_environment() -> None:
    result = CommandRunner().run(
        CommandSpec(
            name="explicit-environment",
            argv=(sys.executable, "-c", "import os; print(os.environ['SAFE_INPUT'])"),
            timeout_seconds=10,
        ),
        env={"SAFE_INPUT": "present"},
    )
    assert result.stdout.strip() == "present"


def test_command_runner_passes_spec_secrets_outside_process_argv() -> None:
    secret = "spec-only-secret"
    spec = CommandSpec(
        name="spec-environment",
        argv=(sys.executable, "-c", "import os; print(os.environ['SAFE_SECRET'])"),
        environment=(("SAFE_SECRET", secret),),
        timeout_seconds=10,
    )
    result = CommandRunner().run(spec)

    assert result.stdout.strip() == secret
    assert all(secret not in argument for argument in spec.argv)
