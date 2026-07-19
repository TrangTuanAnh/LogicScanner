from pathlib import Path

from logiclab.commands import CommandResult
from logiclab.schemas import Engagement
from logiclab.workspace import TargetWorkspace


class FakeRunner:
    def __init__(self, commit: str) -> None:
        self.commit = commit
        self.commands = []

    def run(self, spec):
        self.commands.append(spec)
        if spec.name == "git_clone":
            Path(spec.argv[-1]).mkdir(parents=True)
            (Path(spec.argv[-1]) / ".git").mkdir()
        if spec.name == "git_rev_parse":
            return CommandResult(0, self.commit + "\n", "")
        return CommandResult(0, "", "")


def test_target_workspace_clones_checks_out_and_verifies_pin(tmp_path: Path) -> None:
    commit = "bc593b186b50f5c832a92f6ea1cbad88747d78ac"
    engagement = Engagement(
        name="tls",
        repository={
            "url": "https://github.com/TrangTuanAnh/tls-anomaly-detection-ids.git",
            "commit": commit,
        },
    )
    runner = FakeRunner(commit)
    target = TargetWorkspace(tmp_path, runner=runner).prepare(engagement)
    assert target.is_dir()
    assert [command.name for command in runner.commands] == [
        "git_clone",
        "git_checkout",
        "git_rev_parse",
    ]
