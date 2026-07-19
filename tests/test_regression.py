import py_compile
from pathlib import Path

from logiclab.artifacts import ArtifactStore
from logiclab.regression import RegressionGenerator
from logiclab.schemas import ExperimentKind


def test_generated_regression_tests_are_python_files_that_compile(tmp_path: Path) -> None:
    generator = RegressionGenerator(ArtifactStore(tmp_path))
    artifacts = [
        generator.generate(ExperimentKind.TRUST_LAUNDERING),
        generator.generate(ExperimentKind.HMAC_NONCE_MUTATION),
    ]
    for artifact in artifacts:
        assert artifact.path.suffix == ".py"
        py_compile.compile(str(artifact.path), doraise=True)
        assert "pytestmark" in artifact.path.read_text(encoding="utf-8")
