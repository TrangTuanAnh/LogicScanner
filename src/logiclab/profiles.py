from __future__ import annotations

from pathlib import Path
from typing import TypeVar

import yaml
from pydantic import BaseModel

from logiclab.schemas import Engagement, LabBlueprint


T = TypeVar("T", bound=BaseModel)


def _load(path: Path, schema: type[T]) -> T:
    resolved = path.resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"profile does not exist: {path}")
    document = yaml.safe_load(resolved.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"profile must be a YAML mapping: {path}")
    return schema.model_validate(document)


def load_engagement(path: Path) -> Engagement:
    return _load(path, Engagement)


def load_blueprint(path: Path) -> LabBlueprint:
    return _load(path, LabBlueprint)
