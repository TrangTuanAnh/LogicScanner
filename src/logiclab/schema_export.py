from __future__ import annotations

from typing import Any

from logiclab.schemas import (
    Engagement,
    Evidence,
    Experiment,
    Finding,
    Hypothesis,
    Invariant,
    LabBlueprint,
    StaticFact,
    Verification,
)


PUBLIC_SCHEMAS = {
    model.__name__: model
    for model in (
        Engagement,
        LabBlueprint,
        StaticFact,
        Invariant,
        Hypothesis,
        Experiment,
        Evidence,
        Verification,
        Finding,
    )
}


def export_public_schemas() -> dict[str, dict[str, Any]]:
    """Return versioned public JSON Schemas suitable for API clients and audit."""
    return {name: model.model_json_schema() for name, model in PUBLIC_SCHEMAS.items()}
