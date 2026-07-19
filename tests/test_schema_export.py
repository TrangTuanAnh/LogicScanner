from logiclab.schema_export import export_public_schemas


def test_all_public_models_export_json_schema() -> None:
    schemas = export_public_schemas()
    assert set(schemas) == {
        "Engagement",
        "LabBlueprint",
        "StaticFact",
        "Invariant",
        "Hypothesis",
        "Experiment",
        "Evidence",
        "Verification",
        "Finding",
    }
    assert all(schema["type"] == "object" for schema in schemas.values())
