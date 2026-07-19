from pathlib import Path

from sqlalchemy import inspect, text

from logiclab.storage import Storage


def test_alembic_upgrades_existing_control_database_to_repository_intelligence(
    tmp_path: Path,
) -> None:
    storage = Storage(f"sqlite:///{tmp_path / 'migration.db'}")

    storage.upgrade_schema("20260716_0001")
    assert "repository_analyses" not in inspect(storage.engine).get_table_names()

    storage.upgrade_schema()

    assert "repository_analyses" in inspect(storage.engine).get_table_names()
    with storage.engine.connect() as connection:
        revision = connection.execute(text("select version_num from alembic_version")).scalar_one()
    assert revision == "20260716_0003"
