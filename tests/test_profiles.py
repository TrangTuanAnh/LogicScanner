from pathlib import Path

from logiclab.profiles import load_blueprint, load_engagement


def test_example_engagement_and_blueprint_are_loadable() -> None:
    root = Path(__file__).parents[1]
    engagement = load_engagement(root / "engagements" / "tls-ids.yaml")
    blueprint = load_blueprint(root / "engagements" / "tls-ids-lab.yaml")
    assert engagement.repository.commit == "bc593b186b50f5c832a92f6ea1cbad88747d78ac"
    assert {service.name for service in blueprint.services} == {"backend", "python-realtime", "db"}
