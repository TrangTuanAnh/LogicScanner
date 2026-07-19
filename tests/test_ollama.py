import json
from uuid import uuid4

import httpx
import pytest

from logiclab.ollama import Hunter, ModelContractError, OllamaClient
from logiclab.schemas import FactKind, HypothesisSet, StaticFact


def make_fact() -> StaticFact:
    return StaticFact(
        kind=FactKind.ENTRY_POINT,
        subject="POST /flow",
        source_path="python-real-time-service/main.py",
        line=204,
    )


def make_output(source_ref: str) -> dict:
    invariant_id = uuid4()
    return {
        "schema_version": "1.0",
        "invariants": [
            {
                "schema_version": "1.0",
                "id": str(invariant_id),
                "title": "Only trusted sensors create events",
                "expression": "unauthenticated input implies no downstream event",
                "expected_outcome": {"flow_event_delta": 0},
                "evidence_refs": [source_ref],
            }
        ],
        "hypotheses": [
            {
                "schema_version": "1.0",
                "id": str(uuid4()),
                "invariant_id": str(invariant_id),
                "title": "Untrusted flow is re-signed",
                "rationale": "The route has no guard.",
                "candidate_entry_point": "POST /flow",
                "experiment_kind": "trust_laundering",
                "source_refs": [source_ref],
            }
        ],
    }


def client_for_output(output: dict) -> OllamaClient:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": "hunter"}]})
        assert request.url.path == "/api/chat"
        body = json.loads(request.content)
        assert body["stream"] is False
        assert body["keep_alive"] == 0
        assert body["options"]["temperature"] == 0
        assert body["format"] == HypothesisSet.model_json_schema()
        return httpx.Response(200, json={"message": {"content": json.dumps(output)}})

    return OllamaClient(
        base_url="http://ollama.test",
        timeout_seconds=5,
        transport=httpx.MockTransport(handler),
    )


def test_hunter_validates_structured_output_and_source_references() -> None:
    fact = make_fact()
    source_ref = "python-real-time-service/main.py:204"
    result = Hunter(client_for_output(make_output(source_ref)), "hunter").generate([fact])
    assert result.hypotheses[0].source_refs == [source_ref]


def test_hunter_rejects_hallucinated_source_reference() -> None:
    fact = make_fact()
    with pytest.raises(ModelContractError, match="unknown source reference"):
        Hunter(client_for_output(make_output("invented.py:999")), "hunter").generate([fact])


def test_hunter_rejects_model_command_fields() -> None:
    source_ref = "python-real-time-service/main.py:204"
    output = make_output(source_ref)
    output["hypotheses"][0]["command"] = "docker compose up"
    with pytest.raises(ModelContractError):
        Hunter(client_for_output(output), "hunter").generate([make_fact()])
