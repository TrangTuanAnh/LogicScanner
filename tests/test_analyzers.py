from pathlib import Path

from logiclab.analyzers import BashAnalyzer, ComposeAnalyzer, PythonAnalyzer, SqlAnalyzer
from logiclab.schemas import FactKind


def test_python_analyzer_extracts_routes_http_edges_and_security_calls(tmp_path: Path) -> None:
    source = tmp_path / "main.py"
    source.write_text(
        "from fastapi import FastAPI\n"
        "import requests\n"
        "app = FastAPI()\n"
        "@app.post('/flow')\n"
        "def flow(payload):\n"
        "    verify_hmac_request(payload)\n"
        "    return requests.post('http://backend:8000/api/events', json=payload)\n",
        encoding="utf-8",
    )
    facts = PythonAnalyzer().analyze(source, tmp_path)
    kinds = {fact.kind for fact in facts}
    assert FactKind.ENTRY_POINT in kinds
    assert FactKind.HTTP_EDGE in kinds
    assert FactKind.SECURITY_GUARD in kinds


def test_sql_analyzer_extracts_tables_and_mutations(tmp_path: Path) -> None:
    source = tmp_path / "schema.sql"
    source.write_text(
        "CREATE TABLE request_nonces (id BIGINT PRIMARY KEY);\n"
        "INSERT INTO request_nonces(id) VALUES (1);",
        encoding="utf-8",
    )
    facts = SqlAnalyzer().analyze(source, tmp_path)
    assert {fact.kind for fact in facts} == {FactKind.DATA_MODEL, FactKind.DB_MUTATION}


def test_bash_analyzer_extracts_commands_and_environment(tmp_path: Path) -> None:
    source = tmp_path / "run.sh"
    source.write_text(
        '#!/bin/sh\nexec python main.py --iface "${CAPTURE_INTERFACE}"\n', encoding="utf-8"
    )
    facts = BashAnalyzer().analyze(source, tmp_path)
    assert {fact.kind for fact in facts} == {FactKind.COMMAND, FactKind.CONFIGURATION}


def test_compose_analyzer_extracts_services_networks_and_capabilities(tmp_path: Path) -> None:
    source = tmp_path / "docker-compose.yml"
    source.write_text(
        "services:\n"
        "  backend:\n"
        "    build: ./backend\n"
        "    cap_add: [NET_ADMIN]\n"
        "    networks: [lab]\n"
        "networks:\n"
        "  lab: {}\n",
        encoding="utf-8",
    )
    facts = ComposeAnalyzer().analyze(source, tmp_path)
    kinds = {fact.kind for fact in facts}
    assert FactKind.SERVICE in kinds
    assert FactKind.CAPABILITY in kinds
    assert FactKind.TOPOLOGY in kinds
