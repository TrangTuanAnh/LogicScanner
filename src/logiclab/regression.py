from __future__ import annotations

from logiclab.artifacts import ArtifactStore, StoredArtifact
from logiclab.schemas import ExperimentKind


class RegressionGenerator:
    """Generate external regression tests; never write into the target clone."""

    def __init__(self, artifacts: ArtifactStore) -> None:
        self.artifacts = artifacts

    def generate(self, kind: ExperimentKind) -> StoredArtifact:
        if kind is ExperimentKind.TRUST_LAUNDERING:
            return self.artifacts.put_python("regression-tests", _TRUST_LAUNDERING_TEST)
        if kind is ExperimentKind.HMAC_NONCE_MUTATION:
            return self.artifacts.put_python("regression-tests", _HMAC_NONCE_TEST)
        raise ValueError(f"unsupported regression kind: {kind}")


_TRUST_LAUNDERING_TEST = """\"\"\"Regression guard for unauthenticated realtime flow ingestion.

Run only against the isolated LogicLab target: pytest <this-file>.
It deliberately fails on the vulnerable commit and passes after an ingress
authentication fix rejects external flow submissions.
\"\"\"
import os

import httpx
import pytest

pytestmark = pytest.mark.integration


def test_untrusted_realtime_flow_is_rejected() -> None:
    realtime_url = os.environ.get("LOGICLAB_REALTIME_URL", "http://127.0.0.1:19000")
    response = httpx.post(
        f"{realtime_url}/flow",
        json={"Source IP": "198.18.0.42", "Destination IP": "203.0.113.9", "Bytes": 1},
        timeout=10,
    )
    assert response.status_code in {401, 403}, response.text
"""


_HMAC_NONCE_TEST = """\"\"\"Regression guard for nonce persistence before HMAC verification.

The integration fixture supplies ``nonce_count`` from the isolated target
database. It deliberately fails on a vulnerable target that records a nonce
for a rejected signature.
\"\"\"
import os
import time

import httpx
import pytest

pytestmark = pytest.mark.integration


@pytest.fixture
def nonce_count():
    connector = pytest.importorskip("mysql.connector")
    config = {
        "host": os.environ.get("LOGICLAB_MYSQL_HOST", "127.0.0.1"),
        "port": int(os.environ.get("LOGICLAB_MYSQL_PORT", "13306")),
        "user": os.environ.get("LOGICLAB_MYSQL_USER", "tls_user"),
        "password": os.environ["LOGICLAB_TARGET_DB_PASSWORD"],
        "database": os.environ.get("LOGICLAB_MYSQL_DATABASE", "tls_ids"),
    }

    def count() -> int:
        connection = connector.connect(**config)
        try:
            cursor = connection.cursor()
            cursor.execute("SELECT COUNT(*) FROM request_nonces")
            return int(cursor.fetchone()[0])
        finally:
            connection.close()

    return count


def test_rejected_hmac_does_not_write_a_nonce(nonce_count) -> None:
    backend_url = os.environ.get("LOGICLAB_BACKEND_URL", "http://127.0.0.1:18000")
    before = nonce_count()
    response = httpx.post(
        f"{backend_url}/api/events",
        headers={"X-Timestamp": str(int(time.time())), "X-Nonce": "bad-signature-regression", "X-Signature": "00"},
        json={
            "event_time": "2026-01-01T00:00:00Z",
            "src_ip": "198.18.0.77",
            "dst_ip": "198.18.0.99",
            "features_json": {},
            "is_anomaly": False,
        },
        timeout=10,
    )
    assert response.status_code == 401, response.text
    assert nonce_count() == before
"""
