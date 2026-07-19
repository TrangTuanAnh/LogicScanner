from pathlib import Path

from fastapi.testclient import TestClient

from logiclab.api import create_app
from logiclab.config import Settings
from logiclab.storage import Storage


TARGET_URL = "https://github.com/TrangTuanAnh/tls-anomaly-detection-ids.git"
TARGET_COMMIT = "bc593b186b50f5c832a92f6ea1cbad88747d78ac"


def make_client(tmp_path: Path) -> TestClient:
    storage = Storage(f"sqlite:///{tmp_path / 'api.db'}")
    storage.create_schema()
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'api.db'}",
        api_token="test-token-123",
        development_mode=True,
        legacy_runtime_enabled=True,
        artifact_root=tmp_path / "artifacts",
        workspace_root=tmp_path / "workspaces",
    )
    return TestClient(create_app(settings=settings, storage=storage))


def engagement_body() -> dict:
    return {
        "name": "tls-ids",
        "repository": {"url": TARGET_URL, "commit": TARGET_COMMIT},
    }


def test_health_is_public_and_v1_requires_bearer_token(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    assert client.get("/health").status_code == 200
    assert client.post("/v1/engagements", json=engagement_body()).status_code == 401


def test_built_ui_is_served_same_origin_with_security_headers(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    response = client.get("/")
    assert response.status_code == 200
    assert "LogicLab" in response.text
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert client.get("/repositories/demo-repo").status_code == 200
    assert client.get("/v1/not-a-real-endpoint").status_code == 404


def test_browser_session_uses_http_only_cookie_without_local_storage_token(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    assert client.post("/v1/session", json={"token": "wrong-token-123"}).status_code == 401

    unlocked = client.post("/v1/session", json={"token": "test-token-123"})
    assert unlocked.status_code == 204
    cookie = unlocked.headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "samesite=strict" in cookie
    assert "test-token-123" not in cookie
    assert client.post("/v1/engagements", json=engagement_body()).status_code == 201

    assert client.delete("/v1/session").status_code == 204
    assert client.post("/v1/engagements", json=engagement_body()).status_code == 401


def test_browser_session_rate_limits_repeated_failures(tmp_path: Path) -> None:
    client = make_client(tmp_path)

    for _ in range(5):
        assert client.post("/v1/session", json={"token": "wrong-token-123"}).status_code == 401

    limited = client.post("/v1/session", json={"token": "wrong-token-123"})
    assert limited.status_code == 429
    assert limited.headers["retry-after"] == "60"


def test_engagement_run_and_finding_contract(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    headers = {"Authorization": "Bearer test-token-123"}
    created = client.post("/v1/engagements", json=engagement_body(), headers=headers)
    assert created.status_code == 201
    engagement_id = created.json()["id"]

    queued = client.post(f"/v1/engagements/{engagement_id}/runs", headers=headers)
    assert queued.status_code == 202
    run_id = queued.json()["id"]
    assert client.get(f"/v1/runs/{run_id}", headers=headers).json()["status"] == "QUEUED"
    assert [item["id"] for item in client.get("/v1/engagements", headers=headers).json()] == [
        engagement_id
    ]
    assert [item["id"] for item in client.get("/v1/runs", headers=headers).json()] == [run_id]
    assert client.get("/v1/findings", headers=headers).json() == []


def test_legacy_engagement_rejects_remote_model_gateway(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    body = engagement_body()
    body["models"] = {"base_url": "http://169.254.169.254/latest"}

    response = client.post(
        "/v1/engagements",
        headers={"Authorization": "Bearer test-token-123"},
        json=body,
    )

    assert response.status_code == 422


def test_legacy_runtime_rejects_unreviewed_repository_commit(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    body = engagement_body()
    body["repository"]["commit"] = "a" * 40

    response = client.post(
        "/v1/engagements",
        headers={"Authorization": "Bearer test-token-123"},
        json=body,
    )

    assert response.status_code == 403
    assert "reviewed target commit" in response.json()["detail"]


def test_unknown_resources_return_404(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    headers = {"Authorization": "Bearer test-token-123"}
    missing = "00000000-0000-0000-0000-000000000000"
    assert client.get(f"/v1/runs/{missing}", headers=headers).status_code == 404
    assert client.post(f"/v1/findings/{missing}/replay", headers=headers).status_code == 404


def test_legacy_runtime_mutations_are_disabled_by_default(tmp_path: Path) -> None:
    storage = Storage(f"sqlite:///{tmp_path / 'static.db'}")
    storage.create_schema()
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'static.db'}",
        api_token="static-only-test-token",
        development_mode=True,
        artifact_root=tmp_path / "artifacts",
        workspace_root=tmp_path / "workspaces",
    )
    client = TestClient(create_app(settings=settings, storage=storage))

    response = client.post(
        "/v1/engagements",
        headers={"Authorization": "Bearer static-only-test-token"},
        json=engagement_body(),
    )

    assert response.status_code == 403
    assert "static-only" in response.json()["detail"]


def test_control_plane_rejects_known_default_token_outside_dev_mode(tmp_path: Path) -> None:
    storage = Storage(f"sqlite:///{tmp_path / 'unsafe.db'}")
    storage.create_schema()
    app = create_app(
        Settings(
            database_url=f"sqlite:///{tmp_path / 'unsafe.db'}",
            api_token="logiclab-dev-token",
            workspace_root=tmp_path / "workspaces",
        ),
        storage=storage,
    )

    try:
        with TestClient(app):
            raise AssertionError("startup should have failed")
    except ValueError as exc:
        assert "must be set" in str(exc)


def test_non_loopback_control_plane_requires_secure_session_cookie(tmp_path: Path) -> None:
    storage = Storage(f"sqlite:///{tmp_path / 'remote.db'}")
    storage.create_schema()
    app = create_app(
        Settings(
            database_url=f"sqlite:///{tmp_path / 'remote.db'}",
            api_token="a-secure-random-control-token-123456",
            api_host="0.0.0.0",
            session_cookie_secure=False,
            workspace_root=tmp_path / "workspaces",
        ),
        storage=storage,
    )

    try:
        with TestClient(app):
            raise AssertionError("startup should have failed")
    except ValueError as exc:
        assert "SESSION_COOKIE_SECURE" in str(exc)


def test_secure_control_plane_uses_host_prefixed_cookie(tmp_path: Path) -> None:
    storage = Storage(f"sqlite:///{tmp_path / 'secure.db'}")
    storage.create_schema()
    token = "a-secure-random-control-token-123456"
    app = create_app(
        Settings(
            database_url=f"sqlite:///{tmp_path / 'secure.db'}",
            api_token=token,
            api_host="0.0.0.0",
            session_cookie_secure=True,
            workspace_root=tmp_path / "workspaces",
        ),
        storage=storage,
    )

    with TestClient(app, base_url="https://testserver") as client:
        response = client.post("/v1/session", json={"token": token})

    cookie = response.headers["set-cookie"]
    assert "__Host-logiclab_session=" in cookie
    assert "Secure" in cookie
