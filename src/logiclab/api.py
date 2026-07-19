from __future__ import annotations

import hmac
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from hashlib import sha256
from threading import Lock
from uuid import UUID

from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    HTTPException,
    Query,
    Request,
    Response,
    Security,
    status,
)
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from logiclab.config import LEGACY_TARGET_COMMIT, LEGACY_TARGET_URL, Settings
from logiclab.repository_analysis import (
    RepositoryAnalysisManager,
    RepositoryAnalysisRequest,
    RepositoryAnalysisResponse,
)
from logiclab.schemas import ArtifactRef, Engagement, Finding, Run, Verification
from logiclab.snapshots import GitSnapshotFetcher
from logiclab.storage import Storage


bearer = HTTPBearer(auto_error=False)
SESSION_COOKIE = "logiclab_session"
SESSION_TTL_SECONDS = 8 * 60 * 60


class SessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=1, max_length=4096)


class RepositoryAnalysisCollection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[RepositoryAnalysisResponse]
    total: int = Field(ge=0)


def _build_proposer(settings: Settings):
    """Construct the optional semantic proposer, or ``None`` when disabled.

    The model stack is imported lazily so a default deployment never loads it.
    """

    if not settings.proposer_enabled:
        return None
    from logiclab.proposals import ProposerPolicy, build_proposer

    return build_proposer(
        base_url=settings.proposer_base_url,
        model=settings.proposer_model,
        timeout_seconds=settings.proposer_timeout_seconds,
        policy=ProposerPolicy(max_proposals=settings.proposer_max_claims),
    )


def create_app(
    settings: Settings | None = None,
    storage: Storage | None = None,
    analysis_manager: RepositoryAnalysisManager | None = None,
) -> FastAPI:
    settings = settings or Settings()
    owns_storage = storage is None
    storage = storage or Storage(settings.database_url)
    analysis_manager = analysis_manager or RepositoryAnalysisManager(
        storage=storage,
        fetcher=GitSnapshotFetcher(settings.workspace_root / "repository-snapshots"),
        proposer=_build_proposer(settings),
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        settings.validate_control_plane()
        if owns_storage:
            storage.upgrade_schema()
        yield

    app = FastAPI(title="LogicLab Control API", version="0.1.0", lifespan=lifespan)
    app.state.settings = settings
    app.state.storage = storage
    app.state.analysis_manager = analysis_manager

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
            "base-uri 'self'; frame-ancestors 'none'",
        )
        if settings.session_cookie_secure:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        return response

    session_cookie = "__Host-logiclab_session" if settings.session_cookie_secure else SESSION_COOKIE
    login_failures: dict[str, deque[float]] = defaultdict(deque)
    login_lock = Lock()

    def session_value(expires_at: int) -> str:
        payload = str(expires_at)
        signature = hmac.new(
            settings.api_token.encode("utf-8"), payload.encode("ascii"), sha256
        ).hexdigest()
        return f"{payload}.{signature}"

    def valid_session(value: str | None) -> bool:
        if not value:
            return False
        try:
            expiry_text, signature = value.split(".", 1)
            expires_at = int(expiry_text)
        except (TypeError, ValueError):
            return False
        if expires_at < int(time.time()):
            return False
        expected = session_value(expires_at).split(".", 1)[1]
        return hmac.compare_digest(signature, expected)

    def require_token(
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = Security(bearer),
    ) -> None:
        bearer_valid = (
            credentials is not None
            and credentials.scheme.lower() == "bearer"
            and hmac.compare_digest(credentials.credentials, settings.api_token)
        )
        if not bearer_valid and not valid_session(request.cookies.get(session_cookie)):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required"
            )

    def require_legacy_runtime() -> None:
        if not settings.legacy_runtime_enabled:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Legacy target execution is disabled; universal analysis is static-only",
            )

    @app.get("/health")
    def health() -> dict[str, str]:
        try:
            database = "connected" if storage.ping() else "unavailable"
        except Exception:
            database = "unavailable"
        return {
            "status": "ok" if database == "connected" else "degraded",
            "version": "0.1.0",
            "database": database,
            "model_gateway": "not used by universal static analysis",
            "runner": "legacy enabled" if settings.legacy_runtime_enabled else "static-only",
            "policy": "default-deny",
        }

    @app.post("/v1/session", status_code=status.HTTP_204_NO_CONTENT)
    def create_session(payload: SessionRequest, request: Request, response: Response) -> Response:
        client_key = request.client.host if request.client else "unknown"
        now = time.monotonic()
        with login_lock:
            attempts = login_failures[client_key]
            while attempts and attempts[0] < now - 60:
                attempts.popleft()
            if len(attempts) >= 5:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many failed authentication attempts",
                    headers={"Retry-After": "60"},
                )
        if not hmac.compare_digest(payload.token, settings.api_token):
            with login_lock:
                login_failures[client_key].append(now)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        with login_lock:
            login_failures.pop(client_key, None)
        expires_at = int(time.time()) + SESSION_TTL_SECONDS
        response.set_cookie(
            session_cookie,
            session_value(expires_at),
            max_age=SESSION_TTL_SECONDS,
            httponly=True,
            samesite="strict",
            secure=settings.session_cookie_secure,
            path="/",
        )
        response.status_code = status.HTTP_204_NO_CONTENT
        return response

    @app.delete("/v1/session", status_code=status.HTTP_204_NO_CONTENT)
    def delete_session(response: Response) -> Response:
        response.delete_cookie(
            session_cookie,
            path="/",
            httponly=True,
            samesite="strict",
            secure=settings.session_cookie_secure,
        )
        response.status_code = status.HTTP_204_NO_CONTENT
        return response

    @app.post(
        "/v1/engagements",
        response_model=Engagement,
        status_code=status.HTTP_201_CREATED,
        dependencies=[Depends(require_token), Depends(require_legacy_runtime)],
    )
    def create_engagement(engagement: Engagement) -> Engagement:
        if (
            engagement.repository.url != LEGACY_TARGET_URL
            or engagement.repository.commit != LEGACY_TARGET_COMMIT
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Legacy runtime is pinned to its reviewed target commit",
            )
        try:
            return storage.create_engagement(engagement)
        except Exception as exc:
            if "UNIQUE" in str(exc).upper():
                raise HTTPException(status_code=409, detail="Engagement already exists") from exc
            raise

    @app.get(
        "/v1/engagements",
        response_model=list[Engagement],
        dependencies=[Depends(require_token)],
    )
    def list_engagements() -> list[Engagement]:
        return storage.list_engagements()

    @app.post(
        "/v1/repository-analyses",
        response_model=RepositoryAnalysisResponse,
        status_code=status.HTTP_202_ACCEPTED,
        dependencies=[Depends(require_token)],
    )
    def create_repository_analysis(
        payload: RepositoryAnalysisRequest,
        background_tasks: BackgroundTasks,
    ) -> RepositoryAnalysisResponse:
        analysis = analysis_manager.enqueue(payload)
        background_tasks.add_task(analysis_manager.process, analysis.id)
        return analysis.to_response()

    @app.get(
        "/v1/repository-analyses",
        response_model=RepositoryAnalysisCollection,
        dependencies=[Depends(require_token)],
    )
    def list_repository_analyses(
        limit: int = Query(default=20, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
    ) -> RepositoryAnalysisCollection:
        items = [
            item.to_response(include_details=False)
            for item in analysis_manager.list(limit=limit, offset=offset)
        ]
        return RepositoryAnalysisCollection(items=items, total=analysis_manager.count())

    @app.get(
        "/v1/repository-analyses/{analysis_id}",
        response_model=RepositoryAnalysisResponse,
        dependencies=[Depends(require_token)],
    )
    def get_repository_analysis(analysis_id: UUID) -> RepositoryAnalysisResponse:
        try:
            return analysis_manager.get(analysis_id).to_response()
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post(
        "/v1/engagements/{engagement_id}/runs",
        response_model=Run,
        status_code=status.HTTP_202_ACCEPTED,
        dependencies=[Depends(require_token), Depends(require_legacy_runtime)],
    )
    def create_run(engagement_id: UUID) -> Run:
        try:
            return storage.create_run(engagement_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get(
        "/v1/runs/{run_id}",
        response_model=Run,
        dependencies=[Depends(require_token)],
    )
    def get_run(run_id: UUID) -> Run:
        try:
            return storage.get_run(run_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get(
        "/v1/runs",
        response_model=list[Run],
        dependencies=[Depends(require_token)],
    )
    def list_runs(engagement_id: UUID | None = None) -> list[Run]:
        return storage.list_runs(engagement_id=engagement_id)

    @app.get(
        "/v1/findings",
        response_model=list[Finding],
        dependencies=[Depends(require_token)],
    )
    def list_findings(engagement_id: UUID | None = None) -> list[Finding]:
        return storage.list_findings(engagement_id)

    @app.get(
        "/v1/findings/{finding_id}",
        response_model=Finding,
        dependencies=[Depends(require_token)],
    )
    def get_finding(finding_id: UUID) -> Finding:
        try:
            return storage.get_finding(finding_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post(
        "/v1/findings/{finding_id}/replay",
        response_model=Run,
        status_code=status.HTTP_202_ACCEPTED,
        dependencies=[Depends(require_token), Depends(require_legacy_runtime)],
    )
    def replay_finding(finding_id: UUID) -> Run:
        try:
            finding = storage.get_finding(finding_id)
            return storage.create_run(finding.engagement_id, finding_id=finding.id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get(
        "/v1/findings/{finding_id}/artifacts",
        response_model=list[ArtifactRef],
        dependencies=[Depends(require_token)],
    )
    def finding_artifacts(finding_id: UUID) -> list[ArtifactRef]:
        try:
            finding = storage.get_finding(finding_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        artifacts = []
        if finding.regression_artifact is not None:
            artifacts.append(finding.regression_artifact)
        for evidence_id in finding.evidence_ids:
            try:
                artifacts.append(storage.get_evidence(evidence_id).artifact)
            except KeyError:
                continue
        return artifacts

    @app.get(
        "/v1/verifications/{verification_id}",
        response_model=Verification,
        dependencies=[Depends(require_token)],
    )
    def get_verification(verification_id: UUID) -> Verification:
        try:
            return storage.get_verification(verification_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    ui_dist = settings.ui_dist.resolve()
    ui_index = ui_dist / "index.html"
    ui_assets = ui_dist / "assets"
    if ui_index.is_file():
        if ui_assets.is_dir():
            app.mount("/assets", StaticFiles(directory=ui_assets), name="ui-assets")

        @app.get("/", include_in_schema=False)
        def ui_root() -> FileResponse:
            return FileResponse(ui_index)

        @app.get("/{full_path:path}", include_in_schema=False)
        def ui_route(full_path: str) -> FileResponse:
            if full_path == "health" or full_path.startswith("v1/"):
                raise HTTPException(status_code=404, detail="Not found")
            candidate = (ui_dist / full_path).resolve()
            if candidate.is_relative_to(ui_dist) and candidate.is_file():
                return FileResponse(candidate)
            return FileResponse(ui_index)

    return app


app = create_app()
