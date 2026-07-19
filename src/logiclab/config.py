from __future__ import annotations

from ipaddress import ip_address
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


INSECURE_API_TOKENS = {
    "",
    "logiclab-dev-token",
    "replace-with-a-random-token-of-at-least-32-characters",
}
LEGACY_TARGET_URL = "https://github.com/TrangTuanAnh/tls-anomaly-detection-ids.git"
LEGACY_TARGET_COMMIT = "bc593b186b50f5c832a92f6ea1cbad88747d78ac"


def _default_ui_dist() -> Path:
    packaged = Path(__file__).resolve().with_name("ui_dist")
    workspace = Path(__file__).resolve().parents[2] / "ui" / "dist"
    return packaged if (packaged / "index.html").is_file() else workspace


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="LOGICLAB_",
        env_file=".env.logiclab",
        extra="ignore",
    )

    database_url: str = "postgresql+psycopg://logiclab:logiclab@127.0.0.1:15432/logiclab"
    api_token: str = Field(default="logiclab-dev-token", min_length=12)
    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8088, ge=1, le=65535)
    development_mode: bool = False
    session_cookie_secure: bool = False
    legacy_runtime_enabled: bool = False
    # Semantic claim proposal is opt-in. Leaving it off keeps the whole report
    # reproducible; turning it on trades reproducible interpretation for
    # semantic reach, and marks every such claim as INFERRED.
    proposer_enabled: bool = False
    proposer_base_url: str = "http://127.0.0.1:11434"
    proposer_model: str = ""
    proposer_max_claims: int = Field(default=25, ge=1, le=500)
    proposer_timeout_seconds: float = Field(default=120.0, gt=0, le=3_600)
    artifact_root: Path = Path(".logiclab/artifacts")
    workspace_root: Path = Path(".logiclab/workspaces")
    ui_dist: Path = Field(default_factory=_default_ui_dist)
    target_db_password: str = Field(default="logiclab-target-password", min_length=12)
    default_lab_blueprint: Path = Path("engagements/tls-ids-lab.yaml")

    def validate_control_plane(self) -> None:
        host = self.api_host.strip("[]").lower()
        try:
            loopback = ip_address(host).is_loopback
        except ValueError:
            loopback = host == "localhost"
        insecure_token = self.api_token in INSECURE_API_TOKENS or len(self.api_token) < 32
        if insecure_token and not self.development_mode:
            raise ValueError(
                "LOGICLAB_API_TOKEN must be set to a random value of at least 32 characters; "
                "development credentials are disabled by default"
            )
        if insecure_token and not loopback:
            raise ValueError("the development token may only be used on a loopback interface")
        if not loopback and not self.session_cookie_secure:
            raise ValueError(
                "non-loopback API binding requires LOGICLAB_SESSION_COOKIE_SECURE=true"
            )
        if self.proposer_enabled and not self.proposer_model.strip():
            raise ValueError(
                "LOGICLAB_PROPOSER_ENABLED=true requires LOGICLAB_PROPOSER_MODEL to name a model"
            )
