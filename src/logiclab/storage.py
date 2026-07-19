from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, JSON, String, create_engine, func, select, text, update
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from logiclab.schemas import Engagement, Evidence, Finding, Run, RunStatus, Verification
from logiclab.repository_analysis import RepositoryAnalysis, RepositoryAnalysisStatus


class Base(DeclarativeBase):
    pass


class EngagementRow(Base):
    __tablename__ = "engagements"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RunRow(Base):
    __tablename__ = "runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("engagements.id"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class FindingRow(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    engagement_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("engagements.id"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class EvidenceRow(Base):
    __tablename__ = "evidence"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    experiment_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)


class VerificationRow(Base):
    __tablename__ = "verifications"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    hypothesis_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    decision: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AuditEventRow(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    subject_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RepositoryAnalysisRow(Base):
    __tablename__ = "repository_analyses"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    repository_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    commit: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Storage:
    def __init__(self, database_url: str) -> None:
        connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
        self.engine = create_engine(database_url, pool_pre_ping=True, connect_args=connect_args)
        self._session = sessionmaker(bind=self.engine, expire_on_commit=False)

    def create_schema(self) -> None:
        """Create tables for isolated tests only; production uses Alembic."""
        Base.metadata.create_all(self.engine)

    def upgrade_schema(self, revision: str = "head") -> None:
        """Upgrade the control database through the versioned Alembic history."""
        from alembic import command
        from alembic.config import Config

        packaged = Path(__file__).resolve().with_name("migrations")
        workspace = Path(__file__).resolve().parents[2] / "migrations"
        script_location = packaged if packaged.is_dir() else workspace
        if not (script_location / "env.py").is_file():
            raise RuntimeError(f"Alembic migrations are unavailable: {script_location}")
        config = Config()
        config.set_main_option("script_location", str(script_location))
        database_url = self.engine.url.render_as_string(hide_password=False)
        config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
        command.upgrade(config, revision)

    def ping(self) -> bool:
        with self.engine.connect() as connection:
            connection.execute(text("select 1"))
        return True

    def create_engagement(self, engagement: Engagement) -> Engagement:
        row = EngagementRow(
            id=str(engagement.id),
            payload=engagement.model_dump(mode="json"),
            created_at=engagement.created_at,
        )
        with self._session.begin() as session:
            session.add(row)
            self._audit(session, "engagement.created", str(engagement.id))
        return engagement

    def get_engagement(self, engagement_id: UUID) -> Engagement:
        with self._session() as session:
            row = session.get(EngagementRow, str(engagement_id))
            if row is None:
                raise KeyError(f"engagement not found: {engagement_id}")
            return Engagement.model_validate(row.payload)

    def list_engagements(self) -> list[Engagement]:
        statement = select(EngagementRow).order_by(EngagementRow.created_at, EngagementRow.id)
        with self._session() as session:
            return [Engagement.model_validate(row.payload) for row in session.scalars(statement)]

    def create_run(self, engagement_id: UUID, finding_id: UUID | None = None) -> Run:
        self.get_engagement(engagement_id)
        run = Run(engagement_id=engagement_id, finding_id=finding_id)
        row = RunRow(
            id=str(run.id),
            engagement_id=str(engagement_id),
            status=run.status.value,
            payload=run.model_dump(mode="json"),
            created_at=run.created_at,
            updated_at=run.updated_at,
        )
        with self._session.begin() as session:
            session.add(row)
            self._audit(
                session,
                "run.queued",
                str(run.id),
                {
                    "engagement_id": str(engagement_id),
                    "finding_id": str(finding_id) if finding_id else None,
                },
            )
        return run

    def get_run(self, run_id: UUID) -> Run:
        with self._session() as session:
            row = session.get(RunRow, str(run_id))
            if row is None:
                raise KeyError(f"run not found: {run_id}")
            return Run.model_validate(row.payload)

    def list_queued_runs(self, limit: int = 1) -> list[Run]:
        statement = (
            select(RunRow)
            .where(RunRow.status == RunStatus.QUEUED.value)
            .order_by(RunRow.created_at, RunRow.id)
            .limit(limit)
        )
        with self._session() as session:
            return [Run.model_validate(row.payload) for row in session.scalars(statement)]

    def list_runs(
        self,
        engagement_id: UUID | None = None,
        status: RunStatus | None = None,
    ) -> list[Run]:
        statement = select(RunRow).order_by(RunRow.created_at.desc(), RunRow.id)
        if engagement_id is not None:
            statement = statement.where(RunRow.engagement_id == str(engagement_id))
        if status is not None:
            statement = statement.where(RunRow.status == status.value)
        with self._session() as session:
            return [Run.model_validate(row.payload) for row in session.scalars(statement)]

    def update_run(self, run_id: UUID, status: RunStatus, error: str | None = None) -> Run:
        with self._session.begin() as session:
            row = session.get(RunRow, str(run_id))
            if row is None:
                raise KeyError(f"run not found: {run_id}")
            run = Run.model_validate(row.payload).model_copy(
                update={"status": status, "error": error, "updated_at": datetime.now(timezone.utc)}
            )
            row.status = run.status.value
            row.updated_at = run.updated_at
            row.payload = run.model_dump(mode="json")
            self._audit(session, f"run.{status.value.lower()}", str(run_id), {"error": error})
        return run

    def save_finding(self, finding: Finding) -> Finding:
        with self._session.begin() as session:
            row = session.get(FindingRow, str(finding.id))
            payload = finding.model_dump(mode="json")
            if row is None:
                row = FindingRow(
                    id=str(finding.id),
                    engagement_id=str(finding.engagement_id),
                    status=finding.status.value,
                    payload=payload,
                    created_at=finding.created_at,
                )
                session.add(row)
            else:
                row.status = finding.status.value
                row.payload = payload
            self._audit(session, "finding.saved", str(finding.id), {"status": finding.status.value})
        return finding

    def get_finding(self, finding_id: UUID) -> Finding:
        with self._session() as session:
            row = session.get(FindingRow, str(finding_id))
            if row is None:
                raise KeyError(f"finding not found: {finding_id}")
            return Finding.model_validate(row.payload)

    def list_findings(self, engagement_id: UUID | None = None) -> list[Finding]:
        statement = select(FindingRow).order_by(FindingRow.created_at, FindingRow.id)
        if engagement_id is not None:
            statement = statement.where(FindingRow.engagement_id == str(engagement_id))
        with self._session() as session:
            return [Finding.model_validate(row.payload) for row in session.scalars(statement)]

    def save_evidence(self, evidence: Evidence) -> Evidence:
        with self._session.begin() as session:
            row = session.get(EvidenceRow, str(evidence.id))
            payload = evidence.model_dump(mode="json")
            if row is None:
                session.add(
                    EvidenceRow(
                        id=str(evidence.id),
                        experiment_id=str(evidence.experiment_id),
                        payload=payload,
                    )
                )
            else:
                row.payload = payload
            self._audit(session, "evidence.saved", str(evidence.id), {"type": evidence.type.value})
        return evidence

    def get_evidence(self, evidence_id: UUID) -> Evidence:
        with self._session() as session:
            row = session.get(EvidenceRow, str(evidence_id))
            if row is None:
                raise KeyError(f"evidence not found: {evidence_id}")
            return Evidence.model_validate(row.payload)

    def save_verification(self, verification: Verification) -> Verification:
        with self._session.begin() as session:
            row = session.get(VerificationRow, str(verification.id))
            payload = verification.model_dump(mode="json")
            if row is None:
                session.add(
                    VerificationRow(
                        id=str(verification.id),
                        hypothesis_id=str(verification.hypothesis_id),
                        decision=verification.decision.value,
                        payload=payload,
                        created_at=verification.created_at,
                    )
                )
            else:
                row.decision = verification.decision.value
                row.payload = payload
            self._audit(
                session,
                "verification.saved",
                str(verification.id),
                {"decision": verification.decision.value},
            )
        return verification

    def get_verification(self, verification_id: UUID) -> Verification:
        with self._session() as session:
            row = session.get(VerificationRow, str(verification_id))
            if row is None:
                raise KeyError(f"verification not found: {verification_id}")
            return Verification.model_validate(row.payload)

    def create_repository_analysis(self, analysis: RepositoryAnalysis) -> RepositoryAnalysis:
        row = RepositoryAnalysisRow(
            id=str(analysis.id),
            status=analysis.status.value,
            repository_url=analysis.repository_url,
            commit=analysis.commit,
            payload=analysis.model_dump(mode="json"),
            created_at=analysis.created_at,
            updated_at=analysis.updated_at,
        )
        with self._session.begin() as session:
            session.add(row)
            self._audit(session, "repository_analysis.created", str(analysis.id))
        return analysis

    def update_repository_analysis(self, analysis: RepositoryAnalysis) -> RepositoryAnalysis:
        with self._session.begin() as session:
            row = session.get(RepositoryAnalysisRow, str(analysis.id))
            if row is None:
                raise KeyError(f"repository analysis not found: {analysis.id}")
            row.status = analysis.status.value
            row.payload = analysis.model_dump(mode="json")
            row.updated_at = analysis.updated_at
            self._audit(
                session,
                "repository_analysis.updated",
                str(analysis.id),
                {"status": analysis.status.value},
            )
        return analysis

    def claim_repository_analysis(self, analysis_id: UUID) -> RepositoryAnalysis | None:
        now = datetime.now(timezone.utc)
        with self._session.begin() as session:
            row = session.get(RepositoryAnalysisRow, str(analysis_id))
            if row is None:
                raise KeyError(f"repository analysis not found: {analysis_id}")
            analysis = RepositoryAnalysis.model_validate(row.payload)
            claimed = analysis.model_copy(
                update={"status": RepositoryAnalysisStatus.FETCHING, "updated_at": now}
            )
            result = session.execute(
                update(RepositoryAnalysisRow)
                .where(
                    RepositoryAnalysisRow.id == str(analysis_id),
                    RepositoryAnalysisRow.status == "queued",
                )
                .values(
                    status="fetching",
                    payload=claimed.model_dump(mode="json"),
                    updated_at=now,
                )
            )
            if result.rowcount != 1:
                return None
            self._audit(
                session,
                "repository_analysis.claimed",
                str(analysis_id),
                {"status": "fetching"},
            )
            return claimed

    def get_repository_analysis(self, analysis_id: UUID) -> RepositoryAnalysis:
        with self._session() as session:
            row = session.get(RepositoryAnalysisRow, str(analysis_id))
            if row is None:
                raise KeyError(f"repository analysis not found: {analysis_id}")
            return RepositoryAnalysis.model_validate(row.payload)

    def list_repository_analyses(
        self, *, limit: int = 20, offset: int = 0
    ) -> list[RepositoryAnalysis]:
        if not 1 <= limit <= 100:
            raise ValueError("repository analysis limit must be between 1 and 100")
        if offset < 0:
            raise ValueError("repository analysis offset cannot be negative")
        statement = (
            select(RepositoryAnalysisRow)
            .order_by(RepositoryAnalysisRow.created_at.desc(), RepositoryAnalysisRow.id)
            .limit(limit)
            .offset(offset)
        )
        with self._session() as session:
            return [
                RepositoryAnalysis.model_validate(row.payload) for row in session.scalars(statement)
            ]

    def count_repository_analyses(self) -> int:
        with self._session() as session:
            return int(session.scalar(select(func.count()).select_from(RepositoryAnalysisRow)) or 0)

    def list_repository_analyses_by_status(
        self, status: str, *, limit: int = 20
    ) -> list[RepositoryAnalysis]:
        if not 1 <= limit <= 100:
            raise ValueError("repository analysis limit must be between 1 and 100")
        statement = (
            select(RepositoryAnalysisRow)
            .where(RepositoryAnalysisRow.status == status)
            .order_by(RepositoryAnalysisRow.created_at, RepositoryAnalysisRow.id)
            .limit(limit)
        )
        with self._session() as session:
            return [
                RepositoryAnalysis.model_validate(row.payload) for row in session.scalars(statement)
            ]

    @staticmethod
    def _audit(
        session: Session,
        event_type: str,
        subject_id: str | None,
        payload: dict[str, Any] | None = None,
    ) -> None:
        session.add(
            AuditEventRow(
                event_type=event_type,
                subject_id=subject_id,
                payload=payload or {},
                created_at=datetime.now(timezone.utc),
            )
        )
