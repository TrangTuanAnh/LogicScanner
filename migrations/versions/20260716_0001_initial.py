"""Create LogicLab control-plane tables."""

from alembic import op
import sqlalchemy as sa


revision = "20260716_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "engagements",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "runs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "engagement_id", sa.String(length=36), sa.ForeignKey("engagements.id"), nullable=False
        ),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_runs_engagement_id", "runs", ["engagement_id"])
    op.create_index("ix_runs_status", "runs", ["status"])
    op.create_table(
        "findings",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "engagement_id", sa.String(length=36), sa.ForeignKey("engagements.id"), nullable=False
        ),
        sa.Column("status", sa.String(length=48), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_findings_engagement_id", "findings", ["engagement_id"])
    op.create_index("ix_findings_status", "findings", ["status"])
    op.create_table(
        "evidence",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("experiment_id", sa.String(length=36), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index("ix_evidence_experiment_id", "evidence", ["experiment_id"])
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("subject_id", sa.String(length=64), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_audit_events_event_type", "audit_events", ["event_type"])
    op.create_index("ix_audit_events_subject_id", "audit_events", ["subject_id"])


def downgrade() -> None:
    op.drop_index("ix_audit_events_subject_id", table_name="audit_events")
    op.drop_index("ix_audit_events_event_type", table_name="audit_events")
    op.drop_table("audit_events")
    op.drop_index("ix_evidence_experiment_id", table_name="evidence")
    op.drop_table("evidence")
    op.drop_index("ix_findings_status", table_name="findings")
    op.drop_index("ix_findings_engagement_id", table_name="findings")
    op.drop_table("findings")
    op.drop_index("ix_runs_status", table_name="runs")
    op.drop_index("ix_runs_engagement_id", table_name="runs")
    op.drop_table("runs")
    op.drop_table("engagements")
