"""Persist independent verifier decisions.

Revision ID: 20260716_0003
Revises: 20260716_0002
"""

from alembic import op
import sqlalchemy as sa


revision = "20260716_0003"
down_revision = "20260716_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "verifications",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("hypothesis_id", sa.String(length=36), nullable=False),
        sa.Column("decision", sa.String(length=48), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_verifications_hypothesis_id", "verifications", ["hypothesis_id"])
    op.create_index("ix_verifications_decision", "verifications", ["decision"])


def downgrade() -> None:
    op.drop_index("ix_verifications_decision", table_name="verifications")
    op.drop_index("ix_verifications_hypothesis_id", table_name="verifications")
    op.drop_table("verifications")
