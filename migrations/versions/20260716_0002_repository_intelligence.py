"""Add universal repository intelligence records.

Revision ID: 20260716_0002
Revises: 20260716_0001
"""

from alembic import op
import sqlalchemy as sa


revision = "20260716_0002"
down_revision = "20260716_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "repository_analyses",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("repository_url", sa.String(length=2048), nullable=False),
        sa.Column("commit", sa.String(length=40), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_repository_analyses_status", "repository_analyses", ["status"])
    op.create_index("ix_repository_analyses_commit", "repository_analyses", ["commit"])


def downgrade() -> None:
    op.drop_index("ix_repository_analyses_commit", table_name="repository_analyses")
    op.drop_index("ix_repository_analyses_status", table_name="repository_analyses")
    op.drop_table("repository_analyses")
