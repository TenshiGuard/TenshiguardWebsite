"""add action + correlation fields to event

Revision ID: 26fa5047db6f
Revises: bff3b55b9481
Create Date: 2025-11-26 09:50:11.484098

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import sqlite

# revision identifiers, used by Alembic.
revision = "26fa5047db6f"
down_revision = "bff3b55b9481"
branch_labels = None
depends_on = None


def upgrade():
    """Schema change to align Event model with new AI / correlation design.

    NOTE:
    - We **do not** drop / recreate foreign keys here to avoid issues with
      unnamed constraints on SQLite.
    - We only add new columns, adjust nullability, and drop legacy columns.
    """

    with op.batch_alter_table("event", schema=None) as batch_op:
        # New fields
        batch_op.add_column(sa.Column("action", sa.String(length=120), nullable=True))
        batch_op.add_column(sa.Column("message", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("correlation_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("correlation_key", sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column("correlation_score", sa.Integer(), nullable=True))

        # Adjust nullability to match new Event model
        batch_op.alter_column(
            "category",
            existing_type=sa.String(length=50),
            nullable=True,
        )
        batch_op.alter_column(
            "ts",
            existing_type=sa.DateTime(),
            nullable=False,
        )

        # IMPORTANT: Do NOT drop constraints here (SQLite unnamed FKs break).
        # We also skip index drop to avoid potential missing-index issues.
        #
        # Legacy fields being removed from Event model:
        batch_op.drop_column("risk_score")
        batch_op.drop_column("raw")
        batch_op.drop_column("hostname")
        batch_op.drop_column("mitigation")
        batch_op.drop_column("ip")
        batch_op.drop_column("rule_name")


def downgrade():
    """Rollback schema change.

    This reverts to the previous Event schema, without touching foreign keys.
    """

    with op.batch_alter_table("event", schema=None) as batch_op:
        # Restore legacy fields
        batch_op.add_column(sa.Column("rule_name", sa.VARCHAR(length=200), nullable=True))
        batch_op.add_column(sa.Column("ip", sa.VARCHAR(length=50), nullable=True))
        batch_op.add_column(sa.Column("mitigation", sa.TEXT(), nullable=True))
        batch_op.add_column(sa.Column("hostname", sa.VARCHAR(length=100), nullable=True))
        batch_op.add_column(sa.Column("raw", sqlite.JSON(), nullable=True))
        batch_op.add_column(sa.Column("risk_score", sa.Integer(), nullable=True))

        # Restore previous nullability
        batch_op.alter_column(
            "ts",
            existing_type=sa.DateTime(),
            nullable=True,
        )
        batch_op.alter_column(
            "category",
            existing_type=sa.String(length=50),
            nullable=False,
        )

        # Drop new fields
        batch_op.drop_column("correlation_score")
        batch_op.drop_column("correlation_key")
        batch_op.drop_column("correlation_id")
        batch_op.drop_column("message")
        batch_op.drop_column("action")
