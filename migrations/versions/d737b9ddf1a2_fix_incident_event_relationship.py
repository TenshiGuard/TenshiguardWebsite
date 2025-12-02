"""fix incident-event relationship

Revision ID: d737b9ddf1a2
Revises: d4d098541ba9
Create Date: 2025-11-26 22:07:22.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers
revision = 'd737b9ddf1a2'
down_revision = 'd4d098541ba9'
branch_labels = None
depends_on = None


def upgrade():
    """
    IMPORTANT:
    - SQLite does NOT support dropping unnamed constraints.
    - So we only ADD the new FK and skip dropping old unnamed ones.
    """

    with op.batch_alter_table("event", schema=None) as batch_op:
        # ensure column exists (safe on SQLite)
        batch_op.add_column(sa.Column('incident_id', sa.Integer(), nullable=True))

        # ADD foreign keys ONLY — do not DROP anything
        batch_op.create_foreign_key(
            "fk_event_incident",
            "incident",
            ["incident_id"],
            ["id"],
            ondelete="SET NULL"
        )

        # Recreate device FK
        batch_op.create_foreign_key(
            "fk_event_device",
            "device",
            ["device_id"],
            ["id"],
            ondelete="SET NULL"
        )

        # Recreate organization FK
        batch_op.create_foreign_key(
            "fk_event_org",
            "organization",
            ["organization_id"],
            ["id"],
            ondelete="CASCADE"
        )


def downgrade():
    """
    Safe rollback for SQLite — drop only named FKs and drop column.
    """

    with op.batch_alter_table("event", schema=None) as batch_op:
        batch_op.drop_constraint("fk_event_incident", type_="foreignkey")
        batch_op.drop_constraint("fk_event_device", type_="foreignkey")
        batch_op.drop_constraint("fk_event_org", type_="foreignkey")
        batch_op.drop_column("incident_id")
