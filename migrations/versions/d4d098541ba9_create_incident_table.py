"""create incident table

Revision ID: d4d098541ba9
Revises: 26fa5047db6f
Create Date: 2025-11-26 19:35:48.427339
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd4d098541ba9'
down_revision = '26fa5047db6f'
branch_labels = None
depends_on = None


def upgrade():
    # -----------------------------------------------------------
    # 1. Create INCIDENT table (safe)
    # -----------------------------------------------------------
    op.create_table(
        'incident',
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('category', sa.String(length=50), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('risk_score', sa.Integer(), nullable=True),
        sa.Column('mitre_tag', sa.String(length=120), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ['organization_id'],
            ['organization.id'],
            ondelete='CASCADE'
        ),
    )

    # -----------------------------------------------------------
    # 2. Modify EVENT table (SQLite-safe)
    # -----------------------------------------------------------
    with op.batch_alter_table('event', schema=None) as batch_op:
        # add new column
        batch_op.add_column(sa.Column('incident_id', sa.Integer(), nullable=True))

        # DO NOT DROP ANY CONSTRAINTS — SQLite can't handle unnamed FKs
        # DO NOT DROP INDEX ix_event_ts — dropping is unsafe on SQLite

        # add new FK safely
        batch_op.create_foreign_key(
            'fk_event_incident',
            'incident',
            ['incident_id'],
            ['id'],
            ondelete='SET NULL'
        )


def downgrade():
    # -----------------------------------------------------------
    # Reverse EVENT table modifications
    # -----------------------------------------------------------
    with op.batch_alter_table('event', schema=None) as batch_op:
        # drop FK by NAME ONLY (safe)
        batch_op.drop_constraint('fk_event_incident', type_='foreignkey')

        batch_op.drop_column('incident_id')

    # -----------------------------------------------------------
    # Drop INCIDENT table
    # -----------------------------------------------------------
    op.drop_table('incident')
