"""make_snapshot_changed_by_id_nullable

Revision ID: 988e2ea3a7bd
Revises: 8e8795b619bc
Create Date: 2026-10-11 14:00:32.598326

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '988e2ea3a7bd'
down_revision: Union[str, None] = '8e8795b619bc'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column(
        'role_permission_snapshots',
        'changed_by_id',
        existing_type=sa.UUID(),
        nullable=True,
        schema='rbac',
    )
    op.alter_column(
        'user_rbac_snapshots',
        'changed_by_id',
        existing_type=sa.UUID(),
        nullable=True,
        schema='rbac',
    )


def downgrade() -> None:
    op.alter_column(
        'user_rbac_snapshots',
        'changed_by_id',
        existing_type=sa.UUID(),
        nullable=False,
        schema='rbac',
    )
    op.alter_column(
        'role_permission_snapshots',
        'changed_by_id',
        existing_type=sa.UUID(),
        nullable=False,
        schema='rbac',
    )
