"""fix_audit_logs_hash_chain_columns_nullable

Corrective migration: the previous audit_trail table creation migration
declared record_hash, prev_hash, and chain_id as NOT NULL, but the ORM model
declares them as Optional (nullable=True). Because hash chaining is not yet
implemented in the service layer, no values are ever populated for these fields,
causing every audit_service.log() call to fail with a NotNullViolation that is
silently swallowed by the fail-safe try/except in AuditTrailService.log().

This migration aligns the DB schema with the ORM model by setting those three
columns to nullable, unblocking audit writes.

Revision ID: e97659720b0e
Revises: ce1e8c572852
Create Date: 2026-10-13 11:12:39.373958

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e97659720b0e'
down_revision: Union[str, None] = 'ce1e8c572852'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Allow NULL on hash-chaining columns until the chaining feature is built.
    # These were incorrectly created as NOT NULL in the initial migration while
    # the ORM model always had them as Optional[str] (nullable=True).
    op.alter_column(
        'audit_logs',
        'record_hash',
        existing_type=sa.String(length=64),
        nullable=True,
        schema='audit_trail',
    )
    op.alter_column(
        'audit_logs',
        'prev_hash',
        existing_type=sa.String(length=64),
        nullable=True,
        schema='audit_trail',
    )
    op.alter_column(
        'audit_logs',
        'chain_id',
        existing_type=sa.String(length=100),
        nullable=True,
        schema='audit_trail',
    )


def downgrade() -> None:
    # Revert to NOT NULL — only safe if all existing rows have been backfilled
    # with hash values. In practice, downgrade should not be executed in production
    # without a prior data backfill.
    op.alter_column(
        'audit_logs',
        'chain_id',
        existing_type=sa.String(length=100),
        nullable=False,
        schema='audit_trail',
    )
    op.alter_column(
        'audit_logs',
        'prev_hash',
        existing_type=sa.String(length=64),
        nullable=False,
        schema='audit_trail',
    )
    op.alter_column(
        'audit_logs',
        'record_hash',
        existing_type=sa.String(length=64),
        nullable=False,
        schema='audit_trail',
    )
