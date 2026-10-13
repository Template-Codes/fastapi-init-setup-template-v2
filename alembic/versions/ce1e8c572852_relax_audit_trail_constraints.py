"""relax_audit_trail_constraints

Revision ID: ce1e8c572852
Revises: 50770eba3438
Create Date: 2026-10-13 08:51:30.870537

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'ce1e8c572852'
down_revision: Union[str, None] = '50770eba3438'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Drop immutability trigger and function
    op.execute("DROP TRIGGER IF EXISTS tg_prevent_audit_log_mutation ON audit_trail.audit_logs;")
    op.execute("DROP FUNCTION IF EXISTS audit_trail.fn_prevent_audit_log_mutation();")

    # 2. Drop mandatory reason check constraint
    op.drop_constraint('ck_audit_logs_mandatory_reason', 'audit_logs', schema='audit_trail', type_='check')

    # 3. Make cryptographic chaining fields optional
    op.alter_column('audit_logs', 'record_hash', existing_type=sa.String(length=64), nullable=True, schema='audit_trail')
    op.alter_column('audit_logs', 'prev_hash', existing_type=sa.String(length=64), nullable=True, schema='audit_trail')
    op.alter_column('audit_logs', 'chain_id', existing_type=sa.String(length=100), nullable=True, schema='audit_trail')

    # 4. Drop checkpoints table
    op.drop_table('audit_hash_checkpoints', schema='audit_trail')


def downgrade() -> None:
    # 1. Recreate checkpoints table
    op.create_table(
        'audit_hash_checkpoints',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('checkpoint_sequence', sa.BigInteger(), nullable=False),
        sa.Column('checkpoint_time', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('from_sequence', sa.BigInteger(), nullable=False),
        sa.Column('to_sequence', sa.BigInteger(), nullable=False),
        sa.Column('root_hash', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('verification_details', sa.dialects.postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.PrimaryKeyConstraint('id', 'checkpoint_sequence', name=op.f('pk_audit_hash_checkpoints')),
        schema='audit_trail',
    )

    # 2. Revert columns to not nullable
    op.alter_column('audit_logs', 'chain_id', existing_type=sa.String(length=100), nullable=False, schema='audit_trail')
    op.alter_column('audit_logs', 'prev_hash', existing_type=sa.String(length=64), nullable=False, schema='audit_trail')
    op.alter_column('audit_logs', 'record_hash', existing_type=sa.String(length=64), nullable=False, schema='audit_trail')

    # 3. Restore check constraint
    op.create_check_constraint(
        'ck_audit_logs_mandatory_reason',
        'audit_logs',
        "action NOT IN ('VOID', 'ADJUSTMENT', 'ROLE_CHANGE', 'PERMISSION_CHANGE', 'SECURITY_LOCKOUT', 'FORCED_LOGOUT') "
        "OR (reason IS NOT NULL AND length(trim(reason)) >= 5)",
        schema='audit_trail',
    )

    # 4. Restore immutability trigger
    op.execute("""
        CREATE OR REPLACE FUNCTION audit_trail.fn_prevent_audit_log_mutation()
        RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION 'Security Violation: Records in audit_trail.audit_logs are immutable and cannot be modified or deleted.'
            USING ERRCODE = '55000';
        END;
        $$ LANGUAGE plpgsql;
    """)
    op.execute("""
        CREATE TRIGGER tg_prevent_audit_log_mutation
            BEFORE UPDATE OR DELETE ON audit_trail.audit_logs
            FOR EACH ROW
            EXECUTE FUNCTION audit_trail.fn_prevent_audit_log_mutation();
    """)
