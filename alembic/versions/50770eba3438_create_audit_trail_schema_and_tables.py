"""create_audit_trail_schema_and_tables

Revision ID: 50770eba3438
Revises: 988e2ea3a7bd
Create Date: 2026-10-12 09:59:53.480479

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '50770eba3438'
down_revision: Union[str, None] = '988e2ea3a7bd'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Ensure isolated PostgreSQL schema exists
    op.execute("CREATE SCHEMA IF NOT EXISTS audit_trail")

    # 2. Monotonic sequence for gap-free audit sequence numbers
    op.execute("""
        CREATE SEQUENCE IF NOT EXISTS audit_trail.audit_seq
            START WITH 1
            INCREMENT BY 1
            NO MINVALUE
            NO MAXVALUE
            CACHE 1;
    """)

    # 3. Create tables and constraints
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
        sa.Column('verification_details', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.PrimaryKeyConstraint('id', 'checkpoint_sequence', name=op.f('pk_audit_hash_checkpoints')),
        schema='audit_trail',
    )

    op.create_table(
        'audit_export_jobs',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('requested_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('requested_by', sa.UUID(), nullable=False),
        sa.Column('file_format', sa.String(length=10), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('filter_criteria', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('total_rows', sa.Integer(), nullable=True),
        sa.Column('file_path', sa.String(length=500), nullable=True),
        sa.Column('sha256_checksum', sa.String(length=64), nullable=True),
        sa.Column('failure_reason', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['requested_by'], ['auth.users.id'], name=op.f('fk_audit_export_jobs_requested_by_users'), ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_audit_export_jobs')),
        schema='audit_trail',
    )
    op.create_index(op.f('ix_audit_trail_audit_export_jobs_requested_by'), 'audit_export_jobs', ['requested_by'], unique=False, schema='audit_trail')
    op.create_index(op.f('ix_audit_trail_audit_export_jobs_status'), 'audit_export_jobs', ['status'], unique=False, schema='audit_trail')

    op.create_table(
        'audit_logs',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('sequence_number', sa.BigInteger(), server_default=sa.text("nextval('audit_trail.audit_seq')"), nullable=False),
        sa.Column('user_id', sa.UUID(), nullable=True),
        sa.Column('user_code', sa.String(length=20), nullable=True),
        sa.Column('username_snapshot', sa.String(length=50), nullable=True),
        sa.Column('severity', sa.Enum('INFO', 'SUCCESS', 'WARNING', 'ERROR', 'CRITICAL', name='auditseverity'), nullable=False),
        sa.Column('module', sa.String(length=50), nullable=False),
        sa.Column('resource', sa.String(length=50), nullable=False),
        sa.Column('action', sa.String(length=50), nullable=False),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('target_schema', sa.String(length=50), nullable=True),
        sa.Column('target_table', sa.String(length=100), nullable=True),
        sa.Column('target_id', sa.String(length=100), nullable=True),
        sa.Column('target_code', sa.String(length=100), nullable=True),
        sa.Column('is_reversal', sa.Boolean(), nullable=False),
        sa.Column('reversal_for_id', sa.String(length=100), nullable=True),
        sa.Column('old_values', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('new_values', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('changed_fields', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('context', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('request_id', sa.String(length=64), nullable=True),
        sa.Column('session_id', sa.UUID(), nullable=True),
        sa.Column('record_hash', sa.String(length=64), nullable=False),
        sa.Column('prev_hash', sa.String(length=64), nullable=False),
        sa.Column('chain_id', sa.String(length=100), nullable=False),
        sa.CheckConstraint(
            "action NOT IN ('VOID', 'ADJUSTMENT', 'ROLE_CHANGE', 'PERMISSION_CHANGE', 'SECURITY_LOCKOUT', 'FORCED_LOGOUT') "
            "OR (reason IS NOT NULL AND length(trim(reason)) >= 5)",
            name=op.f('ck_audit_logs_ck_audit_logs_mandatory_reason'),
        ),
        sa.CheckConstraint(
            'octet_length(context::text) <= 65536 AND '
            'octet_length(old_values::text) <= 262144 AND '
            'octet_length(new_values::text) <= 262144',
            name=op.f('ck_audit_logs_ck_audit_logs_payload_size'),
        ),
        sa.ForeignKeyConstraint(['session_id'], ['session.sessions.id'], name=op.f('fk_audit_logs_session_id_sessions'), ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['user_id'], ['auth.users.id'], name=op.f('fk_audit_logs_user_id_users'), ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('id', 'created_at', name=op.f('pk_audit_logs')),
        schema='audit_trail',
    )

    op.create_index('ix_audit_logs_mod_res_act_created', 'audit_logs', ['module', 'resource', 'action', sa.literal_column('created_at DESC')], unique=False, schema='audit_trail')
    op.create_index('ix_audit_logs_reversal_for_id', 'audit_logs', ['reversal_for_id'], unique=False, schema='audit_trail')
    op.create_index('ix_audit_logs_target_code_created', 'audit_logs', ['target_code', sa.literal_column('created_at DESC')], unique=False, schema='audit_trail')
    op.create_index('ix_audit_logs_target_entity_created', 'audit_logs', ['target_table', 'target_id', sa.literal_column('created_at DESC')], unique=False, schema='audit_trail')
    op.create_index('ix_audit_logs_user_created', 'audit_logs', ['user_id', sa.literal_column('created_at DESC')], unique=False, schema='audit_trail')
    op.create_index(op.f('ix_audit_trail_audit_logs_action'), 'audit_logs', ['action'], unique=False, schema='audit_trail')
    op.create_index(op.f('ix_audit_trail_audit_logs_chain_id'), 'audit_logs', ['chain_id'], unique=False, schema='audit_trail')
    op.create_index(op.f('ix_audit_trail_audit_logs_module'), 'audit_logs', ['module'], unique=False, schema='audit_trail')
    op.create_index(op.f('ix_audit_trail_audit_logs_request_id'), 'audit_logs', ['request_id'], unique=False, schema='audit_trail')
    op.create_index(op.f('ix_audit_trail_audit_logs_resource'), 'audit_logs', ['resource'], unique=False, schema='audit_trail')
    op.create_index(op.f('ix_audit_trail_audit_logs_sequence_number'), 'audit_logs', ['sequence_number'], unique=True, schema='audit_trail')
    op.create_index(op.f('ix_audit_trail_audit_logs_session_id'), 'audit_logs', ['session_id'], unique=False, schema='audit_trail')
    op.create_index(op.f('ix_audit_trail_audit_logs_severity'), 'audit_logs', ['severity'], unique=False, schema='audit_trail')
    op.create_index(op.f('ix_audit_trail_audit_logs_target_code'), 'audit_logs', ['target_code'], unique=False, schema='audit_trail')
    op.create_index(op.f('ix_audit_trail_audit_logs_target_id'), 'audit_logs', ['target_id'], unique=False, schema='audit_trail')
    op.create_index(op.f('ix_audit_trail_audit_logs_target_table'), 'audit_logs', ['target_table'], unique=False, schema='audit_trail')
    op.create_index(op.f('ix_audit_trail_audit_logs_user_id'), 'audit_logs', ['user_id'], unique=False, schema='audit_trail')

    # Full-text search GIN index on justification reason
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_audit_logs_reason_gin
        ON audit_trail.audit_logs
        USING GIN (to_tsvector('english', coalesce(reason, '')));
    """)

    # Foreign key attribution protection alignment for RBAC snapshot tables (SET NULL)
    op.drop_constraint(op.f('fk_role_permission_snapshots_changed_by_id_users'), 'role_permission_snapshots', schema='rbac', type_='foreignkey')
    op.create_foreign_key(op.f('fk_role_permission_snapshots_changed_by_id_users'), 'role_permission_snapshots', 'users', ['changed_by_id'], ['id'], source_schema='rbac', referent_schema='auth', ondelete='SET NULL')
    op.drop_constraint(op.f('fk_user_rbac_snapshots_changed_by_id_users'), 'user_rbac_snapshots', schema='rbac', type_='foreignkey')
    op.create_foreign_key(op.f('fk_user_rbac_snapshots_changed_by_id_users'), 'user_rbac_snapshots', 'users', ['changed_by_id'], ['id'], source_schema='rbac', referent_schema='auth', ondelete='SET NULL')

    # 4. Database-level immutability enforcement trigger (BIR CAS Annex B Item 11.i)
    op.execute("""
        CREATE OR REPLACE FUNCTION audit_trail.fn_prevent_audit_log_mutation()
        RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION 'BIR CAS Security Violation: Records in audit_trail.audit_logs are immutable and cannot be modified or deleted. (Annex B Item 11.i)'
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


def downgrade() -> None:
    # 1. Drop immutability trigger and function
    op.execute("DROP TRIGGER IF EXISTS tg_prevent_audit_log_mutation ON audit_trail.audit_logs;")
    op.execute("DROP FUNCTION IF EXISTS audit_trail.fn_prevent_audit_log_mutation();")

    # 2. Drop GIN index
    op.execute("DROP INDEX IF EXISTS audit_trail.ix_audit_logs_reason_gin;")

    # 3. Revert RBAC snapshot foreign keys
    op.drop_constraint(op.f('fk_user_rbac_snapshots_changed_by_id_users'), 'user_rbac_snapshots', schema='rbac', type_='foreignkey')
    op.create_foreign_key(op.f('fk_user_rbac_snapshots_changed_by_id_users'), 'user_rbac_snapshots', 'users', ['changed_by_id'], ['id'], source_schema='rbac', referent_schema='auth', ondelete='CASCADE')
    op.drop_constraint(op.f('fk_role_permission_snapshots_changed_by_id_users'), 'role_permission_snapshots', schema='rbac', type_='foreignkey')
    op.create_foreign_key(op.f('fk_role_permission_snapshots_changed_by_id_users'), 'role_permission_snapshots', 'users', ['changed_by_id'], ['id'], source_schema='rbac', referent_schema='auth', ondelete='CASCADE')

    # 4. Drop audit tables and indexes
    op.drop_index(op.f('ix_audit_trail_audit_logs_user_id'), table_name='audit_logs', schema='audit_trail')
    op.drop_index(op.f('ix_audit_trail_audit_logs_target_table'), table_name='audit_logs', schema='audit_trail')
    op.drop_index(op.f('ix_audit_trail_audit_logs_target_id'), table_name='audit_logs', schema='audit_trail')
    op.drop_index(op.f('ix_audit_trail_audit_logs_target_code'), table_name='audit_logs', schema='audit_trail')
    op.drop_index(op.f('ix_audit_trail_audit_logs_severity'), table_name='audit_logs', schema='audit_trail')
    op.drop_index(op.f('ix_audit_trail_audit_logs_session_id'), table_name='audit_logs', schema='audit_trail')
    op.drop_index(op.f('ix_audit_trail_audit_logs_sequence_number'), table_name='audit_logs', schema='audit_trail')
    op.drop_index(op.f('ix_audit_trail_audit_logs_resource'), table_name='audit_logs', schema='audit_trail')
    op.drop_index(op.f('ix_audit_trail_audit_logs_request_id'), table_name='audit_logs', schema='audit_trail')
    op.drop_index(op.f('ix_audit_trail_audit_logs_module'), table_name='audit_logs', schema='audit_trail')
    op.drop_index(op.f('ix_audit_trail_audit_logs_chain_id'), table_name='audit_logs', schema='audit_trail')
    op.drop_index(op.f('ix_audit_trail_audit_logs_action'), table_name='audit_logs', schema='audit_trail')
    op.drop_index('ix_audit_logs_user_created', table_name='audit_logs', schema='audit_trail')
    op.drop_index('ix_audit_logs_target_entity_created', table_name='audit_logs', schema='audit_trail')
    op.drop_index('ix_audit_logs_target_code_created', table_name='audit_logs', schema='audit_trail')
    op.drop_index('ix_audit_logs_reversal_for_id', table_name='audit_logs', schema='audit_trail')
    op.drop_index('ix_audit_logs_mod_res_act_created', table_name='audit_logs', schema='audit_trail')
    op.drop_table('audit_logs', schema='audit_trail')

    op.drop_index(op.f('ix_audit_trail_audit_export_jobs_status'), table_name='audit_export_jobs', schema='audit_trail')
    op.drop_index(op.f('ix_audit_trail_audit_export_jobs_requested_by'), table_name='audit_export_jobs', schema='audit_trail')
    op.drop_table('audit_export_jobs', schema='audit_trail')
    op.drop_table('audit_hash_checkpoints', schema='audit_trail')

    # 5. Drop enum type
    sa.Enum(name='auditseverity').drop(op.get_bind(), checkfirst=True)

    # 6. Drop sequence and schema
    op.execute("DROP SEQUENCE IF EXISTS audit_trail.audit_seq;")
    op.execute("DROP SCHEMA IF EXISTS audit_trail CASCADE;")

