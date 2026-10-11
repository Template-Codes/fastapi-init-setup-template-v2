"""add_rbac_snapshots_tables

Revision ID: 8e8795b619bc
Revises: 1cd7634dcbea
Create Date: 2026-10-11 13:34:12.055163

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '8e8795b619bc'
down_revision: Union[str, None] = '1cd7634dcbea'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Move native enum type to rbac schema if in public
    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM pg_type t 
                JOIN pg_namespace n ON n.oid = t.typnamespace 
                WHERE n.nspname = 'public' AND t.typname = 'rbacchangerequeststatus'
            ) THEN
                ALTER TYPE public.rbacchangerequeststatus SET SCHEMA rbac;
            END IF;
        END $$;
    """)

    # 2. Rename index naming convention from auth to rbac
    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = 'rbac' AND indexname = 'ix_auth_permissions_code') THEN
                ALTER INDEX rbac.ix_auth_permissions_code RENAME TO ix_rbac_permissions_code;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = 'rbac' AND indexname = 'ix_auth_permissions_module') THEN
                ALTER INDEX rbac.ix_auth_permissions_module RENAME TO ix_rbac_permissions_module;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = 'rbac' AND indexname = 'ix_auth_rbac_change_requests_status') THEN
                ALTER INDEX rbac.ix_auth_rbac_change_requests_status RENAME TO ix_rbac_rbac_change_requests_status;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = 'rbac' AND indexname = 'ix_auth_roles_name') THEN
                ALTER INDEX rbac.ix_auth_roles_name RENAME TO ix_rbac_roles_name;
            END IF;
        END $$;
    """)

    # 3. Create role_permission_snapshots table
    op.create_table(
        'role_permission_snapshots',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('role_id', sa.UUID(), nullable=False),
        sa.Column('permissions_payload', sa.JSON(), nullable=False),
        sa.Column('changed_by_id', sa.UUID(), nullable=False),
        sa.Column('reason', sa.String(length=255), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['changed_by_id'], ['auth.users.id'], name=op.f('fk_role_permission_snapshots_changed_by_id_users'), ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['role_id'], ['rbac.roles.id'], name=op.f('fk_role_permission_snapshots_role_id_roles'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_role_permission_snapshots')),
        schema='rbac'
    )
    op.create_index(op.f('ix_rbac_role_permission_snapshots_role_id'), 'role_permission_snapshots', ['role_id'], unique=False, schema='rbac')
    op.create_index('ix_rbac_role_snapshots_role_created', 'role_permission_snapshots', ['role_id', 'created_at'], unique=False, schema='rbac')

    # 4. Create user_rbac_snapshots table
    op.create_table(
        'user_rbac_snapshots',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('user_id', sa.UUID(), nullable=False),
        sa.Column('roles_payload', sa.JSON(), nullable=False),
        sa.Column('direct_permissions_payload', sa.JSON(), nullable=False),
        sa.Column('effective_permissions_payload', sa.JSON(), nullable=False),
        sa.Column('changed_by_id', sa.UUID(), nullable=False),
        sa.Column('reason', sa.String(length=255), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['changed_by_id'], ['auth.users.id'], name=op.f('fk_user_rbac_snapshots_changed_by_id_users'), ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['auth.users.id'], name=op.f('fk_user_rbac_snapshots_user_id_users'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_user_rbac_snapshots')),
        schema='rbac'
    )
    op.create_index(op.f('ix_rbac_user_rbac_snapshots_user_id'), 'user_rbac_snapshots', ['user_id'], unique=False, schema='rbac')
    op.create_index('ix_rbac_user_snapshots_user_created', 'user_rbac_snapshots', ['user_id', 'created_at'], unique=False, schema='rbac')


def downgrade() -> None:
    # 1. Drop user_rbac_snapshots table
    op.drop_index('ix_rbac_user_snapshots_user_created', table_name='user_rbac_snapshots', schema='rbac')
    op.drop_index(op.f('ix_rbac_user_rbac_snapshots_user_id'), table_name='user_rbac_snapshots', schema='rbac')
    op.drop_table('user_rbac_snapshots', schema='rbac')

    # 2. Drop role_permission_snapshots table
    op.drop_index('ix_rbac_role_snapshots_role_created', table_name='role_permission_snapshots', schema='rbac')
    op.drop_index(op.f('ix_rbac_role_permission_snapshots_role_id'), table_name='role_permission_snapshots', schema='rbac')
    op.drop_table('role_permission_snapshots', schema='rbac')

    # 3. Rename indexes back
    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = 'rbac' AND indexname = 'ix_rbac_permissions_code') THEN
                ALTER INDEX rbac.ix_rbac_permissions_code RENAME TO ix_auth_permissions_code;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = 'rbac' AND indexname = 'ix_rbac_permissions_module') THEN
                ALTER INDEX rbac.ix_rbac_permissions_module RENAME TO ix_auth_permissions_module;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = 'rbac' AND indexname = 'ix_rbac_rbac_change_requests_status') THEN
                ALTER INDEX rbac.ix_rbac_rbac_change_requests_status RENAME TO ix_auth_rbac_change_requests_status;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = 'rbac' AND indexname = 'ix_rbac_roles_name') THEN
                ALTER INDEX rbac.ix_rbac_roles_name RENAME TO ix_auth_roles_name;
            END IF;
        END $$;
    """)

    # 4. Move enum back to public
    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM pg_type t 
                JOIN pg_namespace n ON n.oid = t.typnamespace 
                WHERE n.nspname = 'rbac' AND t.typname = 'rbacchangerequeststatus'
            ) THEN
                ALTER TYPE rbac.rbacchangerequeststatus SET SCHEMA public;
            END IF;
        END $$;
    """)

