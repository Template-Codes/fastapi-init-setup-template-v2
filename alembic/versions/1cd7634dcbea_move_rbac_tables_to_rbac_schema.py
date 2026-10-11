"""move_rbac_tables_to_rbac_schema

Revision ID: 1cd7634dcbea
Revises: ffca0bf82523
Create Date: 2026-10-11 11:36:22.391741

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '1cd7634dcbea'
down_revision: Union[str, None] = 'ffca0bf82523'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Ensure rbac schema exists
    op.execute("CREATE SCHEMA IF NOT EXISTS rbac")

    # 2. Non-destructively move tables from auth schema to rbac schema
    tables = [
        "permissions",
        "roles",
        "role_permissions",
        "user_roles",
        "user_permissions",
        "rbac_change_requests",
    ]
    for table in tables:
        op.execute(f"""
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.tables 
                    WHERE table_schema = 'auth' AND table_name = '{table}'
                ) THEN
                    ALTER TABLE auth.{table} SET SCHEMA rbac;
                END IF;
            END $$;
        """)

    # 3. Move native enum type to rbac schema
    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM pg_type t 
                JOIN pg_namespace n ON n.oid = t.typnamespace 
                WHERE n.nspname = 'auth' AND t.typname = 'rbacchangerequeststatus'
            ) THEN
                ALTER TYPE auth.rbacchangerequeststatus SET SCHEMA rbac;
            END IF;
        END $$;
    """)


def downgrade() -> None:
    tables = [
        "rbac_change_requests",
        "user_permissions",
        "user_roles",
        "role_permissions",
        "roles",
        "permissions",
    ]
    for table in tables:
        op.execute(f"""
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.tables 
                    WHERE table_schema = 'rbac' AND table_name = '{table}'
                ) THEN
                    ALTER TABLE rbac.{table} SET SCHEMA auth;
                END IF;
            END $$;
        """)

    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM pg_type t 
                JOIN pg_namespace n ON n.oid = t.typnamespace 
                WHERE n.nspname = 'rbac' AND t.typname = 'rbacchangerequeststatus'
            ) THEN
                ALTER TYPE rbac.rbacchangerequeststatus SET SCHEMA auth;
            END IF;
        END $$;
    """)
    op.execute("DROP SCHEMA IF EXISTS rbac CASCADE")
