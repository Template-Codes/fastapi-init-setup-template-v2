import asyncio
import os
import sys
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context

# Ensure src is in sys.path so clean imports work seamlessly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from core.settings import settings
from db.base import Base

# Import all module models so Base.metadata is fully populated for autogenerate
from modules.authentication import auth_model  # noqa: F401
from modules.rbac import rbac_model  # noqa: F401
from modules.profile import user_profile_model  # noqa: F401
from modules.session import session_model  # noqa: F401
from modules.eis import eis_model  # noqa: F401

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name:
    fileConfig(config.config_file_name)

# Format connection URL for Alembic CLI (prefer psycopg sync driver)
if settings.ENVIRONMENT == "test" and settings.TEST_DATABASE_URL:
    db_url = settings.TEST_DATABASE_URL
else:
    db_url = settings.DATABASE_URL or ""

if db_url.startswith("postgresql+asyncpg://"):
    db_url = db_url.replace("postgresql+asyncpg://", "postgresql+psycopg://", 1)
elif db_url.startswith("postgresql://"):
    db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)
elif db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql+psycopg://", 1)

config.set_main_option("sqlalchemy.url", db_url)


# add your model's MetaData object here
# for 'autogenerate' support
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        include_schemas=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection) -> None:
    """Execute migrations within an active database connection context."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        include_schemas=True,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Run migrations using SQLAlchemy AsyncEngine."""
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode (supporting both sync psycopg and async asyncpg)."""
    url = config.get_main_option("sqlalchemy.url", "")
    if "asyncpg" in url:
        asyncio.run(run_async_migrations())
    else:
        connectable = engine_from_config(
            config.get_section(config.config_ini_section, {}),
            prefix="sqlalchemy.",
            poolclass=pool.NullPool,
        )

        with connectable.connect() as connection:
            do_run_migrations(connection)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
