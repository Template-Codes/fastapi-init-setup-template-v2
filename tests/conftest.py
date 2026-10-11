import os
import sys
import pytest
import pytest_asyncio
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
import redis.asyncio as aioredis
from httpx import AsyncClient, ASGITransport

def pytest_configure(config):
    """Pytest lifecycle hook: Automatically switches ENVIRONMENT to 'test' for all test runs."""
    print("\nSetting ENVIRONMENT to 'test' for all tests...")
    os.environ["ENVIRONMENT"] = "test"
    print(f"ENVIRONMENT: {os.environ.get('ENVIRONMENT')}")


# Ensure src is in sys.path for clean imports in tests
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from main import app
from core.settings import settings
from db.base import Base
from db.db_session import get_async_db
from db.cache_session import get_async_cache

# Ensure models are imported for metadata registration
from modules.authentication import auth_model  # noqa: F401
from modules.rbac import rbac_model  # noqa: F401
from modules.profile import user_profile_model  # noqa: F401
from modules.session import session_model  # noqa: F401
from modules.eis import eis_model  # noqa: F401

# Derive test database URL using TEST_DATABASE_URL
TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL", settings.TEST_DATABASE_URL or "")
if TEST_DATABASE_URL.startswith("postgresql://"):
    TEST_DATABASE_URL = TEST_DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)
elif TEST_DATABASE_URL.startswith("postgres://"):
    TEST_DATABASE_URL = TEST_DATABASE_URL.replace("postgres://", "postgresql+asyncpg://", 1)

# Derive test Redis URL using TEST_REDIS_URL
TEST_REDIS_URL = os.getenv("TEST_REDIS_URL", settings.TEST_REDIS_URL or "redis://localhost:6379/0")


@pytest_asyncio.fixture(scope="session", autouse=True)
async def prepare_test_database():
    """Ensure schemas ('auth', 'profile', 'session') and tables exist on TEST_DATABASE_URL before running integration tests."""
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    async with engine.begin() as conn:
        await conn.execute(sa.text("CREATE SCHEMA IF NOT EXISTS auth"))
        await conn.execute(sa.text("CREATE SCHEMA IF NOT EXISTS rbac"))
        await conn.execute(sa.text("CREATE SCHEMA IF NOT EXISTS profile"))
        await conn.execute(sa.text("CREATE SCHEMA IF NOT EXISTS session"))
        await conn.execute(sa.text("CREATE SCHEMA IF NOT EXISTS eis"))
        await conn.execute(sa.text("CREATE SEQUENCE IF NOT EXISTS auth.user_code_seq START WITH 1 INCREMENT BY 1"))
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(sa.text("""
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.tables 
                    WHERE table_schema = 'auth' AND table_name = 'users'
                ) AND NOT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_schema = 'auth' AND table_name = 'users' AND column_name = 'user_code'
                ) THEN
                    ALTER TABLE auth.users ADD COLUMN user_code VARCHAR(20) 
                    DEFAULT ('USR-' || lpad(nextval('auth.user_code_seq')::text, 5, '0')) NOT NULL;
                    CREATE UNIQUE INDEX IF NOT EXISTS ix_auth_users_user_code ON auth.users (user_code);
                END IF;
            END $$;
        """))
    yield
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session():
    """Provide an AsyncSession connected to real PostgreSQL TEST_DATABASE_URL, wrapped in an isolated transaction."""
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    async with engine.connect() as connection:
        transaction = await connection.begin()
        session_factory = async_sessionmaker(
            connection, class_=AsyncSession, expire_on_commit=False
        )
        session = session_factory()
        try:
            yield session
        finally:
            await session.close()
            if transaction.is_active:
                await transaction.rollback()
    await engine.dispose()


@pytest_asyncio.fixture
async def async_cache():
    """Provide a real Redis client connected to TEST_REDIS_URL."""
    client = aioredis.from_url(TEST_REDIS_URL, decode_responses=True)
    try:
        yield client
    finally:
        await client.aclose()


@pytest_asyncio.fixture
async def async_client(db_session, async_cache):
    """Async HTTP client fixture with real DB and Redis dependency overrides."""
    async def _override_get_async_db():
        yield db_session

    async def _override_get_async_cache():
        yield async_cache

    app.dependency_overrides[get_async_db] = _override_get_async_db
    app.dependency_overrides[get_async_cache] = _override_get_async_cache

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

    app.dependency_overrides.clear()
