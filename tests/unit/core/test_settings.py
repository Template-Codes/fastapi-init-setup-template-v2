import os
import sys

# Ensure src is in sys.path for IDEs and test runners
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "src")))

from core.settings import Settings

def test_settings_default_values():
    settings = Settings()
    assert settings.APP_NAME == "XCOM"
    assert settings.ENVIRONMENT in ["dev", "prod", "test"]

def test_database_url_conversion():
    settings = Settings(DATABASE_URL="postgresql://user:pass@localhost:5432/testdb")
    assert settings.async_database_url == "postgresql+asyncpg://user:pass@localhost:5432/testdb"

def test_database_url_schema_stripping():
    settings = Settings(DATABASE_URL="postgresql://user:pass@localhost:5432/testdb?schema=public")
    assert settings.async_database_url == "postgresql+asyncpg://user:pass@localhost:5432/testdb"
