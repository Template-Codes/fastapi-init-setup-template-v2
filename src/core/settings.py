from typing import Literal
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    APP_NAME: str = "USSCI"
    DEBUG: bool = True
    ENVIRONMENT: Literal["dev", "prod", "test"] = "dev"
    LOG_LEVEL: str = "INFO"

    # SECURITY
    SECRET_HEADER_NAME: str | None = None
    SECRET_HEADER_VALUE: str | None = None

    # API Documentation
    API_DOCS_URL: str | None = None
    API_REDOC_URL: str | None = None
    OPENAPI_URL: str | None = None

    # Database settings    
    DATABASE_URL: str | None = None
    TEST_DATABASE_URL: str | None = None
    
    DB_IO_SESSION_THROTTLING_TIME_S: int = 300 # 5mins

    # Redis settings
    REDIS_URL: str | None = None
    TEST_REDIS_URL: str | None = None
    
    # JWT Settings
    ACCESS_JWT_SECRET_KEY: str | None = None
    REFRESH_JWT_SECRET_KEY: str | None = None
    ACCESS_JWT_EXPIRY_SEC: int | None = None
    REFRESH_JWT_EXPIRY_SEC: int | None = None
    JWT_ALGORITHM: str | None = None
    SESSION_IDLE_TIMEOUT_SEC: int = 1800  # 30 mins
    
    # Cookie Settings
    COOKIE_SECURE: bool = False # not set in .env
    COOKIE_SAMESITE: Literal["lax", "strict", "none"] = "lax" # not set in .env

    # BIR EIS Configuration
    EIS_ENDPOINT_BASE_URL: str | None = None
    EIS_API_VERSION: str = "v2"
    EIS_USER_ID: str | None = None
    EIS_PASSWORD: str | None = None
    EIS_ACCREDITATION_ID: str | None = None
    EIS_APPLICATION_ID: str | None = None
    EIS_APPLICATION_SECRET_KEY: str | None = None
    EIS_APPLICATION_KEY_ID: str | None = None
    EIS_PUBLIC_KEY: str | None = None
    EIS_PRIVATE_KEY: str | None = None
    EIS_PTU_NUM: str | None = None

    # EIS Polling Configuration
    EIS_MAX_POLL_RETRIES: int = 10
    EIS_POLL_INTERVAL_S: int = 30

    # Initial Super Admin Seed Settings
    SEED_SUPERADMIN_USERNAME: str = "superadmin1"
    SEED_SUPERADMIN_EMAIL: str = "admin@system.local"
    SEED_SUPERADMIN_PASSWORD: str = "Admin@123456"
    
    @property
    def async_database_url(self) -> str:
        url = self.DATABASE_URL
        if url.startswith("postgresql://"):
            url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
        elif url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql+asyncpg://", 1)
        # Strip ?schema=... if present to avoid driver issues with asyncpg
        if "?schema=" in url:
            url = url.split("?schema=")[0]
        return url

    # Point directly to .env file
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

# Single source of truth achieved cleanly without constructor arguments or custom hooks
settings = Settings()
