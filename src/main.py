import sys
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from clients.redis import redis_async_client
from fastapi import FastAPI
from loguru import logger

# Configure sys.path so imports like `from core.settings import settings` work directly
if "src" not in sys.path:
    sys.path.insert(0, "src")

from core.settings import settings
from core.logging import setup_logging
from clients.postgresql import init_db, close_db, postgres_client_async_session
from modules.rbac.rbac_repository import RBACRepository

# import models
from modules.authentication import auth_model
from modules.profile import user_profile_model
from modules.session import session_model
from modules.eis import eis_model

# import routers with alias
from modules.authentication.auth_router import router as auth_router
from modules.eis.eis_router import router as eis_router
from modules.session.session_router import router as session_router
from modules.rbac.rbac_router import router as rbac_router

from exceptions.exception_handlers import register_exception_handlers
from core.logging_middleware import LoggingMiddleware
from middlewares.jwt_validator import JWTValidator

# Initialize Loguru logger configuration and intercept standard logging
setup_logging()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """FastAPI Lifespan context manager for startup and shutdown hooks."""
    logger.info(f"Starting up {settings.APP_NAME} (Environment: {settings.ENVIRONMENT})...")
    
    # Initialize Postgres singleton connection pool
    try:
        logger.info("Initializing database...")
        await init_db()

        # Idempotently sync RBAC roles and permissions from code enums
        logger.info("Synchronizing RBAC enums and default presets to database...")
        async with postgres_client_async_session() as session:
            rbac_repo = RBACRepository(db=session)
            sync_result = await rbac_repo.sync_enums_to_db()
            logger.info(f"RBAC enum sync on startup completed: {sync_result}")
    except Exception as e:
        logger.error(f"Database connection or RBAC enum sync failed on startup: {e}")

    
    # Initialize Redis singleton connection pool
    try:
        logger.info("Initializing redis...")
        await redis_async_client.ping()
    except Exception as e:
        logger.warning(f"Redis connection failed on startup: {e}. Application running without active cache session.")
    
    yield
    
    logger.info(f"Shutting down {settings.APP_NAME}...")
    
    # Dispose Postgres singleton engine
    logger.info("Closing DB connection.")
    await close_db()
    
    # Dispose Redis connection pool
    logger.info("Closing redis connection.")
    try:
        await redis_async_client.close()
    except Exception as e:
        logger.warning(f"Error closing Redis connection: {e}")


# Conditionally disable Swagger UI (/docs), ReDoc (/redoc), and OpenAPI schema (/openapi.json) in production
is_prod = settings.ENVIRONMENT == "prod"
docs_url = settings.API_DOCS_URL if is_prod else "/docs"
redoc_url = settings.API_REDOC_URL if is_prod else "/redoc"
openapi_url = settings.OPENAPI_URL if is_prod else "/openapi.json"

app = FastAPI(
    title=settings.APP_NAME,
    debug=settings.DEBUG,
    docs_url=docs_url,
    redoc_url=redoc_url,
    openapi_url=openapi_url,
    lifespan=lifespan,
)

# Register global middleware (logging & request tracking)
app.add_middleware(LoggingMiddleware)
app.add_middleware(JWTValidator)

# Register global exception handlers
register_exception_handlers(app)

# router registration
app.include_router(auth_router)
app.include_router(session_router)
app.include_router(eis_router)
app.include_router(rbac_router)

@app.get("/health", tags=["System"])
async def health_check():
    """Health check endpoint for system readiness and liveness."""
    return {
        "status": "healthy",
        "app_name": settings.APP_NAME,
        "environment": settings.ENVIRONMENT,
    }
