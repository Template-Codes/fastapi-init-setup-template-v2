from typing import Optional
from uuid import UUID

from db.cache_session import get_async_cache
from exceptions.app_exception import AppException, ForbiddenException, InternalServerException, UnauthorizedException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Depends, Request
from core.settings import settings
import jwt
from loguru import logger
from modules.profile.user_profile_repository import UserProfileRepository
import redis.asyncio as aioredis
from utils.maintain_cache_key import MaintainCacheKeyUtils

security = HTTPBearer(auto_error=False)

async def get_current_user_id(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> UUID:
    """
    Extracts user.id from pre-verified request.state (injected by JWTValidator middleware) 
    or falls back to direct JWT token decoding.
    """
    if hasattr(request.state, "user_id") and request.state.user_id:
        return request.state.user_id

    token: Optional[str] = credentials.credentials if credentials else request.cookies.get("access_token")

    if not token:
        logger.warning("Access token missing in both Authorization header and cookies.")
        raise UnauthorizedException(
            message="Not authenticated. Access token required."
        )

    try:
        payload = jwt.decode(
            token, 
            settings.ACCESS_JWT_SECRET_KEY, 
            algorithms=[settings.JWT_ALGORITHM]
        )
        
        token_type: Optional[str] = payload.get("type")
        if token_type != "access-token":
            logger.warning(f"Invalid token type provided: {token_type}")
            raise UnauthorizedException(
                message="Invalid token type. Access token required."
            )
            
        # sub holds user UUID, fallback to 'sid' holds user_session UUID
        user_id_str: Optional[str] = payload.get("sub") or payload.get("sid")
        
        if user_id_str is None:
            logger.warning("User ID not found in token payload.")
            raise UnauthorizedException(
                message="Invalid token payload."
            )
        
        return UUID(user_id_str)
    except jwt.PyJWTError as e:
        logger.warning(f"JWT verification failed: {e}")
        raise UnauthorizedException(message="Invalid or expired access token.")
    except AppException:
        raise
    except Exception as e:
        logger.exception(f"Unexpected error during user access to private resources: {e}")
        raise InternalServerException(message="Unexpected error during user authorization.")


async def require_user_profile_and_get_id(
    user_id: UUID = Depends(get_current_user_id),
    user_profile_repo: UserProfileRepository = Depends(),
    cache_utils: MaintainCacheKeyUtils = Depends()
) -> UUID:
    """
    Dependency guard enforcing profile completion for private routes.
    
    Reads lightweight dedicated Redis key 'user:profile_completed:<user_id>'.
    Falls back to PostgreSQL query on cache miss and populates Redis.
    Raises HTTP 403 Forbidden if profile is not completed.
    """
    if settings.ENVIRONMENT != "prod":
        logger.warning("Profile completion check skipped for non-production environment.")
        return user_id

    cache_key = cache_utils.get_profile_completion_key(user_id)
    try:
        cached_val = await cache_utils.async_cache.get(name=cache_key)
    except Exception as e:
        logger.warning(f"Failed to fetch profile completion status from Redis: {e}")
        cached_val = None

    if cached_val is not None:
        is_profile_completed = str(cached_val).strip() in ("1", "true", "True")
    else:
        # Cache miss or Redis error: fallback to DB check
        user_profile = await user_profile_repo.get_by_id(user_id)
        is_profile_completed = user_profile is not None
        await cache_utils.profile_completion_cache(
            user_id=user_id, 
            is_profile_completed=is_profile_completed
        )

    if not is_profile_completed:
        logger.warning(f"Access denied for user {user_id}: profile setup not completed.")
        raise ForbiddenException(
            message="Profile setup required before accessing private resources.",
            error_code="PROFILE_SETUP_REQUIRED"
        )

    return user_id
