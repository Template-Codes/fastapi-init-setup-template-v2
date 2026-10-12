from unittest.mock import AsyncMock, MagicMock
import uuid
import jwt
import pytest
from fastapi import Request
from fastapi.security import HTTPAuthorizationCredentials
from core.settings import settings
from exceptions.app_exception import ForbiddenException, UnauthorizedException
from dependencies.current_user import get_current_user_id, require_user_profile_and_get_id


def generate_valid_access_token(user_id: str, token_type: str = "access-token") -> str:
    """Helper to generate JWT access tokens for testing."""
    payload = {
        "sub": user_id,
        "type": token_type,
        "exp": 9999999999
    }
    return jwt.encode(payload, settings.ACCESS_JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_mock_request(cookies=None, pre_verified_user_id=None):
    """Create a mock Request object without MagicMock state.user_id auto-attribute trap."""
    request = MagicMock(spec=Request)
    request.cookies = cookies or {}
    request.state = MagicMock(spec=[])
    if pre_verified_user_id:
        request.state.user_id = pre_verified_user_id
    return request


@pytest.mark.asyncio
async def test_get_current_user_id_pre_verified_in_request_state():
    """Test returning pre-verified user_id directly from request.state injected by JWTValidator."""
    user_uuid = uuid.uuid4()
    request = create_mock_request(pre_verified_user_id=user_uuid)

    result = await get_current_user_id(request=request, credentials=None)
    assert result == user_uuid


@pytest.mark.asyncio
async def test_get_current_user_id_from_bearer_header():
    """Test extracting user ID from Bearer Authorization header."""
    user_uuid = uuid.uuid4()
    token = generate_valid_access_token(str(user_uuid))
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    request = create_mock_request()

    result = await get_current_user_id(request=request, credentials=credentials)
    assert result == user_uuid


@pytest.mark.asyncio
async def test_get_current_user_id_from_cookie():
    """Test extracting user ID from access_token cookie when header is absent."""
    user_uuid = uuid.uuid4()
    token = generate_valid_access_token(str(user_uuid))
    request = create_mock_request(cookies={"access_token": token})

    result = await get_current_user_id(request=request, credentials=None)
    assert result == user_uuid


@pytest.mark.asyncio
async def test_get_current_user_id_missing_token():
    """Test that missing both header and cookie raises UnauthorizedException."""
    request = create_mock_request()

    with pytest.raises(UnauthorizedException) as exc_info:
        await get_current_user_id(request=request, credentials=None)

    assert exc_info.value.status_code == 401
    assert "Access token required" in exc_info.value.message


@pytest.mark.asyncio
async def test_get_current_user_id_invalid_token_type():
    """Test that providing a refresh-token raises UnauthorizedException."""
    user_uuid = uuid.uuid4()
    token = generate_valid_access_token(str(user_uuid), token_type="refresh-token")
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    request = create_mock_request()

    with pytest.raises(UnauthorizedException) as exc_info:
        await get_current_user_id(request=request, credentials=credentials)

    assert exc_info.value.status_code == 401
    assert "Invalid token type" in exc_info.value.message


@pytest.mark.asyncio
async def test_get_current_user_id_invalid_jwt_signature():
    """Test that tampered JWT signature raises UnauthorizedException."""
    request = create_mock_request()
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials="invalid.jwt.token")

    with pytest.raises(UnauthorizedException) as exc_info:
        await get_current_user_id(request=request, credentials=credentials)

    assert exc_info.value.status_code == 401
    assert "Invalid or expired access token" in exc_info.value.message


@pytest.mark.asyncio
async def test_require_user_profile_non_prod_skipped():
    """Test require_user_profile_and_get_id skips check when ENVIRONMENT is not 'prod'."""
    user_id = uuid.uuid4()
    mock_repo = AsyncMock()
    mock_cache_utils = MagicMock()

    result = await require_user_profile_and_get_id(
        user_id=user_id,
        user_profile_repo=mock_repo,
        cache_utils=mock_cache_utils
    )

    assert result == user_id
    mock_repo.get_by_id.assert_not_called()
    mock_cache_utils.get_profile_completion_key.assert_not_called()


@pytest.mark.asyncio
async def test_require_user_profile_cache_hit_completed(monkeypatch):
    """Test require_user_profile_and_get_id on Redis cache hit with completed profile."""
    monkeypatch.setattr(settings, "ENVIRONMENT", "prod")
    user_id = uuid.uuid4()
    mock_repo = AsyncMock()
    mock_cache_utils = MagicMock()
    mock_cache_utils.get_profile_completion_key.return_value = f"user:profile_completed:{user_id}"
    mock_cache_utils.async_cache = AsyncMock()
    mock_cache_utils.async_cache.get.return_value = "1"

    result = await require_user_profile_and_get_id(
        user_id=user_id,
        user_profile_repo=mock_repo,
        cache_utils=mock_cache_utils
    )

    assert result == user_id
    mock_repo.get_by_id.assert_not_called()


@pytest.mark.asyncio
async def test_require_user_profile_cache_miss_db_fallback_success(monkeypatch):
    """Test require_user_profile_and_get_id on Redis cache miss with DB check success."""
    monkeypatch.setattr(settings, "ENVIRONMENT", "prod")
    user_id = uuid.uuid4()
    mock_repo = AsyncMock()
    mock_repo.get_by_id.return_value = MagicMock(user_id=user_id)

    mock_cache_utils = MagicMock()
    mock_cache_utils.get_profile_completion_key.return_value = f"user:profile_completed:{user_id}"
    mock_cache_utils.async_cache = AsyncMock()
    mock_cache_utils.async_cache.get.return_value = None
    mock_cache_utils.profile_completion_cache = AsyncMock()

    result = await require_user_profile_and_get_id(
        user_id=user_id,
        user_profile_repo=mock_repo,
        cache_utils=mock_cache_utils
    )

    assert result == user_id
    mock_repo.get_by_id.assert_awaited_once_with(user_id)
    mock_cache_utils.profile_completion_cache.assert_awaited_once_with(
        user_id=user_id,
        is_profile_completed=True
    )


@pytest.mark.asyncio
async def test_require_user_profile_incomplete_raises_forbidden(monkeypatch):
    """Test that an incomplete profile raises 403 ForbiddenException PROFILE_SETUP_REQUIRED."""
    monkeypatch.setattr(settings, "ENVIRONMENT", "prod")
    user_id = uuid.uuid4()
    mock_repo = AsyncMock()
    mock_repo.get_by_id.return_value = None

    mock_cache_utils = MagicMock()
    mock_cache_utils.get_profile_completion_key.return_value = f"user:profile_completed:{user_id}"
    mock_cache_utils.async_cache = AsyncMock()
    mock_cache_utils.async_cache.get.return_value = "0"

    with pytest.raises(ForbiddenException) as exc_info:
        await require_user_profile_and_get_id(
            user_id=user_id,
            user_profile_repo=mock_repo,
            cache_utils=mock_cache_utils
        )

    assert exc_info.value.status_code == 403
    assert exc_info.value.error_code == "PROFILE_SETUP_REQUIRED"
