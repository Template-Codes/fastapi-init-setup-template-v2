from datetime import datetime, timedelta, timezone
import json
import hashlib
from unittest.mock import AsyncMock, MagicMock
import uuid
import jwt
import pytest

from core.settings import settings
from exceptions.app_exception import BadRequestException, ConflictException, ForbiddenException, NotFoundException, UnauthorizedException
from modules.authentication.auth_model import User, UserStatus
from modules.authentication.auth_schema import UserAuthenticationRequest, UserRegistrationRequest
from modules.authentication.auth_service import AuthenticationService


def test_auth_service_hash_and_verify_password():
    """Test password hashing and verification using Argon2id."""
    service = AuthenticationService(
        auth_repo=MagicMock(),
        user_profile_repo=MagicMock(),
        user_session_repo=MagicMock(),
        async_cache=AsyncMock(),
        cache_utils=MagicMock()
    )
    plain_pass = "SecurePass123!"

    hashed = service._hash_password(plain_pass)
    assert hashed != plain_pass
    assert service._verify_password(plain_pass, hashed) is True
    assert service._verify_password("WrongPassword123!", hashed) is False


@pytest.mark.asyncio
async def test_register_user_success():
    """Test successful user registration flow."""
    mock_repo = AsyncMock()
    mock_repo.is_email_exists.return_value = False

    mock_created_user = MagicMock()
    mock_created_user.id = "987e6543-e89b-12d3-a456-426614174000"
    mock_created_user.user_code = "USR-00001"
    mock_created_user.username = "testuser"
    mock_created_user.email = "test@example.com"
    mock_created_user.status = "PENDING"
    mock_repo.create.return_value = mock_created_user

    service = AuthenticationService(
        auth_repo=mock_repo,
        user_profile_repo=AsyncMock(),
        user_session_repo=AsyncMock(),
        async_cache=AsyncMock(),
        cache_utils=AsyncMock()
    )
    req = UserRegistrationRequest(
        username="testuser",
        email="TEST@EXAMPLE.COM",
        plain_password="Password123!"
    )

    response = await service.register_user(req)

    mock_repo.is_email_exists.assert_awaited_once_with("test@example.com")
    mock_repo.create.assert_awaited_once()

    create_args = mock_repo.create.call_args[1]["data"]
    assert create_args["email"] == "test@example.com"
    assert "password_hash" in create_args
    assert "plain_password" not in create_args

    assert response.id == "987e6543-e89b-12d3-a456-426614174000"
    assert response.username == "testuser"
    assert response.email == "test@example.com"
    assert response.status == "PENDING"
    assert response.response_details.status is True


@pytest.mark.asyncio
async def test_register_user_duplicate_email():
    """Test that registering with an existing email raises ConflictException."""
    mock_repo = AsyncMock()
    mock_repo.is_email_exists.return_value = True

    service = AuthenticationService(
        auth_repo=mock_repo,
        user_profile_repo=AsyncMock(),
        user_session_repo=AsyncMock(),
        async_cache=AsyncMock(),
        cache_utils=AsyncMock()
    )
    req = UserRegistrationRequest(
        username="newuser",
        email="existing@example.com",
        plain_password="Password123!"
    )

    with pytest.raises(ConflictException) as exc_info:
        await service.register_user(req)

    assert exc_info.value.status_code == 409
    assert exc_info.value.error_code == "EMAIL_ALREADY_EXISTS"
    mock_repo.create.assert_not_called()


@pytest.mark.asyncio
async def test_authenticate_user_not_found():
    """Test authenticate_user raises 401 generic message when username is not found."""
    mock_auth_repo = AsyncMock()
    mock_auth_repo.get_user_by_username.return_value = None

    service = AuthenticationService(
        auth_repo=mock_auth_repo,
        user_profile_repo=AsyncMock(),
        user_session_repo=AsyncMock(),
        async_cache=AsyncMock(),
        cache_utils=AsyncMock()
    )

    cred = UserAuthenticationRequest(username="non_existent", plain_password="Password123!")
    with pytest.raises(UnauthorizedException) as exc_info:
        await service.authenticate_user(cred)

    assert exc_info.value.status_code == 401
    assert "Invalid username or password" in exc_info.value.message


@pytest.mark.asyncio
async def test_authenticate_user_pre_auth_lockout():
    """Test authenticate_user raises 401 when IP/Username pair is locked out in Redis."""
    mock_auth_repo = AsyncMock()
    user = MagicMock(spec=User)
    user.username = "locked_user"
    mock_auth_repo.get_user_by_username.return_value = user

    mock_cache_utils = AsyncMock()
    mock_cache_utils.is_ip_user_blocked.return_value = True

    service = AuthenticationService(
        auth_repo=mock_auth_repo,
        user_profile_repo=AsyncMock(),
        user_session_repo=AsyncMock(),
        async_cache=AsyncMock(),
        cache_utils=mock_cache_utils
    )

    cred = UserAuthenticationRequest(username="locked_user", plain_password="Password123!")
    with pytest.raises(UnauthorizedException) as exc_info:
        await service.authenticate_user(cred, ip_address="192.168.1.100")

    assert exc_info.value.status_code == 401
    assert "Invalid username or password" in exc_info.value.message
    mock_cache_utils.is_ip_user_blocked.assert_awaited_once_with("192.168.1.100", "locked_user")


@pytest.mark.asyncio
async def test_authenticate_user_inactive_status():
    """Test authenticate_user raises 403 when user account is not active."""
    mock_auth_repo = AsyncMock()
    user = MagicMock(spec=User)
    user.username = "pending_user"
    user.status = UserStatus.PENDING
    user.banned_until_time = None
    mock_auth_repo.get_user_by_username.return_value = user

    mock_cache_utils = AsyncMock()
    mock_cache_utils.is_ip_user_blocked.return_value = False

    service = AuthenticationService(
        auth_repo=mock_auth_repo,
        user_profile_repo=AsyncMock(),
        user_session_repo=AsyncMock(),
        async_cache=AsyncMock(),
        cache_utils=mock_cache_utils
    )

    cred = UserAuthenticationRequest(username="pending_user", plain_password="Password123!")
    with pytest.raises(ForbiddenException) as exc_info:
        await service.authenticate_user(cred)

    assert exc_info.value.status_code == 403
    assert "Account is not in active status" in exc_info.value.message


@pytest.mark.asyncio
async def test_authenticate_user_actively_banned():
    """Test authenticate_user raises 403 when user is within active ban window."""
    mock_auth_repo = AsyncMock()
    user = MagicMock(spec=User)
    user.username = "banned_user"
    user.status = UserStatus.ACTIVE
    user.banned_until_time = datetime.now(timezone.utc) + timedelta(minutes=10)
    mock_auth_repo.get_user_by_username.return_value = user

    mock_cache_utils = AsyncMock()
    mock_cache_utils.is_ip_user_blocked.return_value = False

    service = AuthenticationService(
        auth_repo=mock_auth_repo,
        user_profile_repo=AsyncMock(),
        user_session_repo=AsyncMock(),
        async_cache=AsyncMock(),
        cache_utils=mock_cache_utils
    )

    cred = UserAuthenticationRequest(username="banned_user", plain_password="Password123!")
    with pytest.raises(ForbiddenException) as exc_info:
        await service.authenticate_user(cred)

    assert exc_info.value.status_code == 403
    assert "Account is not in active status" in exc_info.value.message


@pytest.mark.asyncio
async def test_authenticate_user_expired_ban_recovers_account():
    """Test that an expired ban automatically restores user status to ACTIVE."""
    mock_auth_repo = AsyncMock()
    user = MagicMock(spec=User)
    user.id = uuid.uuid4()
    user.user_code = "USR-00001"
    user.username = "recovered_user"
    user.email = "recovered@example.com"
    user.status = UserStatus.SUSPENDED
    user.password_hash = AuthenticationService.pwd_context.hash("Password123!")
    user.banned_until_time = datetime.now(timezone.utc) - timedelta(minutes=1)
    mock_auth_repo.get_user_by_username.return_value = user
    mock_auth_repo.db = AsyncMock()

    mock_session_repo = AsyncMock()
    mock_session_repo.get_active_session_by_user_id.return_value = None
    mock_session_repo.create.return_value = MagicMock(id=uuid.uuid4())

    mock_cache_utils = AsyncMock()
    mock_cache_utils.is_ip_user_blocked.return_value = False

    service = AuthenticationService(
        auth_repo=mock_auth_repo,
        user_profile_repo=AsyncMock(get_by_id=AsyncMock(return_value=None)),
        user_session_repo=mock_session_repo,
        async_cache=AsyncMock(),
        cache_utils=mock_cache_utils
    )

    cred = UserAuthenticationRequest(username="recovered_user", plain_password="Password123!")
    response = await service.authenticate_user(cred)

    assert response is not None
    assert user.banned_until_time is None
    assert user.status == UserStatus.ACTIVE


@pytest.mark.asyncio
async def test_authenticate_user_password_mismatch_records_failed_login():
    """Test password mismatch triggers record_failed_login and raises 401 generic message."""
    mock_auth_repo = AsyncMock()
    user = MagicMock(spec=User)
    user.username = "test_user"
    user.status = UserStatus.ACTIVE
    user.banned_until_time = None
    user.password_hash = AuthenticationService.pwd_context.hash("CorrectPassword123!")
    mock_auth_repo.get_user_by_username.return_value = user

    mock_cache_utils = AsyncMock()
    mock_cache_utils.is_ip_user_blocked.return_value = False

    service = AuthenticationService(
        auth_repo=mock_auth_repo,
        user_profile_repo=AsyncMock(),
        user_session_repo=AsyncMock(),
        async_cache=AsyncMock(),
        cache_utils=mock_cache_utils
    )

    cred = UserAuthenticationRequest(username="test_user", plain_password="WrongPassword123!")
    with pytest.raises(UnauthorizedException) as exc_info:
        await service.authenticate_user(cred, ip_address="10.0.0.5")

    assert exc_info.value.status_code == 401
    assert "Invalid username or password" in exc_info.value.message
    mock_cache_utils.record_failed_login.assert_awaited_once_with("10.0.0.5", "test_user")


@pytest.mark.asyncio
async def test_refresh_authentication_tokens_success():
    """Test successful token rotation returning both access_token and refresh_token."""
    user_id = uuid.uuid4()
    session_id = uuid.uuid4()
    exp = datetime.now(timezone.utc) + timedelta(hours=1)

    payload = {
        "sub": str(user_id),
        "sid": str(session_id),
        "type": "refresh-token",
        "exp": int(exp.timestamp())
    }
    refresh_token = jwt.encode(payload, settings.REFRESH_JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    refresh_token_hash = hashlib.sha256(refresh_token.encode("utf-8")).hexdigest()

    cached_payload = {
        "id": str(session_id),
        "user_id": str(user_id),
        "refresh_token_hash": refresh_token_hash,
        "is_active": True,
    }

    mock_cache = AsyncMock()
    mock_cache.get.return_value = json.dumps(cached_payload)

    service = AuthenticationService(
        auth_repo=AsyncMock(),
        user_profile_repo=AsyncMock(),
        user_session_repo=AsyncMock(),
        async_cache=mock_cache,
        cache_utils=AsyncMock()
    )

    response = await service.refresh_authentication_tokens(refresh_token)

    assert response is not None
    assert response.auth_token_payload is not None
    assert response.auth_token_payload.access_token is not None
    assert response.auth_token_payload.refresh_token is not None
    assert response.response_details.status is True


@pytest.mark.asyncio
async def test_refresh_authentication_tokens_missing_raises_unauthorized():
    """Test refresh_authentication_tokens raises 401 when refresh token is None."""
    service = AuthenticationService(
        auth_repo=AsyncMock(),
        user_profile_repo=AsyncMock(),
        user_session_repo=AsyncMock(),
        async_cache=AsyncMock(),
        cache_utils=AsyncMock()
    )

    with pytest.raises(UnauthorizedException) as exc_info:
        await service.refresh_authentication_tokens(None)

    assert exc_info.value.status_code == 401
    assert "Invalid or expired session" in exc_info.value.message


@pytest.mark.asyncio
async def test_refresh_authentication_tokens_revoked_in_redis_raises_unauthorized():
    """Test refresh_authentication_tokens raises 401 when session is inactive or revoked."""
    user_id = uuid.uuid4()
    session_id = uuid.uuid4()
    exp = datetime.now(timezone.utc) + timedelta(hours=1)

    payload = {
        "sub": str(user_id),
        "sid": str(session_id),
        "type": "refresh-token",
        "exp": int(exp.timestamp())
    }
    refresh_token = jwt.encode(payload, settings.REFRESH_JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

    mock_cache = AsyncMock()
    mock_cache.get.return_value = None  # Cache miss / revoked

    mock_session_repo = AsyncMock()
    mock_session_repo.get_by_id.return_value = None  # DB miss / revoked

    service = AuthenticationService(
        auth_repo=AsyncMock(),
        user_profile_repo=AsyncMock(),
        user_session_repo=mock_session_repo,
        async_cache=mock_cache,
        cache_utils=AsyncMock()
    )

    with pytest.raises(UnauthorizedException) as exc_info:
        await service.refresh_authentication_tokens(refresh_token)

    assert exc_info.value.status_code == 401
    assert "Invalid or expired session" in exc_info.value.message


@pytest.mark.asyncio
async def test_authenticate_user_multi_session_allowed():
    """Test that existing active session does NOT block concurrent login (multi-session support)."""
    mock_auth_repo = AsyncMock()
    user = MagicMock(spec=User)
    user.id = uuid.uuid4()
    user.user_code = "USR-00001"
    user.username = "multi_session_user"
    user.email = "multi@example.com"
    user.status = UserStatus.ACTIVE
    user.banned_until_time = None
    user.password_hash = AuthenticationService.pwd_context.hash("Password123!")
    mock_auth_repo.get_user_by_username.return_value = user

    mock_session_repo = AsyncMock()
    new_session_mock = MagicMock(id=uuid.uuid4())
    mock_session_repo.create.return_value = new_session_mock

    mock_cache_utils = AsyncMock()
    mock_cache_utils.is_ip_user_blocked.return_value = False

    service = AuthenticationService(
        auth_repo=mock_auth_repo,
        user_profile_repo=AsyncMock(get_by_id=AsyncMock(return_value=None)),
        user_session_repo=mock_session_repo,
        async_cache=AsyncMock(),
        cache_utils=mock_cache_utils
    )

    cred = UserAuthenticationRequest(username="multi_session_user", plain_password="Password123!")
    response = await service.authenticate_user(cred)

    assert response is not None
    assert response.status == "ACTIVE"
    mock_session_repo.create.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_pending_registrations():
    """Test retrieving list of users in PENDING status."""
    mock_auth_repo = AsyncMock()
    user1 = MagicMock(id=uuid.uuid4(), user_code="USR-00001", username="user1", email="user1@example.com", status=UserStatus.PENDING, created_at=datetime.now(timezone.utc))
    user2 = MagicMock(id=uuid.uuid4(), user_code="USR-00002", username="user2", email="user2@example.com", status=UserStatus.PENDING, created_at=datetime.now(timezone.utc))
    mock_auth_repo.get_pending_users.return_value = [user1, user2]

    service = AuthenticationService(
        auth_repo=mock_auth_repo,
        user_profile_repo=AsyncMock(),
        user_session_repo=AsyncMock(),
        async_cache=AsyncMock(),
        cache_utils=AsyncMock(),
    )

    result = await service.get_pending_registrations()
    assert len(result) == 2
    assert result[0].username == "user1"
    assert result[1].username == "user2"
    mock_auth_repo.get_pending_users.assert_awaited_once()


@pytest.mark.asyncio
async def test_approve_user_registration_success():
    """Test successfully approving a pending user and assigning role."""
    mock_auth_repo = AsyncMock()
    user = MagicMock(id=uuid.uuid4(), user_code="USR-00001", username="pending_user", status=UserStatus.PENDING)
    mock_auth_repo.get_by_id.return_value = user

    service = AuthenticationService(
        auth_repo=mock_auth_repo,
        user_profile_repo=AsyncMock(),
        user_session_repo=AsyncMock(),
        async_cache=AsyncMock(),
        cache_utils=AsyncMock(),
    )

    res = await service.approve_user_registration(user.id, role_name="STAFF_USER")
    assert res.status is True
    assert res.user_status == "ACTIVE"
    assert user.status == UserStatus.ACTIVE
    mock_auth_repo.assign_role_to_user.assert_awaited_once_with(user_id=user.id, role_name="STAFF_USER")
    mock_auth_repo.db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_approve_user_registration_not_found():
    """Test approving a non-existent user raises NotFoundException."""
    mock_auth_repo = AsyncMock()
    mock_auth_repo.get_by_id.return_value = None

    service = AuthenticationService(
        auth_repo=mock_auth_repo,
        user_profile_repo=AsyncMock(),
        user_session_repo=AsyncMock(),
        async_cache=AsyncMock(),
        cache_utils=AsyncMock(),
    )

    with pytest.raises(NotFoundException):
        await service.approve_user_registration(uuid.uuid4())


@pytest.mark.asyncio
async def test_approve_user_registration_already_active():
    """Test approving an already active user raises BadRequestException."""
    mock_auth_repo = AsyncMock()
    user = MagicMock(id=uuid.uuid4(), username="active_user", status=UserStatus.ACTIVE)
    mock_auth_repo.get_by_id.return_value = user

    service = AuthenticationService(
        auth_repo=mock_auth_repo,
        user_profile_repo=AsyncMock(),
        user_session_repo=AsyncMock(),
        async_cache=AsyncMock(),
        cache_utils=AsyncMock(),
    )

    with pytest.raises(BadRequestException):
        await service.approve_user_registration(user.id)


@pytest.mark.asyncio
async def test_reject_user_registration_success():
    """Test rejecting a pending user marks them INACTIVE."""
    mock_auth_repo = AsyncMock()
    user = MagicMock(id=uuid.uuid4(), user_code="USR-00001", username="rejected_user", status=UserStatus.PENDING)
    mock_auth_repo.get_by_id.return_value = user

    service = AuthenticationService(
        auth_repo=mock_auth_repo,
        user_profile_repo=AsyncMock(),
        user_session_repo=AsyncMock(),
        async_cache=AsyncMock(),
        cache_utils=AsyncMock(),
    )

    res = await service.reject_user_registration(user.id)
    assert res.status is True
    assert res.user_status == "INACTIVE"
    assert user.status == UserStatus.INACTIVE
    mock_auth_repo.db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_verify_admin_user_credential():
    """Test password verification by user ID and username."""
    mock_auth_repo = AsyncMock()
    user = MagicMock(
        id=uuid.uuid4(),
        username="admin",
        password_hash=AuthenticationService.pwd_context.hash("CorrectPassword123!"),
    )
    mock_auth_repo.get_by_id.return_value = user

    service = AuthenticationService(
        auth_repo=mock_auth_repo,
        user_profile_repo=AsyncMock(),
        user_session_repo=AsyncMock(),
        async_cache=AsyncMock(),
        cache_utils=AsyncMock(),
    )

    assert await service.verify_admin_user_credential(user.id, "admin", "CorrectPassword123!") is True
    assert await service.verify_admin_user_credential(user.id, "wrong_user", "CorrectPassword123!") is False
    assert await service.verify_admin_user_credential(user.id, "admin", "WrongPassword") is False

    mock_auth_repo.get_by_id.return_value = None
    assert await service.verify_admin_user_credential(uuid.uuid4(), "admin", "CorrectPassword123!") is False


