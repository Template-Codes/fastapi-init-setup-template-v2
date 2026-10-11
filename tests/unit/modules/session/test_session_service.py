import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
import pytest

from dependencies.credential_guard import (
    SudoCredentialRequest,
    require_sudo_credential,
    verify_sudo_credential,
)
from exceptions.app_exception import BadRequestException, NotFoundException, UnauthorizedException
from modules.session.session_service import SessionService


@pytest.mark.asyncio
async def test_verify_sudo_credential_success():
    """Test sudo credential verification succeeds when auth_service verifies password."""
    mock_auth_service = AsyncMock()
    mock_auth_service.verify_admin_user_credential.return_value = True

    user_id = uuid.uuid4()
    username = "admin"
    await verify_sudo_credential(
        user_id=user_id,
        username=username,
        plain_password="CorrectPassword123!",
        auth_service=mock_auth_service,
    )
    mock_auth_service.verify_admin_user_credential.assert_awaited_once_with(
        user_id=user_id, username=username, plain_password="CorrectPassword123!"
    )


@pytest.mark.asyncio
async def test_verify_sudo_credential_failure():
    """Test sudo credential verification raises UnauthorizedException on incorrect password."""
    mock_auth_service = AsyncMock()
    mock_auth_service.verify_admin_user_credential.return_value = False

    user_id = uuid.uuid4()
    username = "admin"
    with pytest.raises(UnauthorizedException) as exc_info:
        await verify_sudo_credential(
            user_id=user_id,
            username=username,
            plain_password="WrongPassword!",
            auth_service=mock_auth_service,
        )
    assert exc_info.value.status_code == 401
    assert exc_info.value.error_code == "INVALID_ADMIN_CREDENTIALS"


@pytest.mark.asyncio
async def test_require_sudo_credential_guard_success():
    """Test declarative route-level require_sudo_credential dependency with valid admin credential."""
    mock_auth_service = AsyncMock()
    mock_auth_service.verify_admin_user_credential.return_value = True

    mock_request = MagicMock()
    user_id = uuid.uuid4()
    mock_request.state.user_id = user_id

    req = SudoCredentialRequest(admin_username="admin", admin_password="CorrectPassword123!")
    result = await require_sudo_credential(
        credential=req,
        request=mock_request,
        auth_service=mock_auth_service,
    )

    assert result == req
    mock_auth_service.verify_admin_user_credential.assert_awaited_once_with(
        user_id=user_id, username="admin", plain_password="CorrectPassword123!"
    )


@pytest.mark.asyncio
async def test_require_sudo_credential_guard_missing_user_id():
    """Test require_sudo_credential raises UnauthorizedException when request.state.user_id is None."""
    mock_request = MagicMock()
    mock_request.state.user_id = None

    req = SudoCredentialRequest(admin_username="admin", admin_password="Password123!")
    with pytest.raises(UnauthorizedException) as exc_info:
        await require_sudo_credential(
            credential=req,
            request=mock_request,
            auth_service=AsyncMock(),
        )

    assert exc_info.value.status_code == 401
    assert "Authentication required" in exc_info.value.message


@pytest.mark.asyncio
async def test_logout_own_session_success():
    """Test user logging out of own session deactivates session and clears Redis cache."""
    mock_repo = AsyncMock()
    mock_cache = AsyncMock()
    mock_cache_utils = MagicMock()
    mock_cache_utils.create_cache_key.return_value = "cache:key:123"
    mock_cache_utils.create_cache_name.return_value = "cache:name:123"

    service = SessionService(
        user_session_repo=mock_repo,
        async_cache=mock_cache,
        cache_utils=mock_cache_utils,
    )

    user_id = uuid.uuid4()
    session_id = uuid.uuid4()
    res = await service.logout_own_session(user_id=user_id, session_id=session_id)

    assert res.status is True
    assert res.session_id == session_id
    mock_repo.deactivate_session_by_id.assert_awaited_once_with(session_id)
    mock_cache.delete.assert_awaited_once_with("cache:key:123")
    mock_cache.srem.assert_awaited_once_with("cache:name:123", "cache:key:123")


@pytest.mark.asyncio
async def test_admin_force_logout_by_session_id_success():
    """Test admin force-revoking an active session."""
    session_id = uuid.uuid4()
    user_id = uuid.uuid4()
    mock_session = MagicMock(id=session_id, user_id=user_id, is_active=True)

    mock_repo = AsyncMock()
    mock_repo.get_by_id.return_value = mock_session

    mock_cache = AsyncMock()
    mock_cache_utils = MagicMock()
    mock_cache_utils.create_cache_key.return_value = "cache:key"
    mock_cache_utils.create_cache_name.return_value = "cache:name"

    service = SessionService(
        user_session_repo=mock_repo,
        async_cache=mock_cache,
        cache_utils=mock_cache_utils,
    )

    res = await service.admin_force_logout_by_session_id(session_id=session_id)
    assert res.status is True
    mock_repo.deactivate_session_by_id.assert_awaited_once_with(session_id)
    mock_cache.delete.assert_awaited_once_with("cache:key")


@pytest.mark.asyncio
async def test_admin_force_logout_by_session_id_not_found():
    """Test admin force-revoking a non-existent session raises NotFoundException."""
    mock_repo = AsyncMock()
    mock_repo.get_by_id.return_value = None

    service = SessionService(
        user_session_repo=mock_repo,
        async_cache=AsyncMock(),
        cache_utils=MagicMock(),
    )

    with pytest.raises(NotFoundException):
        await service.admin_force_logout_by_session_id(session_id=uuid.uuid4())


@pytest.mark.asyncio
async def test_admin_force_logout_by_session_id_already_inactive():
    """Test admin force-revoking an inactive session raises BadRequestException."""
    mock_session = MagicMock(id=uuid.uuid4(), user_id=uuid.uuid4(), is_active=False)
    mock_repo = AsyncMock()
    mock_repo.get_by_id.return_value = mock_session

    service = SessionService(
        user_session_repo=mock_repo,
        async_cache=AsyncMock(),
        cache_utils=MagicMock(),
    )

    with pytest.raises(BadRequestException):
        await service.admin_force_logout_by_session_id(session_id=mock_session.id)


@pytest.mark.asyncio
async def test_admin_force_logout_all_sessions_success():
    """Test admin emergency mass terminating ALL active sessions enterprise-wide."""
    mock_repo = AsyncMock()
    mock_repo.deactivate_all_active_sessions.return_value = 5

    mock_cache = AsyncMock()
    async def mock_scan_iter(match="*"):
        for k in ["sessions:1:user:a", "user:sessions:a"]:
            yield k
    mock_cache.scan_iter = mock_scan_iter

    mock_cache_utils = MagicMock()

    service = SessionService(
        user_session_repo=mock_repo,
        async_cache=mock_cache,
        cache_utils=mock_cache_utils,
    )

    res = await service.admin_force_logout_all_sessions()

    assert res.status is True
    assert res.revoked_count == 5
    mock_repo.deactivate_all_active_sessions.assert_awaited_once()
    assert mock_cache.delete.await_count >= 1


@pytest.mark.asyncio
async def test_get_all_active_sessions_with_joined_user_and_profile():
    """Test retrieving enterprise-wide active sessions with joined user identity, roles, and profile."""
    now = datetime.now(timezone.utc)
    user_id_1 = uuid.uuid4()
    user_id_2 = uuid.uuid4()

    # User 1 with complete profile and role
    role_mock = MagicMock(name="SUPER_ADMIN")
    role_mock.name = "SUPER_ADMIN"
    profile_mock = MagicMock(first_name="John", last_name="Doe")
    user_mock_1 = MagicMock(
        id=user_id_1,
        user_code="USR-00001",
        username="johndoe",
        email="johndoe@example.com",
        status=MagicMock(value="ACTIVE"),
        roles=[role_mock],
        profile=profile_mock,
    )
    session_1 = MagicMock(
        id=uuid.uuid4(),
        user_id=user_id_1,
        is_active=True,
        ip_address="192.168.1.50",
        user_agent="Chrome/120.0",
        expires_at=now,
        last_active_at=now,
        created_at=now,
        user=user_mock_1,
    )

    # User 2 without profile (profile is None) and no roles
    user_mock_2 = MagicMock(
        id=user_id_2,
        user_code="USR-00002",
        username="janedoe",
        email="janedoe@example.com",
        status=MagicMock(value="ACTIVE"),
        roles=[],
        profile=None,
    )
    session_2 = MagicMock(
        id=uuid.uuid4(),
        user_id=user_id_2,
        is_active=True,
        ip_address="192.168.1.51",
        user_agent="Firefox/118.0",
        expires_at=now,
        last_active_at=now,
        created_at=now,
        user=user_mock_2,
    )

    mock_repo = AsyncMock()
    mock_repo.get_all_active_sessions_with_user_info.return_value = [session_1, session_2]

    service = SessionService(
        user_session_repo=mock_repo,
        async_cache=AsyncMock(),
        cache_utils=MagicMock(),
    )

    result = await service.get_all_active_sessions()
    assert len(result) == 2

    # Verify User 1
    assert result[0].id == session_1.id
    assert result[0].user.user_id == user_id_1
    assert result[0].user.user_code == "USR-00001"
    assert result[0].user.username == "johndoe"
    assert result[0].user.email == "johndoe@example.com"
    assert result[0].user.full_name == "John Doe"
    assert result[0].user.roles == ["SUPER_ADMIN"]
    assert result[0].ip_address == "192.168.1.50"

    # Verify User 2 (Graceful fallback for incomplete profile)
    assert result[1].id == session_2.id
    assert result[1].user.user_id == user_id_2
    assert result[1].user.user_code == "USR-00002"
    assert result[1].user.username == "janedoe"
    assert result[1].user.full_name is None
    assert result[1].user.roles == []
    assert result[1].ip_address == "192.168.1.51"
