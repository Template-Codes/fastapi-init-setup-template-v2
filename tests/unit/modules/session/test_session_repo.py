from unittest.mock import AsyncMock, MagicMock
import pytest
from exceptions.app_exception import InternalServerException
from modules.session.session_repo import UserSessionRepository


@pytest.mark.asyncio
async def test_deactivate_token_success():
    """Test successful deactivation of an active session token."""
    mock_db = AsyncMock()
    mock_result = MagicMock()
    mock_session_instance = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_session_instance
    mock_db.execute.return_value = mock_result

    repo = UserSessionRepository(db=mock_db)
    result = await repo.deactivate_token("sample_token_hash_123")

    mock_db.execute.assert_awaited_once()
    mock_db.commit.assert_awaited_once()
    assert result == mock_session_instance


@pytest.mark.asyncio
async def test_deactivate_token_not_found_returns_none():
    """Test deactivating non-existent or already expired token returns None."""
    mock_db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db.execute.return_value = mock_result

    repo = UserSessionRepository(db=mock_db)
    result = await repo.deactivate_token("non_existent_hash")

    assert result is None


@pytest.mark.asyncio
async def test_deactivate_token_db_exception_raises_internal_server_exception():
    """Test that DB exceptions during session update raise InternalServerException."""
    mock_db = AsyncMock()
    mock_db.execute.side_effect = Exception("DB query timeout")

    repo = UserSessionRepository(db=mock_db)
    with pytest.raises(InternalServerException) as exc_info:
        await repo.deactivate_token("error_hash")

    assert exc_info.value.status_code == 500
    assert exc_info.value.error_code == "SESSION_UPDATE_FAILED"


@pytest.mark.asyncio
async def test_get_active_session_by_user_id_found():
    """Test get_active_session_by_user_id returns active session."""
    from uuid import uuid4
    mock_db = AsyncMock()
    mock_result = MagicMock()
    mock_session = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_session
    mock_db.execute.return_value = mock_result

    repo = UserSessionRepository(db=mock_db)
    user_id = uuid4()
    result = await repo.get_active_session_by_user_id(user_id)

    mock_db.execute.assert_awaited_once()
    assert result == mock_session


@pytest.mark.asyncio
async def test_get_active_session_by_user_id_not_found():
    """Test get_active_session_by_user_id returns None when no active session."""
    from uuid import uuid4
    mock_db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db.execute.return_value = mock_result

    repo = UserSessionRepository(db=mock_db)
    result = await repo.get_active_session_by_user_id(uuid4())

    mock_db.execute.assert_awaited_once()
    assert result is None


@pytest.mark.asyncio
async def test_deactivate_session_by_id_success():
    """Test deactivate_session_by_id updates and returns session."""
    from uuid import uuid4
    mock_db = AsyncMock()
    mock_result = MagicMock()
    mock_session = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_session
    mock_db.execute.return_value = mock_result

    repo = UserSessionRepository(db=mock_db)
    session_id = uuid4()
    result = await repo.deactivate_session_by_id(session_id)

    mock_db.execute.assert_awaited_once()
    mock_db.commit.assert_awaited_once()
    assert result == mock_session


@pytest.mark.asyncio
async def test_deactivate_all_active_sessions():
    """Test deactivate_all_active_sessions deactivates all active sessions."""
    from uuid import uuid4
    mock_db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [uuid4(), uuid4()]
    mock_db.execute.return_value = mock_result

    repo = UserSessionRepository(db=mock_db)
    count = await repo.deactivate_all_active_sessions()

    mock_db.execute.assert_awaited_once()
    mock_db.commit.assert_awaited_once()
    assert count == 2
