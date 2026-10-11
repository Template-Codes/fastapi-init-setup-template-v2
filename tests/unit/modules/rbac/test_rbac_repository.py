from unittest.mock import AsyncMock, MagicMock
import uuid
import pytest

from modules.rbac.rbac_model import Permission, Role
from modules.rbac.rbac_repository import RBACRepository
from shares.enums import RoleName, SystemPermission


@pytest.mark.asyncio
async def test_get_user_roles_and_permissions_filters_obsolete_enums():
    """Test get_user_roles_and_permissions queries DB and filters out obsolete enums."""
    mock_db = MagicMock()
    user_id = uuid.uuid4()

    # Mock role query result: contains valid ADMIN and obsolete DEPRECATED_ROLE
    role_exec_mock = MagicMock()
    role_exec_mock.fetchall.return_value = [("ADMIN",), ("DEPRECATED_ROLE",)]

    # Mock permission query result: contains valid PROFILE:USER:READ and obsolete OBSOLETE:ACTION
    perm_exec_mock = MagicMock()
    perm_exec_mock.fetchall.return_value = [
        (SystemPermission.PROFILE_USER_READ.value,),
        ("OBSOLETE:MODULE:ACTION",),
    ]

    # Mock direct user permission query result
    direct_exec_mock = MagicMock()
    direct_exec_mock.fetchall.return_value = []

    mock_db.execute = AsyncMock(side_effect=[role_exec_mock, perm_exec_mock, direct_exec_mock])

    repo = RBACRepository(db=mock_db)
    result = await repo.get_user_roles_and_permissions(user_id)

    assert result["user_id"] == str(user_id)
    # Only active RoleName is kept
    assert result["roles"] == ["ADMIN"]
    assert "DEPRECATED_ROLE" not in result["roles"]

    # Only active SystemPermission is kept
    assert result["permissions"] == [SystemPermission.PROFILE_USER_READ.value]
    assert "OBSOLETE:MODULE:ACTION" not in result["permissions"]


@pytest.mark.asyncio
async def test_get_role_by_identifier_by_name():
    """Test resolving role by name string."""
    mock_db = MagicMock()
    mock_role = MagicMock(spec=Role)
    mock_role.name = "ADMIN"
    mock_role.permissions = []

    res_mock = MagicMock()
    res_mock.scalar_one_or_none.return_value = mock_role
    mock_db.execute = AsyncMock(return_value=res_mock)

    repo = RBACRepository(db=mock_db)
    role = await repo.get_role_by_identifier("ADMIN")
    assert role is not None
    assert role.name == "ADMIN"


@pytest.mark.asyncio
async def test_resolve_roles_empty():
    """Test resolve_roles with empty list returns empty list immediately."""
    mock_db = MagicMock()
    repo = RBACRepository(db=mock_db)
    res = await repo.resolve_roles([])
    assert res == []


@pytest.mark.asyncio
async def test_resolve_permissions_empty():
    """Test resolve_permissions with empty list returns empty list immediately."""
    mock_db = MagicMock()
    repo = RBACRepository(db=mock_db)
    res = await repo.resolve_permissions([])
    assert res == []
