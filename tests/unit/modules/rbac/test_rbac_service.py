from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
import uuid
import pytest

from exceptions.app_exception import (
    BadRequestException,
    ConflictException,
    ForbiddenException,
    NotFoundException,
)
from modules.authentication.auth_model import User
from modules.rbac.rbac_model import (
    Permission,
    RBACChangeRequest,
    RBACChangeRequestStatus,
    Role,
    UserPermission,
)
from modules.rbac.rbac_schema import (
    AssignUserDirectPermissionsPayload,
    ReviewChangeRequestPayload,
)
from modules.rbac.rbac_service import RBACService
from shares.enums import SystemPermission


@pytest.fixture
def mock_rbac_repo():
    repo = MagicMock()
    repo.db = MagicMock()
    repo.db.commit = AsyncMock()
    repo.db.expire_all = MagicMock()
    repo.count_active_super_admins = AsyncMock(return_value=2)
    repo.assign_roles_to_user = AsyncMock(return_value=[])
    repo.get_user_roles_and_permissions = AsyncMock(return_value={"roles": [], "permissions": []})
    repo.get_user_with_rbac_details = AsyncMock(return_value=None)
    repo.create_user_rbac_snapshot = AsyncMock()
    repo.create_role_permission_snapshot = AsyncMock()
    repo.get_role_permission_history = AsyncMock(return_value=[])
    repo.get_user_rbac_history = AsyncMock(return_value=[])
    repo.get_role_permission_snapshot_by_id = AsyncMock(return_value=None)
    repo.get_user_rbac_snapshot_by_id = AsyncMock(return_value=None)
    repo.restore_user_direct_permissions = AsyncMock()
    repo.get_user_ids_by_role = AsyncMock(return_value=[])
    repo.resolve_roles = AsyncMock(return_value=[])
    return repo


@pytest.fixture
def mock_auth_repo():
    repo = MagicMock()
    repo.get_by_id = AsyncMock(return_value=None)
    return repo


@pytest.fixture
def mock_session_repo():
    repo = MagicMock()
    repo.deactivate_all_active_by_user_id = AsyncMock(return_value=1)
    return repo


@pytest.fixture
def mock_cache_utils():
    utils = MagicMock()
    utils.async_cache = MagicMock()
    utils.async_cache.get = AsyncMock(return_value=None)
    utils.create_user_permission_cache_key = MagicMock(side_effect=lambda uid: f"user_permission:{uid}")
    utils.cache_user_permissions = AsyncMock()
    utils.invalidate_user_permission_cache = AsyncMock()
    return utils


@pytest.fixture
def rbac_service(mock_rbac_repo, mock_auth_repo, mock_session_repo, mock_cache_utils):
    return RBACService(
        rbac_repo=mock_rbac_repo,
        auth_repo=mock_auth_repo,
        session_repo=mock_session_repo,
        cache_utils=mock_cache_utils,
    )


@pytest.mark.asyncio
async def test_get_rbac_configuration(rbac_service, mock_rbac_repo):
    """Test get_rbac_configuration returns hierarchical tree and active roles with ranks and permissions."""
    role_id = uuid.uuid4()
    mock_perm = MagicMock(spec=Permission)
    mock_perm.code = SystemPermission.AUTHENTICATION_USER_READ.value

    mock_role = MagicMock(spec=Role)
    mock_role.id = role_id
    mock_role.name = "ADMIN"
    mock_role.description = "System Administrator"
    mock_role.is_system_role = True
    mock_role.permissions = [mock_perm]

    mock_rbac_repo.get_all_roles = AsyncMock(return_value=[mock_role])

    config = await rbac_service.get_rbac_configuration()

    module_names = [m.name for m in config.modules]
    assert "AUTHENTICATION" in module_names
    assert "PROFILE" in module_names
    assert "RBAC" in module_names

    assert len(config.roles) == 1
    assert config.roles[0].name == "ADMIN"
    assert config.roles[0].rank == 50
    assert config.roles[0].permissions == [SystemPermission.AUTHENTICATION_USER_READ.value]


@pytest.mark.asyncio
async def test_self_mutation_refusal(rbac_service):
    """Test operators cannot modify their own assigned roles (CANNOT_MODIFY_OWN_ROLES)."""
    operator_id = uuid.uuid4()

    with pytest.raises(ForbiddenException) as exc_info:
        await rbac_service.assign_roles_to_user(
            operator_id=operator_id,
            user_id=operator_id,
            role_identifiers=["ADMIN"],
            reason="Attempting self-mutation.",
        )
    assert exc_info.value.error_code == "CANNOT_MODIFY_OWN_ROLES"


@pytest.mark.asyncio
async def test_role_rank_escalation_refusal(rbac_service, mock_auth_repo, mock_rbac_repo, mock_cache_utils):
    """Test ADMIN (rank 50) cannot assign SUPER_ADMIN (rank 100) to another user."""
    operator_id = uuid.uuid4()
    target_id = uuid.uuid4()

    # Operator is ADMIN
    mock_cache_utils.async_cache.get = AsyncMock(side_effect=[
        '{"roles": ["ADMIN"], "permissions": []}',  # operator
        '{"roles": ["STAFF_USER"], "permissions": []}',  # target
    ])

    target_user = MagicMock(spec=User)
    target_user.id = target_id
    target_user.username = "staffuser"
    mock_auth_repo.get_by_id = AsyncMock(return_value=target_user)

    mock_super_role = MagicMock(spec=Role)
    mock_super_role.id = uuid.uuid4()
    mock_super_role.name = "SUPER_ADMIN"
    mock_rbac_repo.resolve_roles = AsyncMock(return_value=[mock_super_role])

    with pytest.raises(ForbiddenException) as exc_info:
        await rbac_service.assign_roles_to_user(
            operator_id=operator_id,
            user_id=target_id,
            role_identifiers=["SUPER_ADMIN"],
            reason="Escalation attempt.",
        )
    assert exc_info.value.error_code == "ROLE_RANK_ESCALATION"


@pytest.mark.asyncio
async def test_target_user_rank_refusal(rbac_service, mock_auth_repo, mock_rbac_repo, mock_cache_utils):
    """Test ADMIN (rank 50) cannot modify a SUPER_ADMIN (rank 100) user."""
    operator_id = uuid.uuid4()
    target_id = uuid.uuid4()

    # Operator is ADMIN, target is SUPER_ADMIN
    mock_cache_utils.async_cache.get = AsyncMock(side_effect=[
        '{"roles": ["ADMIN"], "permissions": []}',  # operator
        '{"roles": ["SUPER_ADMIN"], "permissions": []}',  # target
    ])

    target_user = MagicMock(spec=User)
    target_user.id = target_id
    target_user.username = "superadmin"
    mock_auth_repo.get_by_id = AsyncMock(return_value=target_user)

    with pytest.raises(ForbiddenException) as exc_info:
        await rbac_service.assign_roles_to_user(
            operator_id=operator_id,
            user_id=target_id,
            role_identifiers=["STAFF_USER"],
            reason="Demotion attempt.",
        )
    assert exc_info.value.error_code == "INSUFFICIENT_ROLE_RANK"


@pytest.mark.asyncio
async def test_last_super_admin_demotion_refusal(rbac_service, mock_auth_repo, mock_rbac_repo, mock_cache_utils):
    """Test SUPER_ADMIN cannot demote the last remaining active Super Admin."""
    operator_id = uuid.uuid4()
    target_id = uuid.uuid4()

    mock_cache_utils.async_cache.get = AsyncMock(side_effect=[
        '{"roles": ["SUPER_ADMIN"], "permissions": []}',  # operator
        '{"roles": ["SUPER_ADMIN"], "permissions": []}',  # target
    ])

    target_user = MagicMock(spec=User)
    target_user.id = target_id
    target_user.username = "last_superadmin"
    mock_auth_repo.get_by_id = AsyncMock(return_value=target_user)

    mock_staff_role = MagicMock(spec=Role)
    mock_staff_role.id = uuid.uuid4()
    mock_staff_role.name = "STAFF_USER"
    mock_rbac_repo.resolve_roles = AsyncMock(return_value=[mock_staff_role])
    mock_rbac_repo.count_active_super_admins = AsyncMock(return_value=1)

    with pytest.raises(ConflictException) as exc_info:
        await rbac_service.assign_roles_to_user(
            operator_id=operator_id,
            user_id=target_id,
            role_identifiers=["STAFF_USER"],
            reason="Attempting to demote last superadmin.",
        )
    assert exc_info.value.error_code == "CANNOT_DEMOTE_LAST_SUPER_ADMIN"


@pytest.mark.asyncio
async def test_super_admin_immutability_refusal(rbac_service, mock_rbac_repo, mock_cache_utils):
    """Test mutating SUPER_ADMIN role permissions is strictly forbidden."""
    operator_id = uuid.uuid4()
    mock_super_role = MagicMock(spec=Role)
    mock_super_role.id = uuid.uuid4()
    mock_super_role.name = "SUPER_ADMIN"
    mock_rbac_repo.get_role_by_identifier = AsyncMock(return_value=mock_super_role)

    with pytest.raises(ForbiddenException) as exc_info:
        await rbac_service.assign_permissions_to_role(
            operator_id=operator_id,
            role_identifier="SUPER_ADMIN",
            permission_identifiers=["PROFILE:USER:READ"],
            reason="Attempting mutation.",
        )
    assert exc_info.value.error_code == "SUPER_ADMIN_IMMUTABLE"


@pytest.mark.asyncio
async def test_assign_roles_success_and_cache_invalidation(
    rbac_service, mock_rbac_repo, mock_auth_repo, mock_cache_utils
):
    """Test SUPER_ADMIN assigning role to STAFF_USER flushes cache immediately."""
    operator_id = uuid.uuid4()
    target_id = uuid.uuid4()

    mock_cache_utils.async_cache.get = AsyncMock(side_effect=[
        '{"roles": ["SUPER_ADMIN"], "permissions": []}',  # operator
        '{"roles": ["PUBLIC_USER"], "permissions": []}',  # target
    ])

    target_user = MagicMock(spec=User)
    target_user.id = target_id
    target_user.username = "targetuser"
    mock_auth_repo.get_by_id = AsyncMock(return_value=target_user)

    mock_role = MagicMock(spec=Role)
    mock_role.id = uuid.uuid4()
    mock_role.name = "STAFF_USER"
    mock_rbac_repo.resolve_roles = AsyncMock(return_value=[mock_role])
    mock_rbac_repo.assign_roles_to_user = AsyncMock(return_value=["STAFF_USER"])

    res = await rbac_service.assign_roles_to_user(
        operator_id=operator_id,
        user_id=target_id,
        role_identifiers=["STAFF_USER"],
        reason="Normal assignment.",
    )
    assert res.status is True
    assert res.assigned_roles == ["STAFF_USER"]
    assert res.requires_approval is False
    mock_rbac_repo.db.commit.assert_awaited_once()
    mock_cache_utils.invalidate_user_permission_cache.assert_awaited_once_with(str(target_id))


@pytest.mark.asyncio
async def test_dual_control_self_approval_refusal(rbac_service, mock_rbac_repo):
    """Test requester cannot self-approve their own change request (CANNOT_SELF_APPROVE)."""
    operator_id = uuid.uuid4()
    request_id = uuid.uuid4()

    mock_req = MagicMock()
    mock_req.id = request_id
    mock_req.requested_by_id = operator_id  # Same user!
    mock_req.status = RBACChangeRequestStatus.PENDING
    mock_rbac_repo.get_change_request_by_id = AsyncMock(return_value=mock_req)

    payload = ReviewChangeRequestPayload(review_notes="Self approval attempt.")

    with pytest.raises(ForbiddenException) as exc_info:
        await rbac_service.review_change_request(
            operator_id=operator_id,
            request_id=request_id,
            payload=payload,
            is_approved=True,
        )
    assert exc_info.value.error_code == "CANNOT_SELF_APPROVE"


@pytest.mark.asyncio
async def test_assign_direct_permissions_grant_ceiling(rbac_service, mock_auth_repo, mock_cache_utils):
    """Test ADMIN cannot grant direct permission they do not possess (GRANT_CEILING_EXCEEDED)."""
    operator_id = uuid.uuid4()
    target_id = uuid.uuid4()

    # Operator only has PROFILE:USER:READ
    mock_cache_utils.async_cache.get = AsyncMock(side_effect=[
        '{"roles": ["ADMIN"], "permissions": ["PROFILE:USER:READ"]}',  # operator
        '{"roles": ["STAFF_USER"], "permissions": []}',  # target
    ])

    target_user = MagicMock(spec=User)
    target_user.id = target_id
    target_user.username = "staffuser"
    mock_auth_repo.get_by_id = AsyncMock(return_value=target_user)

    payload = AssignUserDirectPermissionsPayload(
        permissions=["AUTHENTICATION:USER:CREATE"],  # Operator does not have this!
        is_granted=True,
        reason="Ceiling test.",
    )

    with pytest.raises(ForbiddenException) as exc_info:
        await rbac_service.assign_direct_permissions_to_user(
            operator_id=operator_id,
            user_id=target_id,
            payload=payload,
        )
    assert exc_info.value.error_code == "GRANT_CEILING_EXCEEDED"


@pytest.mark.asyncio
async def test_list_all_users_rbac_summary_with_ids(rbac_service, mock_rbac_repo):
    """Test retrieving enterprise user list with role and permission UUIDs and effective resolution."""
    user_id = uuid.uuid4()
    role_id = uuid.uuid4()
    perm_read_id = uuid.uuid4()
    perm_reject_id = uuid.uuid4()

    mock_perm_read = MagicMock(spec=Permission)
    mock_perm_read.id = perm_read_id
    mock_perm_read.code = SystemPermission.AUTHENTICATION_USER_READ.value

    mock_role = MagicMock(spec=Role)
    mock_role.id = role_id
    mock_role.name = "ADMIN"
    mock_role.permissions = [mock_perm_read]

    mock_perm_revoke = MagicMock(spec=Permission)
    mock_perm_revoke.id = perm_reject_id
    mock_perm_revoke.code = SystemPermission.SESSION_SESSION_REVOKE.value

    mock_direct_up = MagicMock(spec=UserPermission)
    mock_direct_up.permission = mock_perm_revoke
    mock_direct_up.is_granted = True

    mock_user = MagicMock(spec=User)
    mock_user.id = user_id
    mock_user.user_code = "USR-00007"
    mock_user.username = "user7"
    mock_user.email = "user7@ussci.com"
    mock_user.status = "ACTIVE"
    mock_user.roles = [mock_role]
    mock_user.direct_permissions = [mock_direct_up]

    mock_rbac_repo.get_all_users_with_rbac_details = AsyncMock(return_value=[mock_user])

    results = await rbac_service.list_all_users_rbac_summary(role="ADMIN")

    assert len(results) == 1
    u = results[0]
    assert u.user_id == user_id
    assert u.user_code == "USR-00007"
    assert u.username == "user7"
    assert u.highest_rank == 50
    assert len(u.roles) == 1
    assert u.roles[0].id == role_id
    assert u.roles[0].name == "ADMIN"
    assert u.roles[0].rank == 50

    # Direct grants check
    assert len(u.direct_grants) == 1
    assert u.direct_grants[0].id == perm_reject_id
    assert u.direct_grants[0].code == "SESSION:SESSION:REVOKE"

    # Effective permissions check (includes both role perm and direct grant with their IDs)
    effective_codes = [p.code for p in u.permissions]
    assert "AUTHENTICATION:USER:READ" in effective_codes
    assert "SESSION:SESSION:REVOKE" in effective_codes
    read_item = next(p for p in u.permissions if p.code == "AUTHENTICATION:USER:READ")
    assert read_item.id == perm_read_id


@pytest.mark.asyncio
async def test_list_pending_change_requests_success(rbac_service, mock_rbac_repo):
    """Test listing pending dual-control change requests."""
    operator_id = uuid.uuid4()
    req_id = uuid.uuid4()

    mock_req = MagicMock(spec=RBACChangeRequest)
    mock_req.id = req_id
    mock_req.request_type = "ROLE_ASSIGNMENT"
    mock_req.target_user_id = uuid.uuid4()
    mock_req.target_role_id = None
    mock_req.requested_payload = '{"roles": ["STAFF_USER"]}'
    mock_req.status = RBACChangeRequestStatus.PENDING
    mock_req.reason = "Promotion request"
    mock_req.requested_by_id = uuid.uuid4()
    mock_req.reviewed_by_id = None
    mock_req.review_notes = None
    mock_req.created_at = datetime.now(timezone.utc)
    mock_req.reviewed_at = None

    mock_rbac_repo.get_pending_change_requests = AsyncMock(return_value=[mock_req])

    results = await rbac_service.list_pending_change_requests(operator_id=operator_id)
    assert len(results) == 1
    assert results[0].id == req_id
    assert results[0].status == "PENDING"
    assert results[0].request_type == "ROLE_ASSIGNMENT"


@pytest.mark.asyncio
async def test_reject_change_request_success(rbac_service, mock_rbac_repo, mock_cache_utils):
    """Test higher-rank authority rejecting an RBAC change request."""
    reviewer_id = uuid.uuid4()
    requester_id = uuid.uuid4()
    request_id = uuid.uuid4()

    mock_cache_utils.async_cache.get = AsyncMock(side_effect=[
        '{"roles": ["SUPER_ADMIN"], "permissions": []}',  # Reviewer (rank 100)
        '{"roles": ["ADMIN"], "permissions": []}',        # Requester (rank 50)
    ])

    mock_req = MagicMock(spec=RBACChangeRequest)
    mock_req.id = request_id
    mock_req.request_type = "ROLE_ASSIGNMENT"
    mock_req.target_user_id = uuid.uuid4()
    mock_req.target_role_id = None
    mock_req.requested_payload = '{"roles": ["STAFF_USER"]}'
    mock_req.status = RBACChangeRequestStatus.PENDING
    mock_req.reason = "Promotion request"
    mock_req.requested_by_id = requester_id
    mock_req.reviewed_by_id = None
    mock_req.review_notes = None
    mock_req.created_at = datetime.now(timezone.utc)
    mock_req.reviewed_at = None

    mock_rbac_repo.get_change_request_by_id = AsyncMock(return_value=mock_req)

    payload = ReviewChangeRequestPayload(review_notes="Elevation denied after review.")
    res = await rbac_service.review_change_request(
        operator_id=reviewer_id,
        request_id=request_id,
        payload=payload,
        is_approved=False,
    )

    assert res.id == request_id
    assert res.status == "REJECTED"
    assert mock_req.status == RBACChangeRequestStatus.REJECTED
    assert mock_req.reviewed_by_id == reviewer_id
    assert mock_req.review_notes == "Elevation denied after review."
    mock_rbac_repo.db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_role_permission_history_success(rbac_service, mock_rbac_repo):
    """Test retrieving role permission history returns formatted snapshots."""
    role_id = uuid.uuid4()
    operator_id = uuid.uuid4()
    snapshot_id = uuid.uuid4()
    perm_id = uuid.uuid4()

    mock_role = MagicMock(spec=Role)
    mock_role.id = role_id
    mock_role.name = "STAFF_USER"
    mock_rbac_repo.get_role_by_identifier = AsyncMock(return_value=mock_role)

    mock_operator = MagicMock(spec=User)
    mock_operator.id = operator_id
    mock_operator.username = "super_admin"

    mock_snapshot = MagicMock()
    mock_snapshot.id = snapshot_id
    mock_snapshot.role_id = role_id
    mock_snapshot.role = mock_role
    mock_snapshot.created_at = datetime(2026, 10, 10, 14, 0, 0, tzinfo=timezone.utc)
    mock_snapshot.permissions_payload = [{"id": str(perm_id), "code": "AUTHENTICATION:USER:READ"}]
    mock_snapshot.changed_by = mock_operator
    mock_snapshot.changed_by_id = operator_id
    mock_snapshot.reason = "Quarterly audit update"

    mock_rbac_repo.get_role_permission_history = AsyncMock(return_value=[mock_snapshot])

    results = await rbac_service.get_role_permission_history("STAFF_USER")

    assert len(results) == 1
    item = results[0]
    assert item.snapshot_id == snapshot_id
    assert item.role_id == role_id
    assert item.role_name == "STAFF_USER"
    assert item.total_permissions == 1
    assert len(item.permissions) == 1
    assert item.permissions[0].id == perm_id
    assert item.permissions[0].code == "AUTHENTICATION:USER:READ"
    assert item.updated_by.user_id == operator_id
    assert item.updated_by.username == "super_admin"
    assert item.reason == "Quarterly audit update"


@pytest.mark.asyncio
async def test_get_role_permission_history_not_found(rbac_service, mock_rbac_repo):
    """Test retrieving history for non-existent role raises NotFoundException."""
    mock_rbac_repo.get_role_by_identifier = AsyncMock(return_value=None)
    with pytest.raises(NotFoundException):
        await rbac_service.get_role_permission_history("UNKNOWN_ROLE")


@pytest.mark.asyncio
async def test_get_all_roles_permission_history_all(rbac_service, mock_rbac_repo):
    """Test retrieving history across all roles without role filter."""
    role_id_1 = uuid.uuid4()
    role_id_2 = uuid.uuid4()
    snap_id_1 = uuid.uuid4()
    snap_id_2 = uuid.uuid4()
    perm_id = uuid.uuid4()

    mock_role_1 = MagicMock(spec=Role)
    mock_role_1.id = role_id_1
    mock_role_1.name = "ADMIN"

    mock_role_2 = MagicMock(spec=Role)
    mock_role_2.id = role_id_2
    mock_role_2.name = "STAFF_USER"

    mock_snap_1 = MagicMock()
    mock_snap_1.id = snap_id_1
    mock_snap_1.role_id = role_id_1
    mock_snap_1.role = mock_role_1
    mock_snap_1.created_at = datetime(2026, 10, 11, 10, 0, 0, tzinfo=timezone.utc)
    mock_snap_1.permissions_payload = [{"id": str(perm_id), "code": "PROFILE:USER:READ"}]
    mock_snap_1.changed_by = None
    mock_snap_1.changed_by_id = None
    mock_snap_1.reason = "System startup sync"

    mock_snap_2 = MagicMock()
    mock_snap_2.id = snap_id_2
    mock_snap_2.role_id = role_id_2
    mock_snap_2.role = mock_role_2
    mock_snap_2.created_at = datetime(2026, 10, 11, 9, 0, 0, tzinfo=timezone.utc)
    mock_snap_2.permissions_payload = []
    mock_snap_2.changed_by = None
    mock_snap_2.changed_by_id = None
    mock_snap_2.reason = "Default init"

    mock_rbac_repo.get_role_permission_history = AsyncMock(return_value=[mock_snap_1, mock_snap_2])

    results = await rbac_service.get_all_roles_permission_history()

    mock_rbac_repo.get_role_permission_history.assert_awaited_once_with(
        role_id=None,
        from_date=None,
        to_date=None,
        limit=50,
        offset=0,
    )
    assert len(results) == 2
    assert results[0].role_name == "ADMIN"
    assert results[0].updated_by.username == "SYSTEM"
    assert results[1].role_name == "STAFF_USER"


@pytest.mark.asyncio
async def test_get_all_roles_permission_history_filtered(rbac_service, mock_rbac_repo):
    """Test retrieving history across all roles with role filter."""
    role_id = uuid.uuid4()
    mock_role = MagicMock(spec=Role)
    mock_role.id = role_id
    mock_role.name = "ADMIN"
    mock_rbac_repo.get_role_by_identifier = AsyncMock(return_value=mock_role)
    mock_rbac_repo.get_role_permission_history = AsyncMock(return_value=[])

    results = await rbac_service.get_all_roles_permission_history(role_identifier="ADMIN")

    mock_rbac_repo.get_role_permission_history.assert_awaited_once_with(
        role_id=role_id,
        from_date=None,
        to_date=None,
        limit=50,
        offset=0,
    )
    assert results == []


@pytest.mark.asyncio
async def test_get_user_rbac_history_success(rbac_service, mock_rbac_repo, mock_auth_repo):
    """Test retrieving user RBAC history returns formatted timeline snapshots."""
    user_id = uuid.uuid4()
    operator_id = uuid.uuid4()
    snapshot_id = uuid.uuid4()
    role_id = uuid.uuid4()
    perm_id_1 = uuid.uuid4()
    perm_id_2 = uuid.uuid4()

    mock_user = MagicMock(spec=User)
    mock_user.id = user_id
    mock_user.username = "john_doe"
    mock_auth_repo.get_by_id = AsyncMock(return_value=mock_user)

    mock_operator = MagicMock(spec=User)
    mock_operator.id = operator_id
    mock_operator.username = "super_admin"

    mock_snapshot = MagicMock()
    mock_snapshot.id = snapshot_id
    mock_snapshot.user_id = user_id
    mock_snapshot.user = mock_user
    mock_snapshot.created_at = datetime(2026, 10, 10, 14, 30, 0, tzinfo=timezone.utc)
    mock_snapshot.roles_payload = [{"id": str(role_id), "name": "STAFF_USER", "rank": 10}]
    mock_snapshot.direct_permissions_payload = [
        {"id": str(perm_id_1), "code": "INVENTORY:ITEM:CREATE", "is_granted": True}
    ]
    mock_snapshot.effective_permissions_payload = [
        {"id": str(perm_id_2), "code": "AUTHENTICATION:USER:READ"},
        {"id": str(perm_id_1), "code": "INVENTORY:ITEM:CREATE"},
    ]
    mock_snapshot.changed_by = mock_operator
    mock_snapshot.changed_by_id = operator_id
    mock_snapshot.reason = "Promoted to inventory coordinator"

    mock_rbac_repo.get_user_rbac_history = AsyncMock(return_value=[mock_snapshot])

    results = await rbac_service.get_user_rbac_history(user_id)

    assert len(results) == 1
    item = results[0]
    assert item.snapshot_id == snapshot_id
    assert item.user_id == user_id
    assert item.username == "john_doe"
    assert len(item.roles) == 1
    assert item.roles[0].name == "STAFF_USER"
    assert len(item.direct_permissions) == 1
    assert item.direct_permissions[0].code == "INVENTORY:ITEM:CREATE"
    assert item.total_permissions == 2
    assert len(item.effective_permissions) == 2
    assert item.updated_by.user_id == operator_id
    assert item.updated_by.username == "super_admin"
    assert item.reason == "Promoted to inventory coordinator"


@pytest.mark.asyncio
async def test_get_user_rbac_history_not_found(rbac_service, mock_auth_repo):
    """Test retrieving history for non-existent user raises NotFoundException."""
    mock_auth_repo.get_by_id = AsyncMock(return_value=None)
    with pytest.raises(NotFoundException):
        await rbac_service.get_user_rbac_history(uuid.uuid4())


@pytest.mark.asyncio
async def test_capture_user_rbac_snapshot_full_flow(rbac_service, mock_rbac_repo):
    """Test _capture_user_rbac_snapshot correctly calculates effective set and calls repository."""
    user_id = uuid.uuid4()
    operator_id = uuid.uuid4()
    role_id = uuid.uuid4()
    perm_read_id = uuid.uuid4()
    perm_create_id = uuid.uuid4()

    mock_role = MagicMock(spec=Role)
    mock_role.id = role_id
    mock_role.name = "STAFF_USER"
    mock_perm_read = MagicMock(spec=Permission)
    mock_perm_read.id = perm_read_id
    mock_perm_read.code = SystemPermission.AUTHENTICATION_USER_READ.value
    mock_role.permissions = [mock_perm_read]

    mock_perm_create = MagicMock(spec=Permission)
    mock_perm_create.id = perm_create_id
    mock_perm_create.code = SystemPermission.AUTHENTICATION_USER_CREATE.value

    mock_up = MagicMock(spec=UserPermission)
    mock_up.permission = mock_perm_create
    mock_up.is_granted = True

    mock_user = MagicMock(spec=User)
    mock_user.id = user_id
    mock_user.roles = [mock_role]
    mock_user.direct_permissions = [mock_up]

    mock_rbac_repo.get_user_with_rbac_details = AsyncMock(return_value=mock_user)

    await rbac_service._capture_user_rbac_snapshot(
        user_id=user_id,
        changed_by_id=operator_id,
        reason="Testing snapshot capture",
    )

    mock_rbac_repo.create_user_rbac_snapshot.assert_awaited_once()
    kwargs = mock_rbac_repo.create_user_rbac_snapshot.call_args.kwargs
    assert kwargs["user_id"] == user_id
    assert kwargs["changed_by_id"] == operator_id
    assert kwargs["reason"] == "Testing snapshot capture"
    assert len(kwargs["roles_payload"]) == 1
    assert kwargs["roles_payload"][0]["name"] == "STAFF_USER"
    assert len(kwargs["direct_permissions_payload"]) == 1
    assert len(kwargs["effective_permissions_payload"]) == 2


@pytest.mark.asyncio
async def test_get_role_permission_history_system_snapshot(rbac_service, mock_rbac_repo):
    """Test role history gracefully formats system-originated snapshots with changed_by=None."""
    role_id = uuid.uuid4()
    snapshot_id = uuid.uuid4()
    perm_id = uuid.uuid4()

    mock_role = MagicMock(spec=Role)
    mock_role.id = role_id
    mock_role.name = "ADMIN"
    mock_rbac_repo.get_role_by_identifier = AsyncMock(return_value=mock_role)

    mock_snapshot = MagicMock()
    mock_snapshot.id = snapshot_id
    mock_snapshot.role_id = role_id
    mock_snapshot.role = mock_role
    mock_snapshot.created_at = datetime(2026, 10, 11, 8, 0, 0, tzinfo=timezone.utc)
    mock_snapshot.permissions_payload = [{"id": str(perm_id), "code": "AUTHENTICATION:USER:READ"}]
    mock_snapshot.changed_by = None
    mock_snapshot.changed_by_id = None
    mock_snapshot.reason = "System startup enum synchronization: linked 1 default permission(s)"

    mock_rbac_repo.get_role_permission_history = AsyncMock(return_value=[mock_snapshot])

    results = await rbac_service.get_role_permission_history("ADMIN")

    assert len(results) == 1
    item = results[0]
    assert item.updated_by.user_id is None
    assert item.updated_by.username == "SYSTEM"
    assert item.reason == "System startup enum synchronization: linked 1 default permission(s)"


@pytest.mark.asyncio
async def test_get_user_rbac_history_system_snapshot(rbac_service, mock_rbac_repo, mock_auth_repo):
    """Test user history gracefully formats system-originated snapshots with changed_by=None."""
    user_id = uuid.uuid4()
    snapshot_id = uuid.uuid4()
    role_id = uuid.uuid4()

    mock_user = MagicMock(spec=User)
    mock_user.id = user_id
    mock_user.username = "test_user"
    mock_auth_repo.get_by_id = AsyncMock(return_value=mock_user)

    mock_snapshot = MagicMock()
    mock_snapshot.id = snapshot_id
    mock_snapshot.user_id = user_id
    mock_snapshot.user = mock_user
    mock_snapshot.created_at = datetime(2026, 10, 11, 8, 0, 0, tzinfo=timezone.utc)
    mock_snapshot.roles_payload = [{"id": str(role_id), "name": "PUBLIC_USER", "rank": 0}]
    mock_snapshot.direct_permissions_payload = []
    mock_snapshot.effective_permissions_payload = []
    mock_snapshot.changed_by = None
    mock_snapshot.changed_by_id = None
    mock_snapshot.reason = "System startup lifespan pruning: detached obsolete role(s)"

    mock_rbac_repo.get_user_rbac_history = AsyncMock(return_value=[mock_snapshot])

    results = await rbac_service.get_user_rbac_history(user_id)

    assert len(results) == 1
    item = results[0]
    assert item.updated_by.user_id is None
    assert item.updated_by.username == "SYSTEM"
    assert item.reason == "System startup lifespan pruning: detached obsolete role(s)"


@pytest.mark.asyncio
async def test_rollback_role_permissions_success(rbac_service, mock_rbac_repo, mock_cache_utils):
    """Test successful rollback of role permissions to a historical snapshot."""
    role_id = uuid.uuid4()
    operator_id = uuid.uuid4()
    snapshot_id = uuid.uuid4()
    perm_id = uuid.uuid4()

    mock_role = MagicMock(spec=Role)
    mock_role.id = role_id
    mock_role.name = "STAFF_USER"
    mock_rbac_repo.get_role_by_identifier = AsyncMock(return_value=mock_role)

    mock_snapshot = MagicMock()
    mock_snapshot.id = snapshot_id
    mock_snapshot.role_id = role_id
    mock_snapshot.created_at = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)
    mock_snapshot.permissions_payload = [{"id": str(perm_id), "code": "PROFILE:USER:READ"}]
    mock_rbac_repo.get_role_permission_snapshot_by_id = AsyncMock(return_value=mock_snapshot)

    mock_perm = MagicMock(spec=Permission)
    mock_perm.id = perm_id
    mock_perm.code = "PROFILE:USER:READ"
    mock_rbac_repo.resolve_permissions = AsyncMock(return_value=[mock_perm])
    mock_rbac_repo.assign_permissions_to_role = AsyncMock(return_value=["PROFILE:USER:READ"])
    mock_rbac_repo.get_user_ids_by_role = AsyncMock(return_value=[uuid.uuid4()])

    # Mock operator permissions (SUPER_ADMIN)
    operator_payload = MagicMock()
    operator_payload.roles = ["SUPER_ADMIN"]
    operator_payload.permissions = ["PROFILE:USER:READ"]
    rbac_service.get_or_cache_user_permissions = AsyncMock(return_value=operator_payload)
    rbac_service.invalidate_user_permissions = AsyncMock()

    res = await rbac_service.rollback_role_permissions(
        operator_id=operator_id,
        role_identifier="STAFF_USER",
        snapshot_id=snapshot_id,
        reason="Incident recovery",
    )

    assert res.status is True
    assert res.role_name == "STAFF_USER"
    assert res.restored_from_snapshot_id == snapshot_id
    assert res.restored_permissions == ["PROFILE:USER:READ"]
    assert res.total_permissions == 1
    mock_rbac_repo.assign_permissions_to_role.assert_awaited_once_with(role_id, [perm_id])
    mock_rbac_repo.create_role_permission_snapshot.assert_awaited_once()
    mock_rbac_repo.db.commit.assert_awaited_once()
    rbac_service.invalidate_user_permissions.assert_awaited_once()


@pytest.mark.asyncio
async def test_rollback_role_permissions_super_admin_refusal(rbac_service, mock_rbac_repo):
    """Test immutability check refuses rollback on SUPER_ADMIN role."""
    role_id = uuid.uuid4()
    operator_id = uuid.uuid4()
    snapshot_id = uuid.uuid4()

    mock_role = MagicMock(spec=Role)
    mock_role.id = role_id
    mock_role.name = "SUPER_ADMIN"
    mock_rbac_repo.get_role_by_identifier = AsyncMock(return_value=mock_role)

    with pytest.raises(ForbiddenException):
        await rbac_service.rollback_role_permissions(
            operator_id=operator_id,
            role_identifier="SUPER_ADMIN",
            snapshot_id=snapshot_id,
            reason="Illegal attempt",
        )


@pytest.mark.asyncio
async def test_rollback_role_permissions_mismatch(rbac_service, mock_rbac_repo):
    """Test error raised when snapshot role_id does not match target role."""
    role_id = uuid.uuid4()
    operator_id = uuid.uuid4()
    snapshot_id = uuid.uuid4()

    mock_role = MagicMock(spec=Role)
    mock_role.id = role_id
    mock_role.name = "STAFF_USER"
    mock_rbac_repo.get_role_by_identifier = AsyncMock(return_value=mock_role)

    operator_payload = MagicMock()
    operator_payload.roles = ["SUPER_ADMIN"]
    rbac_service.get_or_cache_user_permissions = AsyncMock(return_value=operator_payload)

    # Snapshot belongs to a different role
    mock_snapshot = MagicMock()
    mock_snapshot.id = snapshot_id
    mock_snapshot.role_id = uuid.uuid4()
    mock_rbac_repo.get_role_permission_snapshot_by_id = AsyncMock(return_value=mock_snapshot)

    with pytest.raises(BadRequestException):
        await rbac_service.rollback_role_permissions(
            operator_id=operator_id,
            role_identifier="STAFF_USER",
            snapshot_id=snapshot_id,
            reason="Mismatch test",
        )


@pytest.mark.asyncio
async def test_rollback_user_rbac_success(
    rbac_service, mock_rbac_repo, mock_auth_repo, mock_session_repo
):
    """Test successful rollback of a user's roles and direct permissions to a snapshot."""
    operator_id = uuid.uuid4()
    target_user_id = uuid.uuid4()
    snapshot_id = uuid.uuid4()
    role_id = uuid.uuid4()
    perm_id = uuid.uuid4()

    mock_user = MagicMock(spec=User)
    mock_user.id = target_user_id
    mock_user.username = "target_emp"
    mock_auth_repo.get_by_id = AsyncMock(return_value=mock_user)

    operator_payload = MagicMock()
    operator_payload.roles = ["SUPER_ADMIN"]
    operator_payload.permissions = ["PROFILE:USER:READ"]

    target_payload = MagicMock()
    target_payload.roles = ["ADMIN"]  # Rank 50
    target_payload.permissions = []

    async def mock_get_perms(uid):
        if uid == operator_id:
            return operator_payload
        return target_payload

    rbac_service.get_or_cache_user_permissions = AsyncMock(side_effect=mock_get_perms)
    rbac_service.invalidate_user_permissions = AsyncMock()
    rbac_service._capture_user_rbac_snapshot = AsyncMock()

    mock_snapshot = MagicMock()
    mock_snapshot.id = snapshot_id
    mock_snapshot.user_id = target_user_id
    mock_snapshot.created_at = datetime(2026, 10, 10, 10, 0, 0, tzinfo=timezone.utc)
    mock_snapshot.roles_payload = [{"id": str(role_id), "name": "STAFF_USER", "rank": 10}]
    mock_snapshot.direct_permissions_payload = [
        {"id": str(perm_id), "code": "PROFILE:USER:READ", "is_granted": True}
    ]
    mock_rbac_repo.get_user_rbac_snapshot_by_id = AsyncMock(return_value=mock_snapshot)

    mock_role = MagicMock(spec=Role)
    mock_role.id = role_id
    mock_role.name = "STAFF_USER"
    mock_rbac_repo.resolve_roles = AsyncMock(return_value=[mock_role])
    mock_rbac_repo.assign_roles_to_user = AsyncMock(return_value=["STAFF_USER"])

    mock_perm = MagicMock(spec=Permission)
    mock_perm.id = perm_id
    mock_perm.code = "PROFILE:USER:READ"
    mock_rbac_repo.resolve_permissions = AsyncMock(return_value=[mock_perm])
    mock_rbac_repo.get_user_roles_and_permissions = AsyncMock(
        return_value={"roles": ["STAFF_USER"], "permissions": ["PROFILE:USER:READ"]}
    )

    res = await rbac_service.rollback_user_rbac(
        operator_id=operator_id,
        user_id=target_user_id,
        snapshot_id=snapshot_id,
        reason="Security rollback to last safe state",
    )

    assert res.status is True
    assert res.user_id == target_user_id
    assert res.username == "target_emp"
    assert res.restored_from_snapshot_id == snapshot_id
    assert res.restored_roles == ["STAFF_USER"]
    assert len(res.restored_direct_permissions) == 1
    assert res.restored_direct_permissions[0].code == "PROFILE:USER:READ"
    assert res.restored_direct_permissions[0].is_granted is True
    # Demotion occurred (from ADMIN rank 50 to STAFF_USER rank 10), so session was deactivated
    mock_session_repo.deactivate_all_active_by_user_id.assert_awaited_once_with(target_user_id)
    mock_rbac_repo.db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_rollback_user_rbac_self_mutation_refusal(rbac_service):
    """Test refusal when operator attempts to roll back their own RBAC state."""
    same_id = uuid.uuid4()
    with pytest.raises(ForbiddenException):
        await rbac_service.rollback_user_rbac(
            operator_id=same_id,
            user_id=same_id,
            snapshot_id=uuid.uuid4(),
            reason="Self modification forbidden",
        )


@pytest.mark.asyncio
async def test_rollback_user_rbac_last_super_admin_lockout(
    rbac_service, mock_rbac_repo, mock_auth_repo
):
    """Test lockout protection prevents demoting the last active Super Admin via rollback."""
    operator_id = uuid.uuid4()
    target_user_id = uuid.uuid4()
    snapshot_id = uuid.uuid4()

    mock_user = MagicMock(spec=User)
    mock_user.id = target_user_id
    mock_user.username = "last_super_admin"
    mock_auth_repo.get_by_id = AsyncMock(return_value=mock_user)

    operator_payload = MagicMock()
    operator_payload.roles = ["SUPER_ADMIN"]

    target_payload = MagicMock()
    target_payload.roles = ["SUPER_ADMIN"]  # Currently is super admin

    async def mock_get_perms(uid):
        if uid == operator_id:
            return operator_payload
        return target_payload

    rbac_service.get_or_cache_user_permissions = AsyncMock(side_effect=mock_get_perms)

    # Snapshot does not have SUPER_ADMIN
    mock_snapshot = MagicMock()
    mock_snapshot.id = snapshot_id
    mock_snapshot.user_id = target_user_id
    mock_snapshot.roles_payload = [{"id": str(uuid.uuid4()), "name": "ADMIN", "rank": 50}]
    mock_snapshot.direct_permissions_payload = []
    mock_rbac_repo.get_user_rbac_snapshot_by_id = AsyncMock(return_value=mock_snapshot)
    mock_rbac_repo.count_active_super_admins = AsyncMock(return_value=1)  # Only 1 left!

    with pytest.raises(ConflictException):
        await rbac_service.rollback_user_rbac(
            operator_id=operator_id,
            user_id=target_user_id,
            snapshot_id=snapshot_id,
            reason="Attempted lockout",
        )



