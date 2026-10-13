from datetime import datetime
from typing import List, Optional
from uuid import UUID

from dependencies.current_user import require_user_profile_and_get_id
from dependencies.rbac_guard import require_role
from fastapi import APIRouter, Depends, Query, status
from modules.rbac.rbac_schema import (
    AssignRolePermissionsPayload,
    AssignUserDirectPermissionsPayload,
    AssignUserRolesPayload,
    BatchRolePermissionAssignmentPayload,
    BatchRolePermissionAssignmentResponse,
    DemoteUserRolePayload,
    DemoteUserRoleResponse,
    RBACChangeRequestResponse,
    RBACConfigResponse,
    RemoveUserDirectPermissionsPayload,
    ReviewChangeRequestPayload,
    RolePermissionAssignmentResponse,
    RoleRollbackPayload,
    RoleRollbackResponse,
    RoleSnapshotHistoryResponse,
    UserDirectPermissionsResponse,
    UserRBACListItemResponse,
    UserRBACSummaryResponse,
    UserRoleAssignmentResponse,
    UserRollbackPayload,
    UserRollbackResponse,
    UserSnapshotHistoryResponse,
)
from modules.rbac.rbac_service import RBACService
from shares.enums import RoleName

router = APIRouter(
    prefix="/api/private/admin/rbac", 
    tags=["RBAC Administration"],
    dependencies=[Depends(require_user_profile_and_get_id)],
)


@router.get(
    "/test-guarded-access",
    summary="Probe endpoint guarded by ADMIN/SUPER_ADMIN for immediate revocation testing.",
    status_code=status.HTTP_200_OK,
)
async def test_guarded_access(
    caller_id: UUID = Depends(require_role(RoleName.SUPER_ADMIN, RoleName.ADMIN)),
) -> dict:
    """
    Immediate Revocation Challenge Probe:
    Returns 200 OK if caller has active administrative privileges.
    Returns 403 Forbidden immediately upon demotion or cache invalidation.
    """
    return {
        "status": True,
        "message": "Access granted: Caller possesses required administrative privileges.",
        "user_id": str(caller_id),
    }


@router.get(
    "/configuration",
    summary="Get unified RBAC hierarchy and active system roles with permissions.",
    status_code=status.HTTP_200_OK,
    response_model=RBACConfigResponse,
    dependencies=[Depends(require_role(RoleName.SUPER_ADMIN, RoleName.ADMIN))],
)
async def get_rbac_configuration(
    service: RBACService = Depends(),
) -> RBACConfigResponse:
    """
    Returns the complete system RBAC structure:
    - Hierarchical Module -> Resource -> Action tree directly from code enums.
    - All active database roles and their assigned permission codes.
    """
    return await service.get_rbac_configuration()


@router.get(
    "/users-role-perms",
    summary="List all users and their assigned roles and permissions (Admin only).",
    status_code=status.HTTP_200_OK,
    response_model=List[UserRBACListItemResponse],
    dependencies=[Depends(require_role(RoleName.SUPER_ADMIN, RoleName.ADMIN))],
)
async def list_all_users_rbac_summary(
    role: Optional[str] = Query(None, description="Filter by role name or UUID"),
    search: Optional[str] = Query(None, description="Search by username, user code, or email"),
    status: Optional[str] = Query(None, description="Filter by account status (e.g. ACTIVE, PENDING)"),
    service: RBACService = Depends(),
) -> List[UserRBACListItemResponse]:
    """Retrieve enterprise-wide list of users with assigned roles, direct overrides, and effective permissions."""
    return await service.list_all_users_rbac_summary(
        role=role,
        search=search,
        status_filter=status,
    )


@router.get(
    "/users/{user_id}/role-perms-summary",
    summary="Retrieve user's assigned roles, direct overrides, and resolved permissions.",
    status_code=status.HTTP_200_OK,
    response_model=UserRBACSummaryResponse,
    dependencies=[Depends(require_role(RoleName.SUPER_ADMIN, RoleName.ADMIN))],
)
async def get_user_rbac_summary(
    user_id: UUID,
    service: RBACService = Depends(),
) -> UserRBACSummaryResponse:
    """Retrieve user identity details, assigned roles, direct overrides, and effective permissions."""
    return await service.get_user_rbac_summary(user_id=user_id)


@router.get(
    "/users/{user_id}/snapshot-histories",
    summary="Get point-in-time RBAC snapshot history for a user.",
    status_code=status.HTTP_200_OK,
    response_model=List[UserSnapshotHistoryResponse],
    dependencies=[Depends(require_role(RoleName.SUPER_ADMIN, RoleName.ADMIN))],
)
async def get_user_rbac_history(
    user_id: UUID,
    from_date: Optional[datetime] = Query(None, alias="fromDate", description="Filter history from date"),
    to_date: Optional[datetime] = Query(None, alias="toDate", description="Filter history to date"),
    limit: int = Query(50, ge=1, le=100, description="Max snapshots to retrieve"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    service: RBACService = Depends(),
) -> List[UserSnapshotHistoryResponse]:
    """Retrieve chronological point-in-time snapshots of user roles, direct permissions, and effective permissions."""
    return await service.get_user_rbac_history(
        user_id=user_id,
        from_date=from_date,
        to_date=to_date,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/users/{user_id}/rollback-snapshot",
    summary="Rollback user RBAC state to a selected point-in-time snapshot.",
    status_code=status.HTTP_200_OK,
    response_model=UserRollbackResponse,
)
async def rollback_user_rbac(
    user_id: UUID,
    payload: UserRollbackPayload,
    operator_id: UUID = Depends(require_role(RoleName.SUPER_ADMIN, RoleName.ADMIN)),
    service: RBACService = Depends(),
) -> UserRollbackResponse:
    """Restores user roles and direct permissions to a historical snapshot and invalidates caches/sessions."""
    return await service.rollback_user_rbac(
        operator_id=operator_id,
        user_id=user_id,
        snapshot_id=payload.snapshot_id,
        reason=payload.reason,
    )


@router.post(
    "/users/{user_id}/assign-roles",
    summary="Additively assign roles to a specific user and invalidate permission cache.",
    status_code=status.HTTP_200_OK,
    response_model=UserRoleAssignmentResponse,
)
async def assign_user_roles(
    user_id: UUID,
    payload: AssignUserRolesPayload,
    operator_id: UUID = Depends(require_role(RoleName.SUPER_ADMIN, RoleName.ADMIN)),
    service: RBACService = Depends(),
) -> UserRoleAssignmentResponse:
    """
    Additively compounds assigned roles for a target user with strict governance refusals:
    - Rejects self-mutation
    - Rejects assignment at/above operator rank
    - Non-super-admin privilege elevations queue for dual-authorization approval
    - Automatically combines default permissions of newly assigned roles with existing roles
    - Immediately invalidates Redis permissions cache
    """
    return await service.assign_roles_to_user(
        operator_id=operator_id,
        user_id=user_id,
        role_identifiers=payload.roles,
        reason=payload.reason,
    )


@router.post(
    "/users/{user_id}/demote-roles",
    summary="Demote user roles and immediately terminate active sessions.",
    status_code=status.HTTP_200_OK,
    response_model=DemoteUserRoleResponse,
)
async def demote_user_roles(
    user_id: UUID,
    payload: DemoteUserRolePayload,
    operator_id: UUID = Depends(require_role(RoleName.SUPER_ADMIN, RoleName.ADMIN)),
    service: RBACService = Depends(),
) -> DemoteUserRoleResponse:
    """
    Explicitly demotes a user by removing specified roles with zero-trust enforcement:
    - Rejects self-mutation (operators cannot demote themselves)
    - Rejects demoting users with equal or higher rank
    - Rejects removing roles at or above operator rank
    - Rejects removing unassigned roles or leaving user with zero roles
    - Rejects demotion of the last active Super Admin
    - Flushes Redis permissions cache and terminates active user sessions immediately
    """
    return await service.demote_user_role(
        operator_id=operator_id,
        user_id=user_id,
        roles_to_remove=payload.roles_to_remove,
        reason=payload.reason,
    )


@router.post(
    "/users/{user_id}/assign-direct-permissions",
    summary="Grant or explicitly deny custom direct permissions for a user.",
    status_code=status.HTTP_200_OK,
    response_model=UserDirectPermissionsResponse,
)
async def assign_user_direct_permissions(
    user_id: UUID,
    payload: AssignUserDirectPermissionsPayload,
    operator_id: UUID = Depends(require_role(RoleName.SUPER_ADMIN, RoleName.ADMIN)),
    service: RBACService = Depends(),
) -> UserDirectPermissionsResponse:
    """Grants or denies direct custom permissions, enforcing grant ceiling and rank boundaries."""
    return await service.assign_direct_permissions_to_user(
        operator_id=operator_id,
        user_id=user_id,
        payload=payload,
    )


@router.post(
    "/users/{user_id}/revoke-direct-permissions",
    summary="Remove direct permission overrides from a user.",
    status_code=status.HTTP_200_OK,
    response_model=UserDirectPermissionsResponse,
)
async def remove_user_direct_permissions(
    user_id: UUID,
    payload: RemoveUserDirectPermissionsPayload,
    operator_id: UUID = Depends(require_role(RoleName.SUPER_ADMIN, RoleName.ADMIN)),
    service: RBACService = Depends(),
) -> UserDirectPermissionsResponse:
    """Removes direct permission overrides for a user and invalidates cache."""
    return await service.remove_direct_permissions_from_user(
        operator_id=operator_id,
        user_id=user_id,
        permissions=payload.permissions,
        reason=payload.reason,
    )


@router.put(
    "/roles/{role_identifier}/assign-permissions",
    summary="Assign / update permissions for a role and invalidate affected user caches.",
    status_code=status.HTTP_200_OK,
    response_model=RolePermissionAssignmentResponse,
)
async def assign_role_permissions(
    role_identifier: str,
    payload: AssignRolePermissionsPayload,
    operator_id: UUID = Depends(require_role(RoleName.SUPER_ADMIN, RoleName.ADMIN)),
    service: RBACService = Depends(),
) -> RolePermissionAssignmentResponse:
    """
    Replaces permissions for a role:
    - Super Admin permissions are immutable
    - Operator cannot edit role with rank >= own rank
    - Operator cannot grant permissions they do not hold
    - Post-commit cache invalidation for all affected users
    """
    return await service.assign_permissions_to_role(
        operator_id=operator_id,
        role_identifier=role_identifier,
        permission_identifiers=payload.permissions,
        reason=payload.reason,
    )


@router.post(
    "/roles/batch-assign-permissions",
    summary="Batch update permissions across multiple roles in a single operation.",
    status_code=status.HTTP_200_OK,
    response_model=BatchRolePermissionAssignmentResponse,
)
async def batch_assign_role_permissions(
    payload: BatchRolePermissionAssignmentPayload,
    operator_id: UUID = Depends(require_role(RoleName.SUPER_ADMIN, RoleName.ADMIN)),
    service: RBACService = Depends(),
) -> BatchRolePermissionAssignmentResponse:
    """Atomically updates permissions for multiple roles with governance refusal validation."""
    return await service.batch_assign_role_permissions(
        operator_id=operator_id,
        payload=payload,
    )


@router.post(
    "/roles/{role_identifier}/reset-default-permissions",
    summary="Reset a role's permissions back to its code-defined default preset.",
    status_code=status.HTTP_200_OK,
    response_model=RolePermissionAssignmentResponse,
)
async def reset_role_to_defaults(
    role_identifier: str,
    operator_id: UUID = Depends(require_role(RoleName.SUPER_ADMIN, RoleName.ADMIN)),
    service: RBACService = Depends(),
) -> RolePermissionAssignmentResponse:
    """Reverts a system role's permissions to its default preset defined in enums.py."""
    return await service.reset_role_to_defaults(
        operator_id=operator_id,
        role_identifier=role_identifier,
    )


@router.get(
    "/roles/snapshot-histories",
    summary="Get point-in-time permission snapshot history across all roles.",
    status_code=status.HTTP_200_OK,
    response_model=List[RoleSnapshotHistoryResponse],
    dependencies=[Depends(require_role(RoleName.SUPER_ADMIN, RoleName.ADMIN))],
)
async def get_all_roles_permission_history(
    role: Optional[str] = Query(None, description="Filter history by role name or UUID"),
    from_date: Optional[datetime] = Query(None, alias="fromDate", description="Filter history from date"),
    to_date: Optional[datetime] = Query(None, alias="toDate", description="Filter history to date"),
    limit: int = Query(50, ge=1, le=100, description="Max snapshots to retrieve"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    service: RBACService = Depends(),
) -> List[RoleSnapshotHistoryResponse]:
    """Retrieve chronological point-in-time snapshots of role permissions across all roles with audit details."""
    return await service.get_all_roles_permission_history(
        role_identifier=role,
        from_date=from_date,
        to_date=to_date,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/roles/{role_identifier}/snapshot-histories",
    summary="Get point-in-time permission snapshot history for a role.",
    status_code=status.HTTP_200_OK,
    response_model=List[RoleSnapshotHistoryResponse],
    dependencies=[Depends(require_role(RoleName.SUPER_ADMIN, RoleName.ADMIN))],
)
async def get_role_permission_history(
    role_identifier: str,
    from_date: Optional[datetime] = Query(None, alias="fromDate", description="Filter history from date"),
    to_date: Optional[datetime] = Query(None, alias="toDate", description="Filter history to date"),
    limit: int = Query(50, ge=1, le=100, description="Max snapshots to retrieve"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    service: RBACService = Depends(),
) -> List[RoleSnapshotHistoryResponse]:
    """Retrieve chronological point-in-time snapshots of role permissions with audit details."""
    return await service.get_role_permission_history(
        role_identifier=role_identifier,
        from_date=from_date,
        to_date=to_date,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/roles/{role_identifier}/rollback-snapshot",
    summary="Rollback role permissions to a selected point-in-time snapshot.",
    status_code=status.HTTP_200_OK,
    response_model=RoleRollbackResponse,
)
async def rollback_role_permissions(
    role_identifier: str,
    payload: RoleRollbackPayload,
    operator_id: UUID = Depends(require_role(RoleName.SUPER_ADMIN, RoleName.ADMIN)),
    service: RBACService = Depends(),
) -> RoleRollbackResponse:
    """Restores role permissions to a historical point-in-time snapshot and invalidates affected caches."""
    return await service.rollback_role_permissions(
        operator_id=operator_id,
        role_identifier=role_identifier,
        snapshot_id=payload.snapshot_id,
        reason=payload.reason,
    )


@router.get(
    "/change-requests/pending-requests",
    summary="List pending dual-control change requests awaiting hierarchical review.",
    status_code=status.HTTP_200_OK,
    response_model=List[RBACChangeRequestResponse],
)
async def list_pending_change_requests(
    operator_id: UUID = Depends(require_role(RoleName.SUPER_ADMIN, RoleName.ADMIN)),
    service: RBACService = Depends(),
) -> List[RBACChangeRequestResponse]:
    """Lists pending privilege escalation requests."""
    return await service.list_pending_change_requests(operator_id=operator_id)


@router.post(
    "/change-requests/{request_id}/approve",
    summary="Approve an RBAC change request under hierarchical authority.",
    status_code=status.HTTP_200_OK,
    response_model=RBACChangeRequestResponse,
)
async def approve_change_request(
    request_id: UUID,
    payload: ReviewChangeRequestPayload,
    operator_id: UUID = Depends(require_role(RoleName.SUPER_ADMIN, RoleName.ADMIN)),
    service: RBACService = Depends(),
) -> RBACChangeRequestResponse:
    """
    Approves change request:
    - Enforces dual control (requester cannot self-approve)
    - Reviewer rank must strictly exceed requester rank
    - Applies changes and flushes target user cache
    """
    return await service.review_change_request(
        operator_id=operator_id,
        request_id=request_id,
        payload=payload,
        is_approved=True,
    )


@router.post(
    "/change-requests/{request_id}/reject",
    summary="Reject an RBAC change request.",
    status_code=status.HTTP_200_OK,
    response_model=RBACChangeRequestResponse,
)
async def reject_change_request(
    request_id: UUID,
    payload: ReviewChangeRequestPayload,
    operator_id: UUID = Depends(require_role(RoleName.SUPER_ADMIN, RoleName.ADMIN)),
    service: RBACService = Depends(),
) -> RBACChangeRequestResponse:
    """Rejects change request with review notes."""
    return await service.review_change_request(
        operator_id=operator_id,
        request_id=request_id,
        payload=payload,
        is_approved=False,
    )
