from uuid import UUID

from fastapi import APIRouter, Depends, status

from dependencies.current_user import require_user_profile_and_get_id
from dependencies.rbac_guard import require_role
from modules.audit_trail.audit_trail_schema import (
    AuditLogQueryFilter,
    AuditLogResponse,
    PaginatedAuditLogResponse,
)
from modules.audit_trail.audit_trail_service import AuditTrailService
from shares.enums import RoleName

router = APIRouter(
    prefix="/api/private/admin/audit-logs",
    tags=["Audit Trail"],
    dependencies=[
        Depends(require_user_profile_and_get_id),
        Depends(require_role(RoleName.SUPER_ADMIN, RoleName.ADMIN)),
    ],
)


@router.get(
    "",
    summary="List paginated audit logs with dynamic filtering (Admin only).",
    status_code=status.HTTP_200_OK,
    response_model=PaginatedAuditLogResponse,
)
async def list_audit_logs(
    filter_params: AuditLogQueryFilter = Depends(),
    service: AuditTrailService = Depends(),
) -> PaginatedAuditLogResponse:
    """Retrieve paginated and filtered activity audit logs."""
    return await service.get_logs(filter_params)


@router.get(
    "/{id}",
    summary="Retrieve details of a single audit log entry (Admin only).",
    status_code=status.HTTP_200_OK,
    response_model=AuditLogResponse,
)
async def get_audit_log_by_id(
    id: UUID,
    service: AuditTrailService = Depends(),
) -> AuditLogResponse:
    """Retrieve full detail of an activity audit log entry by UUID."""
    return await service.get_log_by_id(id)
