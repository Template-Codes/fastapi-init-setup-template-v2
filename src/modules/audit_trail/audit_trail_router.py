from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Path, Query, Request, status

from dependencies.current_user import require_user_profile_and_get_id
from dependencies.rate_limit import rate_limit_by_user
from dependencies.rbac_guard import require_role
from modules.audit_trail.audit_trail_schema import (
    AuditLogQueryFilter,
    AuditLogResponse,
    AuditTrailDashboardResponse,
    CursorAuditLogResponse,
    RecordHistoryResponse,
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
    "/dashboard",
    summary="Retrieve initial audit trail dashboard view with summary metrics, filter options, and initial logs.",
    status_code=status.HTTP_200_OK,
    response_model=AuditTrailDashboardResponse,
    dependencies=[
        Depends(rate_limit_by_user(max_requests=30, window_sec=60)),
    ],
)
async def get_audit_trail_dashboard(
    request: Request,
    service: AuditTrailService = Depends(),
) -> AuditTrailDashboardResponse:
    """Provides initial bootstrap view for the Audit Trail compliance console."""
    base_path = str(request.url.path).replace("/dashboard", "")
    return await service.get_dashboard_data(base_path=base_path)


@router.get(
    "",
    summary="List cursor-paginated audit logs with dynamic multi-dimensional filtering (Admin only).",
    status_code=status.HTTP_200_OK,
    response_model=CursorAuditLogResponse,
    dependencies=[
        Depends(rate_limit_by_user(max_requests=30, window_sec=60)),
    ],
)
async def list_audit_logs(
    request: Request,
    filter_params: AuditLogQueryFilter = Depends(),
    service: AuditTrailService = Depends(),
) -> CursorAuditLogResponse:
    """Retrieve cursor-paginated and filtered activity audit logs with deep link support."""
    return await service.get_logs_cursor(filter_params, base_path=str(request.url.path))


@router.get(
    "/records/{target_table}/{record_id}/history",
    summary="Retrieve chronological audit history of a specific target entity record (Admin only).",
    status_code=status.HTTP_200_OK,
    response_model=RecordHistoryResponse,
    dependencies=[
        Depends(rate_limit_by_user(max_requests=30, window_sec=60)),
    ],
)
async def get_record_audit_history(
    target_table: str = Path(..., description="Target model table name (e.g. users, roles, sessions)"),
    record_id: str = Path(..., description="Target record unique identifier"),
    cursor: Optional[str] = Query(default=None, description="Cursor for pagination traversal"),
    limit: int = Query(default=50, ge=1, le=200, description="Items limit"),
    service: AuditTrailService = Depends(),
) -> RecordHistoryResponse:
    """Retrieve chronological state mutation diffs and lifecycle history for a specific entity record."""
    return await service.get_record_history(
        target_table=target_table,
        target_id=record_id,
        cursor=cursor,
        limit=limit,
    )


@router.get(
    "/{id}",
    summary="Retrieve details of a single audit log entry (Admin only).",
    status_code=status.HTTP_200_OK,
    response_model=AuditLogResponse,
    dependencies=[
        Depends(rate_limit_by_user(max_requests=60, window_sec=60)),
    ],
)
async def get_audit_log_by_id(
    id: UUID,
    service: AuditTrailService = Depends(),
) -> AuditLogResponse:
    """Retrieve full detail of an activity audit log entry by UUID."""
    return await service.get_log_by_id(id)
