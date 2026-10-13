from typing import Optional
from uuid import UUID

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    Path,
    Query,
    Request,
    Response,
    status,
)

from dependencies.current_user import require_user_profile_and_get_id
from dependencies.rate_limit import rate_limit_by_user
from dependencies.rbac_guard import require_role
from modules.audit_trail.audit_trail_schema import (
    AuditExportJobStatusResponse,
    AuditLogDetailResponse,
    AuditLogExportRequest,
    AuditLogPollQuery,
    AuditLogPollResponse,
    AuditLogQueryFilter,
    AuditLogResponse,
    AuditTrailDashboardResponse,
    CursorAuditLogResponse,
    RecordHistoryResponse,
)
from modules.audit_trail.audit_trail_service import AuditTrailService
from shares.enums import RoleName

router = APIRouter(
    prefix="/api/private/admin/audit-trail",
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
    base_path = str(request.url.path).replace("/dashboard", "/activity-logs")
    return await service.get_dashboard_data(base_path=base_path)


@router.get(
    "/poll-new-entries",
    summary="Poll for new audit trail entries since the active screen cursor (Admin only).",
    status_code=status.HTTP_200_OK,
    response_model=AuditLogPollResponse,
    dependencies=[
        Depends(rate_limit_by_user(max_requests=60, window_sec=60)),
    ],
)
async def poll_audit_logs(
    filter_params: AuditLogPollQuery = Depends(),
    service: AuditTrailService = Depends(),
) -> AuditLogPollResponse:
    """Lightweight head check indicating count of new entries since since_cursor."""
    return await service.poll_new_entries(filter_params)


@router.post(
    "/export-logs",
    summary="Export filtered audit logs as CSV or Excel (Admin only).",
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(rate_limit_by_user(max_requests=10, window_sec=60)),
    ],
)
async def export_audit_logs(
    export_req: AuditLogExportRequest,
    background_tasks: BackgroundTasks,
    current_user_id: UUID = Depends(require_user_profile_and_get_id),
    service: AuditTrailService = Depends(),
) -> Response:
    """
    Exports audit logs within a mandatory UTC date range.
    Streams directly if <= 1,000 rows, or dispatches an async background job if > 1,000 rows.
    """
    async_res, content, filename, content_type = await service.create_export(
        export_req=export_req,
        current_user_id=current_user_id,
        background_tasks=background_tasks,
    )
    if async_res:
        return Response(
            content=async_res.model_dump_json(by_alias=True),
            media_type="application/json",
            status_code=status.HTTP_202_ACCEPTED,
        )
    return Response(
        content=content,
        media_type=content_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get(
    "/export-jobs/{job_id}",
    summary="Check status of an asynchronous audit export job (Admin only).",
    status_code=status.HTTP_200_OK,
    response_model=AuditExportJobStatusResponse,
    dependencies=[
        Depends(rate_limit_by_user(max_requests=60, window_sec=60)),
    ],
)
async def get_export_job_status(
    job_id: UUID,
    service: AuditTrailService = Depends(),
) -> AuditExportJobStatusResponse:
    """Retrieves current processing status, row counts, and checksum of an export job."""
    return await service.get_export_job_status(job_id)


@router.get(
    "/export-jobs/{job_id}/download",
    summary="Download completed export file artifact (Admin only).",
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(rate_limit_by_user(max_requests=30, window_sec=60)),
    ],
)
async def download_export_file(
    job_id: UUID,
    service: AuditTrailService = Depends(),
) -> Response:
    """Downloads generated CSV or Excel export payload."""
    content, filename, content_type = await service.get_export_file(job_id)
    return Response(
        content=content,
        media_type=content_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


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
    "/activity-logs/{id}/detail",
    summary="Retrieve detail panel view model with context and before/after diff (Admin only).",
    status_code=status.HTTP_200_OK,
    response_model=AuditLogDetailResponse,
    dependencies=[
        Depends(rate_limit_by_user(max_requests=60, window_sec=60)),
    ],
)
async def get_audit_log_detail(
    id: UUID,
    service: AuditTrailService = Depends(),
) -> AuditLogDetailResponse:
    """Retrieve complete audit log detail with execution context and field-by-field mutation diff."""
    return await service.get_log_detail(id)


@router.get(
    "/activity-logs/{id}",
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


@router.get(
    "/activity-logs",
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
