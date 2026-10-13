from datetime import datetime, timezone
import hashlib
import io
from pathlib import Path
import tempfile
from typing import Any, Dict, List, Optional, Sequence, Tuple
import urllib.parse
from uuid import UUID

from fastapi import BackgroundTasks, Depends
from loguru import logger
import pandas as pd

from exceptions.app_exception import BadRequestException, NotFoundException
from modules.audit_trail.audit_trail_model import AuditLog
from modules.audit_trail.audit_trail_repository import AuditTrailRepository
from modules.audit_trail.audit_trail_schema import (
    AuditExportJobStatusResponse,
    AuditLogDetailResponse,
    AuditLogExportRequest,
    AuditLogExportResponse,
    AuditLogPollQuery,
    AuditLogPollResponse,
    AuditLogQueryFilter,
    AuditLogResponse,
    AuditTrailDashboardResponse,
    AuditTrailFilterOptionsResponse,
    AuditTrailSummaryStats,
    ChangeTypeEnum,
    CursorAuditLogResponse,
    CursorPaginationMetadata,
    DiffFieldItem,
    ExecutionContextDetail,
    ExportFormatEnum,
    FilterOptionItem,
    OperatorSnapshot,
    PaginatedAuditLogResponse,
    RecordHistoryResponse,
    ReversalSnapshot,
    StateDiffResponse,
    TargetEntitySnapshot,
)
from shares.enums import (
    ACTION_DESCRIPTIONS,
    MODULE_DESCRIPTIONS,
    RESOURCE_DESCRIPTIONS,
    ActionName,
    AuditSeverity,
    ModuleName,
    ResourceName,
)


def _build_query_url(base_path: str, params: Dict[str, Any]) -> str:
    """Constructs a deterministic canonical URL with sorted query parameters."""
    cleaned = {}
    for k, v in params.items():
        if v is None or v == "":
            continue
        if hasattr(v, "isoformat"):
            cleaned[k] = v.isoformat()
        elif hasattr(v, "value"):
            cleaned[k] = str(v.value)
        else:
            cleaned[k] = str(v)

    sorted_pairs = sorted(cleaned.items())
    query_str = urllib.parse.urlencode(sorted_pairs)
    return f"{base_path}?{query_str}" if query_str else base_path


class AuditTrailService:
    """
    Decoupled enterprise activity audit service.
    Provides opt-in logging for domain services and administrative query APIs.
    """

    def __init__(
        self,
        audit_repo: AuditTrailRepository = Depends(),
    ):
        self.audit_repo = audit_repo

    async def log(
        self,
        action: str | ActionName,
        resource: str | ResourceName,
        module: str | ModuleName = ModuleName.SYSTEM,
        user_id: Optional[UUID] = None,
        user_code: Optional[str] = None,
        username: Optional[str] = None,
        target_id: Optional[str] = None,
        target_code: Optional[str] = None,
        target_table: Optional[str] = None,
        reason: Optional[str] = None,
        old_values: Optional[Dict[str, Any]] = None,
        new_values: Optional[Dict[str, Any]] = None,
        severity: AuditSeverity = AuditSeverity.INFO,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_id: Optional[str] = None,
        session_id: Optional[UUID] = None,
        commit: bool = False,
    ) -> Optional[AuditLog]:
        """
        Records an audit log entry.
        Defaults to commit=False to share the active business transaction.
        """
        action_val = action.value if isinstance(action, ActionName) else str(action)
        resource_val = resource.value if isinstance(resource, ResourceName) else str(resource)
        module_val = module.value if isinstance(module, ModuleName) else str(module)

        # Auto-compute changed_fields from symmetric diff of old and new values
        computed_changed_fields: Optional[list] = None
        if old_values is not None and new_values is not None:
            computed_changed_fields = [
                k
                for k in set(old_values) | set(new_values)
                if old_values.get(k) != new_values.get(k)
            ]

        data = {
            "module": module_val,
            "resource": resource_val,
            "action": action_val,
            "severity": severity,
            "user_id": user_id,
            "user_code": user_code,
            "username_snapshot": username,
            "target_id": target_id,
            "target_code": target_code,
            "target_table": target_table,
            "reason": reason,
            "old_values": old_values,
            "new_values": new_values,
            "changed_fields": computed_changed_fields,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "request_id": request_id,
            "session_id": session_id,
        }

        try:
            audit_entry = await self.audit_repo.create_log(data, commit=commit)
            logger.debug(
                f"Audit log recorded: [{module_val}:{resource_val}:{action_val}] by user {user_id or 'SYSTEM'}"
            )
            return audit_entry
        except Exception as e:
            logger.warning(f"Failed to record audit log: {e}")
            return None

    async def get_logs_cursor(
        self,
        filter_params: AuditLogQueryFilter,
        base_path: str = "/api/private/admin/audit-trail/activity-logs",
    ) -> CursorAuditLogResponse:
        """Fetch cursor-paginated audit log entries with dynamic multidimensional filters."""
        items, has_more, next_cursor = await self.audit_repo.query_logs_cursor(filter_params)
        parsed_items = [AuditLogResponse.model_validate(log) for log in items]

        # Construct shareable / bookmarkable URLs
        raw_params = filter_params.model_dump(exclude_none=True, by_alias=True)
        canonical_url = _build_query_url(base_path, raw_params)

        next_url: Optional[str] = None
        if has_more and next_cursor:
            next_params = {**raw_params, "cursor": next_cursor}
            next_url = _build_query_url(base_path, next_params)

        pagination = CursorPaginationMetadata(
            next_cursor=next_cursor,
            has_more=has_more,
            limit=filter_params.limit,
            canonical_url=canonical_url,
            next_url=next_url,
        )

        return CursorAuditLogResponse(
            items=parsed_items,
            pagination=pagination,
        )

    async def get_dashboard_data(
        self,
        base_path: str = "/api/private/admin/audit-trail/activity-logs",
    ) -> AuditTrailDashboardResponse:
        """
        Assembles initial audit trail dashboard view:
        24h aggregate stats, available filter options catalog, and initial log slice.
        """
        aggregates = await self.audit_repo.get_dashboard_aggregates()
        stats = AuditTrailSummaryStats(
            events_last_24h=aggregates["events_last_24h"],
            critical_events_last_24h=aggregates["critical_events_last_24h"],
            error_events_last_24h=aggregates["error_events_last_24h"],
        )

        filter_options = AuditTrailFilterOptionsResponse(
            modules=[
                FilterOptionItem(
                    value=m.value,
                    label=m.value.replace("_", " ").title(),
                    description=MODULE_DESCRIPTIONS.get(m),
                )
                for m in ModuleName
            ],
            resources=[
                FilterOptionItem(
                    value=r.value,
                    label=r.value.replace("_", " ").title(),
                    description=RESOURCE_DESCRIPTIONS.get(r),
                )
                for r in ResourceName
            ],
            actions=[
                FilterOptionItem(
                    value=a.value,
                    label=a.value.replace("_", " ").title(),
                    description=ACTION_DESCRIPTIONS.get(a),
                )
                for a in ActionName
            ],
            severities=[
                FilterOptionItem(
                    value=s.value,
                    label=s.value.title(),
                    description=f"{s.value.title()} priority audit event",
                )
                for s in AuditSeverity
            ],
        )

        initial_filter = AuditLogQueryFilter(limit=25)
        initial_logs = await self.get_logs_cursor(initial_filter, base_path=base_path)

        return AuditTrailDashboardResponse(
            stats=stats,
            filter_options=filter_options,
            initial_logs=initial_logs,
        )

    async def get_record_history(
        self,
        target_table: str,
        target_id: str,
        cursor: Optional[str] = None,
        limit: int = 50,
        base_path: str = "/api/private/admin/audit-trail/records",
    ) -> RecordHistoryResponse:
        """Retrieves chronological mutation timeline of a specific model entity record."""
        items, has_more, next_cursor = await self.audit_repo.query_record_history(
            target_table=target_table,
            target_id=target_id,
            cursor=cursor,
            limit=limit,
        )
        parsed_items = [AuditLogResponse.model_validate(log) for log in items]

        record_base_path = f"{base_path}/{target_table}/{target_id}/history"
        raw_params: Dict[str, Any] = {"limit": limit}
        if cursor:
            raw_params["cursor"] = cursor
        canonical_url = _build_query_url(record_base_path, raw_params)

        next_url: Optional[str] = None
        if has_more and next_cursor:
            next_url = _build_query_url(
                record_base_path, {"limit": limit, "cursor": next_cursor}
            )

        target_code = parsed_items[0].target_code if parsed_items else None

        pagination = CursorPaginationMetadata(
            next_cursor=next_cursor,
            has_more=has_more,
            limit=limit,
            canonical_url=canonical_url,
            next_url=next_url,
        )

        return RecordHistoryResponse(
            target_table=target_table,
            target_id=target_id,
            target_code=target_code,
            history=parsed_items,
            pagination=pagination,
        )

    async def get_logs(
        self, filter_params: AuditLogQueryFilter
    ) -> PaginatedAuditLogResponse:
        """Fetch paginated audit log entries matching query criteria (legacy offset pagination)."""
        items, total_count = await self.audit_repo.query_logs(filter_params)
        parsed_items = [AuditLogResponse.model_validate(log) for log in items]
        return PaginatedAuditLogResponse(
            items=parsed_items,
            total_count=total_count,
            page=filter_params.page or 1,
            limit=filter_params.limit,
        )

    async def get_log_by_id(self, log_id: UUID) -> AuditLogResponse:
        """Fetch a single audit log entry by its UUID."""
        item = await self.audit_repo.get_by_id(log_id)
        if not item:
            raise NotFoundException(
                message=f"Audit log with ID '{log_id}' not found.",
                error_code="AUDIT_LOG_NOT_FOUND",
            )
        return AuditLogResponse.model_validate(item)

    async def get_log_detail(self, log_id: UUID) -> AuditLogDetailResponse:
        """
        Deep inspection view model for detail panel with execution context and before/after diff.
        """
        item = await self.audit_repo.get_by_id(log_id)
        if not item:
            raise NotFoundException(
                message=f"Audit log with ID '{log_id}' not found.",
                error_code="AUDIT_LOG_NOT_FOUND",
            )

        old_val = item.old_values or {}
        new_val = item.new_values or {}
        all_keys = sorted(set(old_val.keys()) | set(new_val.keys()))

        changes: List[DiffFieldItem] = []
        for key in all_keys:
            in_old = key in old_val
            in_new = key in new_val
            v_old = old_val.get(key)
            v_new = new_val.get(key)

            if in_old and in_new:
                if v_old != v_new:
                    change_type = ChangeTypeEnum.MODIFIED
                else:
                    change_type = ChangeTypeEnum.UNCHANGED
            elif in_new and not in_old:
                change_type = ChangeTypeEnum.ADDED
            else:
                change_type = ChangeTypeEnum.REMOVED

            changes.append(
                DiffFieldItem(
                    field=key,
                    change_type=change_type,
                    old_value=v_old,
                    new_value=v_new,
                )
            )

        total_changes = len([c for c in changes if c.change_type != ChangeTypeEnum.UNCHANGED])
        changed_fields = item.changed_fields or [
            c.field for c in changes if c.change_type != ChangeTypeEnum.UNCHANGED
        ]

        diff = StateDiffResponse(
            total_changes=total_changes,
            changed_fields=changed_fields,
            changes=changes,
        )

        operator = OperatorSnapshot(
            user_id=item.user_id,
            user_code=item.user_code,
            username=item.username_snapshot,
        )

        target_entity = TargetEntitySnapshot(
            target_schema=item.target_schema,
            target_table=item.target_table,
            target_id=item.target_id,
            target_code=item.target_code,
        )

        context = ExecutionContextDetail(
            ip_address=item.ip_address,
            user_agent=item.user_agent,
            request_id=item.request_id,
            session_id=item.session_id,
            metadata=item.context,
        )

        reversal = ReversalSnapshot(
            is_reversal=item.is_reversal,
            reversal_for_id=item.reversal_for_id,
        )

        return AuditLogDetailResponse(
            id=item.id,
            created_at=item.created_at,
            sequence_number=item.sequence_number,
            severity=item.severity,
            module=item.module,
            resource=item.resource,
            action=item.action,
            reason=item.reason,
            operator=operator,
            target_entity=target_entity,
            context=context,
            reversal=reversal,
            diff=diff,
        )

    async def poll_new_entries(
        self, filter_params: AuditLogPollQuery
    ) -> AuditLogPollResponse:
        """
        Lightweight head check indicating count of new entries since since_cursor.
        Used by the frontend 60s background polling and 'Manual Refresh' button.
        """
        count, latest_cursor, latest_dt = await self.audit_repo.count_new_entries_since(
            filter_params.since_cursor, filter_params
        )
        return AuditLogPollResponse(
            has_new_entries=count > 0,
            new_entries_count=count,
            since_cursor=filter_params.since_cursor,
            latest_cursor=latest_cursor,
            latest_created_at=latest_dt,
        )

    def _generate_export_content(
        self, logs: Sequence[AuditLog], file_format: ExportFormatEnum
    ) -> Tuple[bytes, str, str]:
        """Converts audit log sequences into CSV or Excel binary payloads."""
        rows = [
            {
                "id": str(log.id),
                "created_at": log.created_at.isoformat(),
                "sequence_number": log.sequence_number,
                "severity": log.severity.value if hasattr(log.severity, "value") else str(log.severity),
                "module": log.module,
                "resource": log.resource,
                "action": log.action,
                "reason": log.reason or "",
                "user_id": str(log.user_id) if log.user_id else "",
                "user_code": log.user_code or "",
                "username": log.username_snapshot or "",
                "target_table": log.target_table or "",
                "target_id": log.target_id or "",
                "target_code": log.target_code or "",
                "is_reversal": log.is_reversal,
                "ip_address": log.ip_address or "",
            }
            for log in logs
        ]
        columns = [
            "id", "created_at", "sequence_number", "severity", "module",
            "resource", "action", "reason", "user_id", "user_code", "username",
            "target_table", "target_id", "target_code", "is_reversal", "ip_address"
        ]
        df = pd.DataFrame(rows, columns=columns) if rows else pd.DataFrame(columns=columns)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        if file_format == ExportFormatEnum.EXCEL:
            buffer = io.BytesIO()
            df.to_excel(buffer, index=False, engine="openpyxl")
            content = buffer.getvalue()
            filename = f"audit_logs_{timestamp}.xlsx"
            content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        else:
            content = df.to_csv(index=False).encode("utf-8")
            filename = f"audit_logs_{timestamp}.csv"
            content_type = "text/csv"

        return content, filename, content_type

    async def process_export_job(
        self, job_id: UUID, export_req: AuditLogExportRequest
    ) -> None:
        """Processes an asynchronous export job, writing the file to disk and recording checksum."""
        job = await self.audit_repo.get_export_job_by_id(job_id)
        if not job:
            return
        try:
            await self.audit_repo.update_export_job(job, {"status": "PROCESSING"})

            logs = await self.audit_repo.query_logs_for_export(export_req)
            content, filename, _ = self._generate_export_content(logs, export_req.file_format)

            export_dir = Path(tempfile.gettempdir()) / "xcom_audit_exports"
            export_dir.mkdir(parents=True, exist_ok=True)
            file_path = export_dir / f"{job_id}_{filename}"
            with open(file_path, "wb") as f:
                f.write(content)

            checksum = hashlib.sha256(content).hexdigest()
            await self.audit_repo.update_export_job(
                job,
                {
                    "status": "COMPLETED",
                    "completed_at": datetime.now(timezone.utc),
                    "total_rows": len(logs),
                    "file_path": str(file_path),
                    "sha256_checksum": checksum,
                },
            )
            await self.audit_repo.db.commit()
        except Exception as exc:
            logger.error(f"Failed to process audit export job {job_id}: {exc}")
            await self.audit_repo.update_export_job(
                job,
                {
                    "status": "FAILED",
                    "completed_at": datetime.now(timezone.utc),
                    "failure_reason": str(exc),
                },
            )
            await self.audit_repo.db.commit()

    async def create_export(
        self,
        export_req: AuditLogExportRequest,
        current_user_id: UUID,
        current_user_code: Optional[str] = None,
        current_username: Optional[str] = None,
        background_tasks: Optional[BackgroundTasks] = None,
    ) -> Tuple[Optional[AuditLogExportResponse], Optional[bytes], Optional[str], Optional[str]]:
        """
        Dispatches export request:
        - If matching rows <= 1,000: generates synchronous streaming download.
        - If matching rows > 1,000: registers AuditExportJob and queues async background worker.
        Records an internal statutory audit entry for all export operations.
        """
        total_matched = await self.audit_repo.count_logs_for_export(export_req)

        # 1. Statutory audit entry for export action
        await self.log(
            action=ActionName.EXPORT,
            resource=ResourceName.EXPORT_JOB,
            module=ModuleName.AUDIT_TRAIL,
            user_id=current_user_id,
            user_code=current_user_code,
            username=current_username,
            reason=(
                f"Exported audit trail data [format={export_req.file_format.value}, "
                f"range={export_req.date_from.date()} to {export_req.date_to.date()}, matched={total_matched}]"
            ),
            severity=AuditSeverity.INFO,
            commit=True,
        )

        # 2. Synchronous stream threshold check (<= 1,000 rows)
        if total_matched <= 1000:
            logs = await self.audit_repo.query_logs_for_export(export_req)
            content, filename, content_type = self._generate_export_content(
                logs, export_req.file_format
            )
            return None, content, filename, content_type

        # 3. Asynchronous background job (> 1,000 rows)
        job = await self.audit_repo.create_export_job(
            {
                "requested_by": current_user_id,
                "file_format": export_req.file_format.value,
                "status": "PENDING",
                "filter_criteria": export_req.model_dump(mode="json", exclude_none=True),
                "total_rows": total_matched,
            }
        )
        await self.audit_repo.db.commit()

        if background_tasks:
            background_tasks.add_task(self.process_export_job, job.id, export_req)

        async_response = AuditLogExportResponse(
            job_id=job.id,
            status=job.status,
            file_format=export_req.file_format,
            requested_at=job.requested_at,
            total_rows_estimated=total_matched,
            is_async=True,
            status_url=f"/api/private/admin/audit-trail/export-jobs/{job.id}",
            download_url=None,
            message="Export dataset exceeds direct stream threshold (>1,000 rows). Running as background job.",
        )

        return async_response, None, None, None

    async def get_export_job_status(self, job_id: UUID) -> AuditExportJobStatusResponse:
        """Retrieves status and checksum details for an asynchronous export job."""
        job = await self.audit_repo.get_export_job_by_id(job_id)
        if not job:
            raise NotFoundException(
                message=f"Export job with ID '{job_id}' not found.",
                error_code="EXPORT_JOB_NOT_FOUND",
            )
        download_url = (
            f"/api/private/admin/audit-trail/export-jobs/{job.id}/download"
            if job.status == "COMPLETED"
            else None
        )
        return AuditExportJobStatusResponse(
            job_id=job.id,
            status=job.status,
            file_format=job.file_format,
            requested_at=job.requested_at,
            completed_at=job.completed_at,
            total_rows=job.total_rows,
            sha256_checksum=job.sha256_checksum,
            download_url=download_url,
            failure_reason=job.failure_reason,
        )

    async def get_export_file(self, job_id: UUID) -> Tuple[bytes, str, str]:
        """Reads generated export file payload from disk for download."""
        job = await self.audit_repo.get_export_job_by_id(job_id)
        if not job:
            raise NotFoundException(
                message=f"Export job with ID '{job_id}' not found.",
                error_code="EXPORT_JOB_NOT_FOUND",
            )
        if job.status != "COMPLETED" or not job.file_path:
            raise BadRequestException(
                message="Export job has not completed yet or failed.",
                error_code="EXPORT_NOT_READY",
                details={"current_status": job.status},
            )

        file_path = Path(job.file_path)
        if not file_path.exists():
            raise NotFoundException(
                message="Exported file artifact has expired or was removed.",
                error_code="EXPORT_FILE_MISSING",
            )

        content = file_path.read_bytes()
        content_type = (
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            if job.file_format == "EXCEL"
            else "text/csv"
        )
        return content, file_path.name, content_type
