import urllib.parse
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import Depends
from loguru import logger

from exceptions.app_exception import NotFoundException
from modules.audit_trail.audit_trail_model import AuditLog
from modules.audit_trail.audit_trail_repository import AuditTrailRepository
from modules.audit_trail.audit_trail_schema import (
    AuditLogQueryFilter,
    AuditLogResponse,
    AuditTrailDashboardResponse,
    AuditTrailFilterOptionsResponse,
    AuditTrailSummaryStats,
    CursorAuditLogResponse,
    CursorPaginationMetadata,
    FilterOptionItem,
    PaginatedAuditLogResponse,
    RecordHistoryResponse,
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
        base_path: str = "/api/private/admin/audit-logs",
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
        base_path: str = "/api/private/admin/audit-logs",
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
        base_path: str = "/api/private/admin/audit-logs/records",
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
