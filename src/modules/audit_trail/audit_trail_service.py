from typing import Any, Dict, Optional
from uuid import UUID

from fastapi import Depends
from loguru import logger

from exceptions.app_exception import NotFoundException
from modules.audit_trail.audit_trail_model import AuditLog
from modules.audit_trail.audit_trail_repository import AuditTrailRepository
from modules.audit_trail.audit_trail_schema import (
    AuditLogQueryFilter,
    AuditLogResponse,
    PaginatedAuditLogResponse,
)
from shares.enums import ActionName, AuditSeverity, ModuleName, ResourceName


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

    async def get_logs(
        self, filter_params: AuditLogQueryFilter
    ) -> PaginatedAuditLogResponse:
        """Fetch paginated audit log entries matching query criteria."""
        items, total_count = await self.audit_repo.query_logs(filter_params)
        parsed_items = [AuditLogResponse.model_validate(log) for log in items]
        return PaginatedAuditLogResponse(
            items=parsed_items,
            total_count=total_count,
            page=filter_params.page,
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
