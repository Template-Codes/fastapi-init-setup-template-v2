from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import Field

from base.schema import BaseSchema
from shares.enums import AuditSeverity


class AuditLogResponse(BaseSchema):
    """Public representation of an activity audit log record."""
    id: UUID
    created_at: datetime
    sequence_number: int
    user_id: Optional[UUID] = None
    user_code: Optional[str] = None
    username_snapshot: Optional[str] = None
    severity: AuditSeverity = AuditSeverity.INFO
    module: str
    resource: str
    action: str
    reason: Optional[str] = None
    target_schema: Optional[str] = None
    target_table: Optional[str] = None
    target_id: Optional[str] = None
    target_code: Optional[str] = None
    old_values: Optional[Dict[str, Any]] = None
    new_values: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    request_id: Optional[str] = None
    session_id: Optional[UUID] = None


class AuditLogQueryFilter(BaseSchema):
    """Query parameters for filtering audit logs."""
    page: int = Field(default=1, ge=1, description="Page number starting from 1")
    limit: int = Field(default=50, ge=1, le=200, description="Page size limit")
    module: Optional[str] = Field(default=None, description="Filter by system module")
    resource: Optional[str] = Field(default=None, description="Filter by target resource")
    action: Optional[str] = Field(default=None, description="Filter by action name")
    user_id: Optional[UUID] = Field(default=None, description="Filter by user UUID")
    target_id: Optional[str] = Field(default=None, description="Filter by target entity ID")
    target_code: Optional[str] = Field(default=None, description="Filter by document or user code")
    severity: Optional[AuditSeverity] = Field(default=None, description="Filter by event severity")
    date_from: Optional[datetime] = Field(default=None, description="Start date filter (UTC)")
    date_to: Optional[datetime] = Field(default=None, description="End date filter (UTC)")


class PaginatedAuditLogResponse(BaseSchema):
    """Paginated list response for audit logs."""
    items: List[AuditLogResponse]
    total_count: int
    page: int
    limit: int
