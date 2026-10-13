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
    changed_fields: Optional[List[str]] = None
    is_reversal: bool = False
    reversal_for_id: Optional[str] = None
    context: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    request_id: Optional[str] = None
    session_id: Optional[UUID] = None


class AuditLogQueryFilter(BaseSchema):
    """Query parameters for filtering audit logs."""
    # Cursor pagination
    cursor: Optional[str] = Field(default=None, description="Opaque base64 cursor token for keyset pagination")
    limit: int = Field(default=50, ge=1, le=200, description="Page size limit")
    page: Optional[int] = Field(default=None, ge=1, description="Page number starting from 1 (legacy fallback)")

    # Event classification
    severity: Optional[AuditSeverity] = Field(default=None, description="Filter by event severity")
    module: Optional[str] = Field(default=None, description="Filter by system module")
    resource: Optional[str] = Field(default=None, description="Filter by target resource")
    action: Optional[str] = Field(default=None, description="Filter by action name")

    # Operator identification (Who)
    user_id: Optional[UUID] = Field(default=None, description="Filter by operator user UUID")
    user_code: Optional[str] = Field(default=None, description="Filter by operator user code")
    username: Optional[str] = Field(default=None, description="Filter by operator username (snapshot)")

    # Temporal filters (When)
    date_from: Optional[datetime] = Field(default=None, description="Start date filter (UTC)")
    date_to: Optional[datetime] = Field(default=None, description="End date filter (UTC)")

    # Text search
    search: Optional[str] = Field(default=None, description="Case-insensitive text search on reason")

    # Target record linkage (Affected model & record)
    target_table: Optional[str] = Field(default=None, description="Filter by affected model / table name")
    target_id: Optional[str] = Field(default=None, description="Filter by target entity ID")
    target_code: Optional[str] = Field(default=None, description="Filter by document or entity code")


class CursorPaginationMetadata(BaseSchema):
    """Metadata for cursor-based pagination and shareable URLs."""
    next_cursor: Optional[str] = None
    has_more: bool = False
    limit: int = 50
    canonical_url: Optional[str] = None
    next_url: Optional[str] = None


class CursorAuditLogResponse(BaseSchema):
    """Cursor-paginated audit log list response."""
    items: List[AuditLogResponse]
    pagination: CursorPaginationMetadata


class FilterOptionItem(BaseSchema):
    """Representation of an available filter option item."""
    value: str
    label: str
    description: Optional[str] = None


class AuditTrailFilterOptionsResponse(BaseSchema):
    """Available filter options catalog for UI dropdowns."""
    modules: List[FilterOptionItem]
    resources: List[FilterOptionItem]
    actions: List[FilterOptionItem]
    severities: List[FilterOptionItem]


class AuditTrailSummaryStats(BaseSchema):
    """Summary statistics for the audit trail dashboard."""
    events_last_24h: int = Field(
        alias="eventsLast24h",
        description="Total events recorded in the last 24 hours",
    )
    critical_events_last_24h: int = Field(
        alias="criticalEventsLast24h",
        description="Critical severity events recorded in the last 24 hours",
    )
    error_events_last_24h: int = Field(
        alias="errorEventsLast24h",
        description="Error severity events recorded in the last 24 hours",
    )


class AuditTrailDashboardResponse(BaseSchema):
    """Initial dashboard bootstrap response combining stats, filter options, and initial logs."""
    stats: AuditTrailSummaryStats
    filter_options: AuditTrailFilterOptionsResponse
    initial_logs: CursorAuditLogResponse


class RecordHistoryResponse(BaseSchema):
    """Chronological mutation timeline for a specific domain record."""
    target_table: str
    target_id: str
    target_code: Optional[str] = None
    history: List[AuditLogResponse]
    pagination: CursorPaginationMetadata


class PaginatedAuditLogResponse(BaseSchema):
    """Paginated list response for audit logs (legacy offset pagination)."""
    items: List[AuditLogResponse]
    total_count: int
    page: int
    limit: int
