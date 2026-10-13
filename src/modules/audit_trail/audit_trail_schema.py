from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import AliasChoices, Field, model_validator

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


# ==============================================================================
# DETAIL PANEL & BEFORE/AFTER DIFF SCHEMAS
# ==============================================================================

class ChangeTypeEnum(str, Enum):
    ADDED = "ADDED"
    MODIFIED = "MODIFIED"
    REMOVED = "REMOVED"
    UNCHANGED = "UNCHANGED"


class DiffFieldItem(BaseSchema):
    """Field-level state mutation difference item."""
    field: str
    change_type: ChangeTypeEnum
    old_value: Optional[Any] = None
    new_value: Optional[Any] = None


class StateDiffResponse(BaseSchema):
    """Structured before/after diff calculation for an audit log mutation."""
    total_changes: int
    changed_fields: List[str]
    changes: List[DiffFieldItem]


class OperatorSnapshot(BaseSchema):
    """Actor identity snapshot."""
    user_id: Optional[UUID] = None
    user_code: Optional[str] = None
    username: Optional[str] = None


class TargetEntitySnapshot(BaseSchema):
    """Affected target entity snapshot."""
    target_schema: Optional[str] = None
    target_table: Optional[str] = None
    target_id: Optional[str] = None
    target_code: Optional[str] = None


class ReversalSnapshot(BaseSchema):
    """Transaction reversal and void linkage state."""
    is_reversal: bool = False
    reversal_for_id: Optional[str] = None


class ExecutionContextDetail(BaseSchema):
    """Execution telemetry and operational context metadata."""
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    request_id: Optional[str] = None
    session_id: Optional[UUID] = None
    metadata: Optional[Dict[str, Any]] = None


class AuditLogDetailResponse(BaseSchema):
    """Deep inspection view model for detail panel with context and before/after diff."""
    id: UUID
    created_at: datetime
    sequence_number: int
    severity: AuditSeverity
    module: str
    resource: str
    action: str
    reason: Optional[str] = None
    operator: OperatorSnapshot
    target_entity: TargetEntitySnapshot
    context: ExecutionContextDetail
    reversal: ReversalSnapshot
    diff: StateDiffResponse


# ==============================================================================
# POLLING & MANUAL REFRESH SCHEMAS
# ==============================================================================

class AuditLogPollQuery(BaseSchema):
    """Query parameters for head check polling and manual refresh button."""
    since_cursor: Optional[str] = Field(default=None, alias="since_cursor", description="Cursor token (snake_case)")
    sinceCursor: Optional[str] = Field(default=None, alias="sinceCursor", description="Cursor token (camelCase)")
    module: Optional[str] = None
    resource: Optional[str] = None
    action: Optional[str] = None
    severity: Optional[AuditSeverity] = None
    user_id: Optional[UUID] = None
    user_code: Optional[str] = None
    username: Optional[str] = None
    search: Optional[str] = None
    target_table: Optional[str] = None
    target_id: Optional[str] = None

    @model_validator(mode="after")
    def validate_cursor(self) -> "AuditLogPollQuery":
        token = self.since_cursor or self.sinceCursor
        if not token:
            raise ValueError("Parameter 'sinceCursor' (or 'since_cursor') is required")
        self.since_cursor = token
        return self


class AuditLogPollResponse(BaseSchema):
    """Lightweight polling check response indicating new entries count."""
    has_new_entries: bool
    new_entries_count: int
    since_cursor: str
    latest_cursor: Optional[str] = None
    latest_created_at: Optional[datetime] = None


# ==============================================================================
# PRINT & EXPORT SCHEMAS (CSV / EXCEL)
# ==============================================================================

class ExportFormatEnum(str, Enum):
    CSV = "CSV"
    EXCEL = "EXCEL"


class AuditLogExportRequest(BaseSchema):
    """Parameters for exporting audit trail records."""
    date_from: datetime = Field(..., description="Start date filter (UTC) - Required")
    date_to: datetime = Field(..., description="End date filter (UTC) - Required")
    file_format: ExportFormatEnum = Field(default=ExportFormatEnum.CSV, description="Target export file format (CSV or EXCEL)")
    module: Optional[str] = None
    resource: Optional[str] = None
    action: Optional[str] = None
    severity: Optional[AuditSeverity] = None
    user_id: Optional[UUID] = None
    user_code: Optional[str] = None
    username: Optional[str] = None
    search: Optional[str] = None
    target_table: Optional[str] = None
    target_id: Optional[str] = None
    row_cap: int = Field(default=50000, ge=1, le=50000, description="Hard cap on rows to export (max 50,000)")

    @model_validator(mode="after")
    def validate_date_range(self) -> "AuditLogExportRequest":
        if self.date_from > self.date_to:
            raise ValueError("date_from must not be later than date_to")
        if (self.date_to - self.date_from).days > 90:
            raise ValueError("Export date range cannot exceed 90 days")
        return self


class AuditLogExportResponse(BaseSchema):
    """Response returned when an export operation is dispatched."""
    job_id: UUID
    status: str
    file_format: ExportFormatEnum
    requested_at: datetime
    total_rows_estimated: int
    is_async: bool
    status_url: str
    download_url: Optional[str] = None
    message: str


class AuditExportJobStatusResponse(BaseSchema):
    """Status tracking representation for an asynchronous export task."""
    job_id: UUID
    status: str
    file_format: str
    requested_at: datetime
    completed_at: Optional[datetime] = None
    total_rows: Optional[int] = None
    sha256_checksum: Optional[str] = None
    download_url: Optional[str] = None
    failure_reason: Optional[str] = None
