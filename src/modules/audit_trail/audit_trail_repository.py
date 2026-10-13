import base64
from datetime import datetime, timedelta, timezone
import json
from typing import Any, Dict, Optional, Sequence, Tuple
from uuid import UUID

from fastapi import Depends
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from base.repository import BaseRepository
from db.db_session import get_async_db
from exceptions.app_exception import BadRequestException
from modules.audit_trail.audit_trail_model import AuditLog
from modules.audit_trail.audit_trail_schema import AuditLogQueryFilter
from shares.enums import AuditSeverity


def encode_cursor(created_at: datetime, sequence_number: int) -> str:
    """Serializes created_at timestamp and sequence_number into an opaque base64 string."""
    payload = json.dumps({"t": created_at.isoformat(), "s": sequence_number})
    return base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii")


def decode_cursor(cursor: str) -> Tuple[datetime, int]:
    """Deserializes an opaque base64 cursor string into (created_at, sequence_number)."""
    try:
        raw = base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8")
        data = json.loads(raw)
        dt = datetime.fromisoformat(data["t"])
        seq = int(data["s"])
        return dt, seq
    except Exception as exc:
        raise BadRequestException(
            message="Invalid or malformed pagination cursor token.",
            error_code="INVALID_CURSOR",
            details=str(exc),
        ) from exc


class AuditTrailRepository(BaseRepository[AuditLog]):
    """Repository handling persistence and queries for system activity logs."""

    def __init__(self, db: AsyncSession = Depends(get_async_db)):
        super().__init__(db, AuditLog)

    async def get_by_id(self, id: UUID) -> Optional[AuditLog]:  # type: ignore[override]
        """
        Fetch audit log by UUID only.

        IMPORTANT — Composite PK Guard:
        AuditLog has a composite primary key (id, created_at) to support
        PostgreSQL range partitioning. The inherited BaseRepository.get_by_id()
        uses db.get(model, id) which requires the *full* composite key tuple;
        passing only the UUID would silently return None for every existing row.

        This override intentionally uses SELECT WHERE on the id column alone.
        Never replace this with super().get_by_id() or db.get(AuditLog, id).
        """
        stmt = select(AuditLog).where(AuditLog.id == id)
        result = await self.db.execute(stmt)
        return result.scalars().first()

    async def create_log(self, data: dict, *, commit: bool = False) -> AuditLog:
        """
        Records an audit log entry within the active transaction.
        Defaults to commit=False so it shares the business transaction boundary.
        """
        return await self.create(data, commit=commit)

    def _apply_filters(self, stmt, filter_params: AuditLogQueryFilter):
        """Applies multidimensional search and filtering criteria to the select statement."""
        if filter_params.module:
            stmt = stmt.where(AuditLog.module == filter_params.module)
        if filter_params.resource:
            stmt = stmt.where(AuditLog.resource == filter_params.resource)
        if filter_params.action:
            stmt = stmt.where(AuditLog.action == filter_params.action)
        if filter_params.severity:
            stmt = stmt.where(AuditLog.severity == filter_params.severity)
        if filter_params.user_id:
            stmt = stmt.where(AuditLog.user_id == filter_params.user_id)
        if filter_params.user_code:
            stmt = stmt.where(AuditLog.user_code == filter_params.user_code)
        if filter_params.username:
            stmt = stmt.where(AuditLog.username_snapshot.ilike(f"%{filter_params.username}%"))
        if filter_params.date_from:
            stmt = stmt.where(AuditLog.created_at >= filter_params.date_from)
        if filter_params.date_to:
            stmt = stmt.where(AuditLog.created_at <= filter_params.date_to)
        if filter_params.search:
            stmt = stmt.where(AuditLog.reason.ilike(f"%{filter_params.search}%"))
        if filter_params.target_table:
            stmt = stmt.where(AuditLog.target_table == filter_params.target_table)
        if filter_params.target_id:
            stmt = stmt.where(AuditLog.target_id == filter_params.target_id)
        if filter_params.target_code:
            stmt = stmt.where(AuditLog.target_code == filter_params.target_code)
        return stmt

    async def query_logs_cursor(
        self, filter_params: AuditLogQueryFilter
    ) -> Tuple[Sequence[AuditLog], bool, Optional[str]]:
        """
        Retrieves a cursor-paginated list of audit logs matching filter criteria.
        Returns (items, has_more, next_cursor).
        """
        stmt = select(AuditLog)
        stmt = self._apply_filters(stmt, filter_params)

        if filter_params.cursor:
            cursor_dt, cursor_seq = decode_cursor(filter_params.cursor)
            stmt = stmt.where(
                or_(
                    AuditLog.created_at < cursor_dt,
                    and_(
                        AuditLog.created_at == cursor_dt,
                        AuditLog.sequence_number < cursor_seq,
                    ),
                )
            )

        stmt = (
            stmt.order_by(AuditLog.created_at.desc(), AuditLog.sequence_number.desc())
            .limit(filter_params.limit + 1)
        )

        result = await self.db.execute(stmt)
        rows = list(result.scalars().all())

        has_more = len(rows) > filter_params.limit
        items = rows[: filter_params.limit]
        next_cursor = (
            encode_cursor(items[-1].created_at, items[-1].sequence_number)
            if has_more and items
            else None
        )

        return items, has_more, next_cursor

    async def query_record_history(
        self,
        target_table: str,
        target_id: str,
        cursor: Optional[str] = None,
        limit: int = 50,
    ) -> Tuple[Sequence[AuditLog], bool, Optional[str]]:
        """
        Retrieves the chronological audit history of a specific target entity record.
        Uses ix_audit_logs_target_entity_created index.
        """
        stmt = select(AuditLog).where(
            AuditLog.target_table == target_table,
            AuditLog.target_id == target_id,
        )

        if cursor:
            cursor_dt, cursor_seq = decode_cursor(cursor)
            stmt = stmt.where(
                or_(
                    AuditLog.created_at < cursor_dt,
                    and_(
                        AuditLog.created_at == cursor_dt,
                        AuditLog.sequence_number < cursor_seq,
                    ),
                )
            )

        stmt = (
            stmt.order_by(AuditLog.created_at.desc(), AuditLog.sequence_number.desc())
            .limit(limit + 1)
        )

        result = await self.db.execute(stmt)
        rows = list(result.scalars().all())

        has_more = len(rows) > limit
        items = rows[:limit]
        next_cursor = (
            encode_cursor(items[-1].created_at, items[-1].sequence_number)
            if has_more and items
            else None
        )

        return items, has_more, next_cursor

    async def get_dashboard_aggregates(self) -> Dict[str, int]:
        """Calculates 24-hour KPI metrics for the audit trail dashboard view."""
        now = datetime.now(timezone.utc)
        past_24h = now - timedelta(hours=24)

        # 24h total events count
        total_stmt = select(func.count(AuditLog.id)).where(AuditLog.created_at >= past_24h)
        total_res = await self.db.execute(total_stmt)
        events_last_24h = total_res.scalar_one() or 0

        # 24h critical events count
        crit_stmt = select(func.count(AuditLog.id)).where(
            AuditLog.created_at >= past_24h,
            AuditLog.severity == AuditSeverity.CRITICAL,
        )
        crit_res = await self.db.execute(crit_stmt)
        critical_events_last_24h = crit_res.scalar_one() or 0

        # 24h error events count
        err_stmt = select(func.count(AuditLog.id)).where(
            AuditLog.created_at >= past_24h,
            AuditLog.severity == AuditSeverity.ERROR,
        )
        err_res = await self.db.execute(err_stmt)
        error_events_last_24h = err_res.scalar_one() or 0

        return {
            "events_last_24h": events_last_24h,
            "critical_events_last_24h": critical_events_last_24h,
            "error_events_last_24h": error_events_last_24h,
        }

    async def query_logs(
        self, filter_params: AuditLogQueryFilter
    ) -> Tuple[Sequence[AuditLog], int]:
        """
        Retrieves a paginated list of audit logs matching filter criteria along with total count.
        (Legacy offset-based pagination).
        """
        stmt = select(AuditLog)
        stmt = self._apply_filters(stmt, filter_params)

        # Count total matching rows
        count_stmt = select(func.count()).select_from(stmt.subquery())
        count_res = await self.db.execute(count_stmt)
        total_count = count_res.scalar_one() or 0

        page = filter_params.page or 1
        offset = (page - 1) * filter_params.limit
        stmt = (
            stmt.order_by(AuditLog.created_at.desc(), AuditLog.sequence_number.desc())
            .offset(offset)
            .limit(filter_params.limit)
        )

        result = await self.db.execute(stmt)
        items = result.scalars().all()

        return items, total_count
