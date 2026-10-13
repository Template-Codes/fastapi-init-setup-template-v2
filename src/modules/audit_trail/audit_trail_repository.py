from datetime import datetime
from typing import Optional, Sequence, Tuple
from uuid import UUID
from fastapi import Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from base.repository import BaseRepository
from db.db_session import get_async_db
from modules.audit_trail.audit_trail_model import AuditLog
from modules.audit_trail.audit_trail_schema import AuditLogQueryFilter


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

    async def query_logs(
        self, filter_params: AuditLogQueryFilter
    ) -> Tuple[Sequence[AuditLog], int]:
        """
        Retrieves a paginated list of audit logs matching filter criteria along with total count.
        """
        stmt = select(AuditLog)

        if filter_params.module:
            stmt = stmt.where(AuditLog.module == filter_params.module)
        if filter_params.resource:
            stmt = stmt.where(AuditLog.resource == filter_params.resource)
        if filter_params.action:
            stmt = stmt.where(AuditLog.action == filter_params.action)
        if filter_params.user_id:
            stmt = stmt.where(AuditLog.user_id == filter_params.user_id)
        if filter_params.target_id:
            stmt = stmt.where(AuditLog.target_id == filter_params.target_id)
        if filter_params.target_code:
            stmt = stmt.where(AuditLog.target_code == filter_params.target_code)
        if filter_params.severity:
            stmt = stmt.where(AuditLog.severity == filter_params.severity)
        if filter_params.date_from:
            stmt = stmt.where(AuditLog.created_at >= filter_params.date_from)
        if filter_params.date_to:
            stmt = stmt.where(AuditLog.created_at <= filter_params.date_to)

        # Count total matching rows
        count_stmt = select(func.count()).select_from(stmt.subquery())
        count_res = await self.db.execute(count_stmt)
        total_count = count_res.scalar_one() or 0

        # Apply ordering and pagination
        offset = (filter_params.page - 1) * filter_params.limit
        stmt = (
            stmt.order_by(AuditLog.created_at.desc(), AuditLog.sequence_number.desc())
            .offset(offset)
            .limit(filter_params.limit)
        )

        result = await self.db.execute(stmt)
        items = result.scalars().all()

        return items, total_count
