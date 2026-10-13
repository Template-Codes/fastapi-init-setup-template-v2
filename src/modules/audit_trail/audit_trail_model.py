from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional
import uuid

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.base import Base, generate_uuid, uuid_pk
from shares.enums import AuditSeverity

if TYPE_CHECKING:
    from modules.authentication.auth_model import User
    from modules.session.session_model import UserSession


class AuditLog(Base):
    """
    Statutory BIR CAS Audit Trail and unalterable activity ledger.
    Governed by BIR Annex B Lines 271-295 and Item 11.i.
    """

    __tablename__ = "audit_logs"
    __table_args__ = (
        # Composite index for Module -> Resource -> Action filtering
        Index(
            "ix_audit_logs_mod_res_act_created",
            "module",
            "resource",
            "action",
            text("created_at DESC"),
        ),
        # Target entity history lookup
        Index(
            "ix_audit_logs_target_entity_created",
            "target_table",
            "target_id",
            text("created_at DESC"),
        ),
        # User actor timeline lookup
        Index(
            "ix_audit_logs_user_created",
            "user_id",
            text("created_at DESC"),
        ),
        # Human-readable document search (e.g., INV-000042)
        Index(
            "ix_audit_logs_target_code_created",
            "target_code",
            text("created_at DESC"),
        ),
        # Reversal linkage index
        Index(
            "ix_audit_logs_reversal_for_id",
            "reversal_for_id",
        ),

        # Check constraint: payload size guard against denial-of-service / JSON bombs
        CheckConstraint(
            "octet_length(context::text) <= 65536 AND "
            "octet_length(old_values::text) <= 262144 AND "
            "octet_length(new_values::text) <= 262144",
            name="ck_audit_logs_payload_size",
        ),
        {"schema": "audit_trail"},
    )

    # Composite Primary Key (id, created_at) enabling PostgreSQL Range Partitioning
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=generate_uuid,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        primary_key=True,
        default=lambda: datetime.now(timezone.utc),
        server_default=text("now()"),
        nullable=False,
    )

    # Monotonic running sequence for mathematical gap detection
    sequence_number: Mapped[int] = mapped_column(
        BigInteger,
        server_default=text("nextval('audit_trail.audit_seq')"),
        unique=True,
        index=True,
        nullable=False,
    )

    # Operator identification (nullable for anonymous/failed login attempts)
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("auth.users.id", ondelete="RESTRICT"),
        index=True,
        nullable=True,
    )
    user_code: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    username_snapshot: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Event classification
    severity: Mapped[AuditSeverity] = mapped_column(
        Enum(AuditSeverity, native_enum=True),
        default=AuditSeverity.INFO,
        index=True,
        nullable=False,
    )
    module: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    resource: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    action: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Target record linkage
    target_schema: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    target_table: Mapped[Optional[str]] = mapped_column(String(100), index=True, nullable=True)
    target_id: Mapped[Optional[str]] = mapped_column(String(100), index=True, nullable=True)
    target_code: Mapped[Optional[str]] = mapped_column(String(100), index=True, nullable=True)

    # Transaction reversal / void linkage (Annex B Item 10.c)
    is_reversal: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    reversal_for_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # State mutations and diffs (secrets redacted prior to write)
    old_values: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    new_values: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    changed_fields: Mapped[Optional[List[str]]] = mapped_column(JSONB, nullable=True)

    # Operational execution context
    context: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    request_id: Mapped[Optional[str]] = mapped_column(String(64), index=True, nullable=True)
    session_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("session.sessions.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )

    # Optional hash chaining for enterprise integrity
    record_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    prev_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    chain_id: Mapped[Optional[str]] = mapped_column(String(100), index=True, nullable=True)

    # Relationships
    user: Mapped[Optional["User"]] = relationship(
        "User",
        foreign_keys=[user_id],
        lazy="selectin",
    )
    session: Mapped[Optional["UserSession"]] = relationship(
        "UserSession",
        foreign_keys=[session_id],
        lazy="selectin",
    )


class AuditExportJob(Base):
    """
    Statutory audit log export task tracking (Annex B Line 171).
    Records generation parameters, row counts, and cryptographic checksums.
    """

    __tablename__ = "audit_export_jobs"
    __table_args__ = {"schema": "audit_trail"}

    id: Mapped[uuid_pk]
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        server_default=text("now()"),
        nullable=False,
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    requested_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("auth.users.id", ondelete="RESTRICT"),
        index=True,
        nullable=False,
    )
    file_format: Mapped[str] = mapped_column(String(10), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="PENDING", index=True, nullable=False)
    filter_criteria: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)
    total_rows: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    file_path: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    sha256_checksum: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    failure_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationship
    requester: Mapped["User"] = relationship(
        "User",
        foreign_keys=[requested_by],
        lazy="selectin",
    )


__all__ = [
    "AuditLog",
    "AuditExportJob",
]
