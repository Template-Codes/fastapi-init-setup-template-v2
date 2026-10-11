from datetime import datetime, timezone
from enum import Enum as PyEnum
from typing import TYPE_CHECKING, List, Optional
import uuid

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    JSON,
    String,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.base import Base, TimestampMixin, uuid_pk

if TYPE_CHECKING:
    from modules.authentication.auth_model import User


class Permission(Base, TimestampMixin):
    """Granular permission code definition (e.g. accounting:journal:post)."""

    __tablename__ = "permissions"
    __table_args__ = {"schema": "rbac"}

    id: Mapped[uuid_pk]
    code: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    module: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Many-to-Many: Permission <-> Role (via rbac.role_permissions junction table)
    roles: Mapped[List["Role"]] = relationship(
        "Role",
        secondary="rbac.role_permissions",
        back_populates="permissions",
    )


class RolePermission(Base, TimestampMixin):
    """Junction table mapping Roles to Permissions (Many-to-Many)."""

    __tablename__ = "role_permissions"
    __table_args__ = {"schema": "rbac"}

    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("rbac.roles.id", ondelete="CASCADE"),
        primary_key=True,
    )
    permission_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("rbac.permissions.id", ondelete="CASCADE"),
        primary_key=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class Role(Base, TimestampMixin):
    """User role holding a batch of permissions."""

    __tablename__ = "roles"
    __table_args__ = {"schema": "rbac"}

    id: Mapped[uuid_pk]
    name: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_system_role: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Many-to-Many: Role <-> Permission (via rbac.role_permissions junction table)
    permissions: Mapped[List[Permission]] = relationship(
        "Permission",
        secondary="rbac.role_permissions",
        back_populates="roles",
        lazy="selectin",
    )
    # Many-to-Many: Role <-> User (via rbac.user_roles junction table)
    users: Mapped[List["User"]] = relationship(
        "User",
        secondary="rbac.user_roles",
        back_populates="roles",
    )


class UserRole(Base, TimestampMixin):
    """Junction table mapping Users to Roles (Many-to-Many)."""

    __tablename__ = "user_roles"
    __table_args__ = {"schema": "rbac"}

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("rbac.roles.id", ondelete="CASCADE"),
        primary_key=True,
    )


class UserPermission(Base, TimestampMixin):
    """Direct user permission grants / denials (Many-to-Many)."""

    __tablename__ = "user_permissions"
    __table_args__ = {"schema": "rbac"}

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    permission_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("rbac.permissions.id", ondelete="CASCADE"),
        primary_key=True,
    )
    is_granted: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    assigned_by_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("auth.users.id", ondelete="SET NULL"),
        nullable=True,
    )
    reason: Mapped[str] = mapped_column(String(255), nullable=False)

    # Relationship to Permission model
    permission: Mapped[Permission] = relationship(
        "Permission",
        foreign_keys=[permission_id],
        lazy="selectin",
    )


class RBACChangeRequestStatus(str, PyEnum):
    """Status for dual-authorization RBAC change requests."""
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class RBACChangeRequest(Base, TimestampMixin):
    """Dual-authorization RBAC change request."""

    __tablename__ = "rbac_change_requests"
    __table_args__ = {"schema": "rbac"}

    id: Mapped[uuid_pk]
    request_type: Mapped[str] = mapped_column(String(50), nullable=False)  # ROLE_ASSIGNMENT, DIRECT_PERMISSION
    target_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=True,
    )
    target_role_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("rbac.roles.id", ondelete="CASCADE"),
        nullable=True,
    )
    requested_payload: Mapped[str] = mapped_column(String(2000), nullable=False)
    status: Mapped[RBACChangeRequestStatus] = mapped_column(
        Enum(RBACChangeRequestStatus, name="rbacchangerequeststatus", schema="rbac", native_enum=True),
        default=RBACChangeRequestStatus.PENDING,
        index=True,
        nullable=False,
    )
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    requested_by_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        nullable=False,
    )
    reviewed_by_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("auth.users.id", ondelete="SET NULL"),
        nullable=True,
    )
    review_notes: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class RolePermissionSnapshot(Base, TimestampMixin):
    """Immutable point-in-time snapshot of role permissions for audit and rollback."""

    __tablename__ = "role_permission_snapshots"
    __table_args__ = (
        Index("ix_rbac_role_snapshots_role_created", "role_id", "created_at"),
        {"schema": "rbac"},
    )

    id: Mapped[uuid_pk]
    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("rbac.roles.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    permissions_payload: Mapped[list] = mapped_column(
        JSON,
        nullable=False,
    )  # List of {"id": str, "code": str}
    changed_by_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("auth.users.id", ondelete="SET NULL"),
        nullable=True,
    )
    reason: Mapped[str] = mapped_column(String(255), nullable=False)

    # Relationships
    role: Mapped["Role"] = relationship("Role", foreign_keys=[role_id])
    changed_by: Mapped[Optional["User"]] = relationship("User", foreign_keys=[changed_by_id])


class UserRBACSnapshot(Base, TimestampMixin):
    """Immutable point-in-time snapshot of user roles, direct permissions, and effective permissions."""

    __tablename__ = "user_rbac_snapshots"
    __table_args__ = (
        Index("ix_rbac_user_snapshots_user_created", "user_id", "created_at"),
        {"schema": "rbac"},
    )

    id: Mapped[uuid_pk]
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("auth.users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    roles_payload: Mapped[list] = mapped_column(
        JSON,
        nullable=False,
    )  # List of {"id": str, "name": str, "rank": int}
    direct_permissions_payload: Mapped[list] = mapped_column(
        JSON,
        default=list,
        nullable=False,
    )  # List of {"id": str, "code": str, "is_granted": bool}
    effective_permissions_payload: Mapped[list] = mapped_column(
        JSON,
        nullable=False,
    )  # List of {"id": str, "code": str}
    changed_by_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("auth.users.id", ondelete="SET NULL"),
        nullable=True,
    )
    reason: Mapped[str] = mapped_column(String(255), nullable=False)

    # Relationships
    user: Mapped["User"] = relationship("User", foreign_keys=[user_id])
    changed_by: Mapped[Optional["User"]] = relationship("User", foreign_keys=[changed_by_id])

