from datetime import datetime, timezone
from enum import Enum as PyEnum
from typing import TYPE_CHECKING, List, Optional
import uuid

from sqlalchemy import (
    DateTime,
    Enum,
    String,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.base import Base, TimestampMixin, uuid_pk
from modules.rbac.rbac_model import (
    Permission,
    RBACChangeRequest,
    RBACChangeRequestStatus,
    Role,
    RolePermission,
    UserPermission,
    UserRole,
)

if TYPE_CHECKING:
    from modules.profile.user_profile_model import UserProfile
    from modules.session.session_model import UserSession


class UserStatus(str, PyEnum):
    """User account lifecycle status."""
    PENDING = "PENDING"      # Registration submitted, awaiting approval
    ACTIVE = "ACTIVE"        # Normal active user
    INACTIVE = "INACTIVE"    # Deactivated account
    SUSPENDED = "SUSPENDED"  # Suspended due to security or administrative reasons


class User(Base, TimestampMixin):
    """Core identity and authentication record."""

    __tablename__ = "users"
    __table_args__ = {"schema": "auth"}

    id: Mapped[uuid_pk]
    user_code: Mapped[str] = mapped_column(
        String(20),
        unique=True,
        index=True,
        nullable=False,
        server_default=text("'USR-' || lpad(nextval('auth.user_code_seq')::text, 5, '0')"),
    )
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True, nullable=False)
    email: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[UserStatus] = mapped_column(
        Enum(UserStatus, native_enum=True),
        default=UserStatus.PENDING,
        index=True,
        nullable=False,
    )

    banned_until_time: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        default=None,
    )

    # Many-to-Many: User <-> Role (via rbac.user_roles junction table)
    roles: Mapped[List[Role]] = relationship(
        "Role",
        secondary="rbac.user_roles",
        back_populates="users",
        lazy="selectin",
    )
    # One-to-Many: User (1) -> UserSession (N)
    sessions: Mapped[List["UserSession"]] = relationship(
        "UserSession",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    # One-to-One: User (1) <-> UserProfile (1)
    profile: Mapped[Optional["UserProfile"]] = relationship(
        "UserProfile",
        back_populates="user",
        uselist=False,
        cascade="all, delete-orphan",
    )
    # One-to-Many: User (1) -> UserPermission (N)
    direct_permissions: Mapped[List[UserPermission]] = relationship(
        "UserPermission",
        foreign_keys="[UserPermission.user_id]",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


__all__ = [
    "UserStatus",
    "User",
    "Permission",
    "Role",
    "RolePermission",
    "UserRole",
    "UserPermission",
    "RBACChangeRequest",
    "RBACChangeRequestStatus",
]
