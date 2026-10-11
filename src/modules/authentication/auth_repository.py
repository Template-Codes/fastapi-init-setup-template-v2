from typing import List, Optional
from uuid import UUID

from db.db_session import get_async_db
from fastapi import Depends
from sqlalchemy import exists, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from loguru import logger

from base.repository import BaseRepository
from modules.authentication.auth_model import User, UserStatus
from modules.rbac.rbac_model import Role, UserRole
from exceptions.app_exception import InternalServerException


class AuthenticationRepository(BaseRepository[User]):
    """Repository for authentication operations.

    Using User model.
    """

    def __init__(
            self, 
            db: AsyncSession = Depends(get_async_db)
        ):
        super().__init__(db, User)
        
    
    async def get_user_by_username(self, username: str) -> Optional[User]:
        """Searcu user by username. Limit search by 1 only."""
        try:
            query = select(User).where(User.username == username).limit(1)
            result = await self.db.execute(query)
            return result.scalars().first()
        except Exception as e:
            logger.error(f"Error occurred while searching for username {username}: {e}")
            raise InternalServerException(
                message="Error occurred while searching for username.",
                error_code="USER_VALIDATION_FAILED"
            )


    async def get_user_by_user_code(self, user_code: str) -> Optional[User]:
        """Search user by human-facing user_code (case-insensitive). Limit 1."""
        try:
            query = select(User).where(func.upper(User.user_code) == user_code.upper().strip()).limit(1)
            result = await self.db.execute(query)
            return result.scalars().first()
        except Exception as e:
            logger.error(f"Error occurred while searching for user_code {user_code}: {e}")
            raise InternalServerException(
                message="Error occurred while searching for user code.",
                error_code="USER_VALIDATION_FAILED"
            )


    async def is_email_exists(self, email: str) -> bool:
        """Check if email is already registered in the table."""
        try:
            stmt = select(exists().where(User.email == email))
            result = await self.db.execute(stmt)
            return bool(result.scalar())
        except Exception as e:
            logger.error(f"Error occurred while searching for email {email}: {e}")
            raise InternalServerException(
                message="Failed to perform user validation check",
                error_code="USER_VALIDATION_FAILED"
            )

    async def get_pending_users(self) -> List[User]:
        """Fetch all user records currently in PENDING approval status."""
        try:
            stmt = select(User).where(User.status == UserStatus.PENDING).order_by(User.created_at.asc())
            result = await self.db.execute(stmt)
            return list(result.scalars().all())
        except Exception as e:
            logger.error(f"Error occurred while retrieving pending users: {e}")
            raise InternalServerException(
                message="Failed to retrieve pending users",
                error_code="PENDING_USERS_QUERY_FAILED"
            )

    async def assign_role_to_user(self, user_id: UUID, role_name: str) -> None:
        """Assign a named role to a user if not already granted."""
        try:
            role_stmt = select(Role).where(Role.name == role_name)
            role_res = await self.db.execute(role_stmt)
            role = role_res.scalars().first()
            if role:
                check_stmt = select(UserRole).where(UserRole.user_id == user_id, UserRole.role_id == role.id)
                check_res = await self.db.execute(check_stmt)
                if not check_res.scalars().first():
                    user_role = UserRole(user_id=user_id, role_id=role.id)
                    self.db.add(user_role)
                    await self.db.flush()
        except Exception as e:
            logger.error(f"Error assigning role '{role_name}' to user {user_id}: {e}")
            raise InternalServerException(
                message="Failed to assign role to user",
                error_code="ROLE_ASSIGNMENT_FAILED"
            )

