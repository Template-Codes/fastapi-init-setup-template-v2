from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID

from db.db_session import get_async_db
from exceptions.app_exception import InternalServerException
from fastapi import Depends
from loguru import logger
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, selectinload

from base.repository import BaseRepository
from modules.authentication.auth_model import User
from modules.session.session_model import UserSession


class UserSessionRepository(BaseRepository[UserSession]):
    """Repository for user session. Mostly, CRUD operations.

    Using UserSession model.
    """

    def __init__(
            self, 
            db: AsyncSession = Depends(get_async_db)
        ):
        super().__init__(db, UserSession)
        
        
    async def deactivate_token(
        self, refresh_token_hash: str
    ) -> Optional[UserSession]:
        """Deactivates/revokes an active refresh token session and returns the updated record."""
        try:
            stmt = (
                update(UserSession)
                .where(
                    UserSession.refresh_token_hash == refresh_token_hash,
                    UserSession.is_active.is_(True),
                    UserSession.expires_at > datetime.now(timezone.utc),
                )
                .values(is_active=False)
                .returning(UserSession)
            )

            result = await self.db.execute(stmt)
            await self.db.commit()

            # Returns the updated UserSession instance, or None if no match was found/updated
            return result.scalar_one_or_none()

        except Exception as e:
            logger.error(
                f"Error deactivating session with token hash {refresh_token_hash}: {e}"
            )
            raise InternalServerException(
                message="Failed to update session status",
                error_code="SESSION_UPDATE_FAILED",
            )

    async def get_active_session_by_user_id(
        self, user_id: UUID
    ) -> Optional[UserSession]:
        """Fetch the most recent active, unexpired session for a user."""
        try:
            stmt = (
                select(UserSession)
                .where(
                    UserSession.user_id == user_id,
                    UserSession.is_active.is_(True),
                    UserSession.expires_at > datetime.now(timezone.utc),
                )
                .order_by(UserSession.last_active_at.desc())
                .limit(1)
            )
            result = await self.db.execute(stmt)
            return result.scalar_one_or_none()
        except Exception as e:
            logger.error(f"Error querying active session for user {user_id}: {e}")
            raise InternalServerException(
                message="Failed to retrieve active session status",
                error_code="SESSION_QUERY_FAILED",
            )

    async def deactivate_session_by_id(
        self, session_id: UUID
    ) -> Optional[UserSession]:
        """Deactivate an active session by its ID."""
        try:
            stmt = (
                update(UserSession)
                .where(
                    UserSession.id == session_id,
                    UserSession.is_active.is_(True),
                )
                .values(is_active=False)
                .returning(UserSession)
            )
            result = await self.db.execute(stmt)
            await self.db.commit()
            return result.scalar_one_or_none()
        except Exception as e:
            logger.error(f"Error deactivating session {session_id}: {e}")
            raise InternalServerException(
                message="Failed to update session status",
                error_code="SESSION_UPDATE_FAILED",
            )

    async def deactivate_all_active_by_user_id(
        self, user_id: UUID
    ) -> int:
        """Deactivate all active sessions for a given user UUID. Returns count of deactivated records."""
        try:
            stmt = (
                update(UserSession)
                .where(
                    UserSession.user_id == user_id,
                    UserSession.is_active.is_(True),
                )
                .values(is_active=False)
                .returning(UserSession.id)
            )
            result = await self.db.execute(stmt)
            await self.db.commit()
            deactivated_ids = result.scalars().all()
            return len(deactivated_ids)
        except Exception as e:
            logger.error(f"Error deactivating all active sessions for user {user_id}: {e}")
            raise InternalServerException(
                message="Failed to terminate user sessions",
                error_code="SESSION_UPDATE_FAILED",
            )

    async def deactivate_all_active_sessions(self) -> int:
        """Deactivate all active unexpired sessions enterprise-wide across all users."""
        try:
            stmt = (
                update(UserSession)
                .where(
                    UserSession.is_active.is_(True),
                    UserSession.expires_at > datetime.now(timezone.utc),
                )
                .values(is_active=False)
                .returning(UserSession.id)
            )
            result = await self.db.execute(stmt)
            await self.db.commit()
            deactivated_ids = result.scalars().all()
            return len(deactivated_ids)
        except Exception as e:
            logger.error(f"Error deactivating all enterprise sessions: {e}")
            raise InternalServerException(
                message="Failed to terminate enterprise sessions",
                error_code="SESSION_UPDATE_FAILED",
            )


    async def get_all_active_sessions_with_user_info(
        self,
    ) -> List[UserSession]:
        """Fetch all active sessions across all users, joined with user identity, roles, and profile."""
        try:
            stmt = (
                select(UserSession)
                .join(UserSession.user)
                .options(
                    joinedload(UserSession.user).joinedload(User.profile),
                    joinedload(UserSession.user).selectinload(User.roles),
                )
                .where(
                    UserSession.is_active.is_(True),
                    UserSession.expires_at > datetime.now(timezone.utc),
                )
                .order_by(UserSession.last_active_at.desc())
            )
            result = await self.db.execute(stmt)
            return list(result.scalars().unique().all())
        except Exception as e:
            logger.error(f"Error querying all active sessions with user info: {e}")
            raise InternalServerException(
                message="Failed to query active sessions",
                error_code="SESSION_QUERY_FAILED",
            )

            