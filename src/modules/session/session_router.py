from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response, status
from loguru import logger

from dependencies.credential_guard import require_sudo_credential
from dependencies.rbac_guard import require_role
from modules.session.session_schema import (
    AdminUserSessionListItemResponse,
    SessionLogoutResponse,
)
from modules.session.session_service import SessionService
from shares.enums import RoleName


router = APIRouter(
    tags=["Session Management & Administrative Overrides"],
)


@router.post(
    "/api/private/session/logout",
    summary="Log out of the current active session and clear HTTP-Only cookies.",
    status_code=status.HTTP_200_OK,
    response_model=SessionLogoutResponse,
)
async def logout_current_session(
    request: Request,
    response: Response,
    service: SessionService = Depends(),
):
    """Gracefully ends the calling user's active session and purges auth cookies."""
    user_id: UUID = getattr(request.state, "user_id", None)
    session_id: UUID = getattr(request.state, "session_id", None)

    logout_res = await service.logout_own_session(user_id=user_id, session_id=session_id)

    # Clear authentication cookies
    response.delete_cookie(key="access_token", path="/")
    response.delete_cookie(key="refresh_token", path="/api/public/auth")

    return logout_res


@router.get(
    "/api/private/admin/sessions",
    summary="List all active sessions across all users with identity telemetry (Admin only).",
    status_code=status.HTTP_200_OK,
    response_model=List[AdminUserSessionListItemResponse],
    dependencies=[Depends(require_role(RoleName.SUPER_ADMIN, RoleName.ADMIN))],
)
async def get_all_active_sessions(
    service: SessionService = Depends(),
):
    """Retrieve all active terminal sessions enterprise-wide for administrative monitoring and auditing."""
    return await service.get_all_active_sessions()



@router.delete(
    "/api/private/admin/sessions/{session_id}",
    summary="Admin force-logout a specific session by its UUID.",
    status_code=status.HTTP_200_OK,
    response_model=SessionLogoutResponse,
    dependencies=[Depends(require_role(RoleName.SUPER_ADMIN, RoleName.ADMIN))],
)
async def admin_logout_session_by_id(
    session_id: UUID,
    service: SessionService = Depends(),
):
    """Force-terminates a specific active session. Target terminal is immediately revoked."""
    return await service.admin_force_logout_by_session_id(session_id=session_id)


@router.post(
    "/api/private/admin/sessions/terminate-all",
    summary="Admin emergency mass termination of ALL active sessions enterprise-wide (Requires password re-entry).",
    status_code=status.HTTP_200_OK,
    response_model=SessionLogoutResponse,
    dependencies=[
        Depends(require_role(RoleName.SUPER_ADMIN, RoleName.ADMIN)),
        Depends(require_sudo_credential),
    ],
)
async def admin_logout_all_sessions(
    service: SessionService = Depends(),
):
    """Emergency mass-terminates ALL active sessions enterprise-wide across all terminals with step-up admin verification."""
    return await service.admin_force_logout_all_sessions()
