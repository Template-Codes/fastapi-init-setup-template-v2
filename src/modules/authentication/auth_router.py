from typing import List, Optional
from uuid import UUID

from core.settings import settings
from dependencies.current_user import require_user_profile_and_get_id
from dependencies.rate_limit import rate_limit_by_ip
from dependencies.rbac_guard import require_role
from fastapi import APIRouter, Depends, Request, Response, status
from loguru import logger
from shares.enums import RoleName

from modules.authentication.auth_schema import (
    ApproveUserRequest,
    PendingUserResponse,
    RefreshAuthenticationTokensResponse,
    UserApprovalActionResponse,
    UserAuthenticationRequest,
    UserAuthenticationResponse,
    UserRegistrationRequest,
    UserRegistrationResponse,
)
from modules.authentication.auth_service import AuthenticationService


router = APIRouter(
    tags=[
        "Public: Register user, Authenticate User Grant JWT, JWTs and Revoke Old",
    ]
)

# User registration. Public access
@router.post(
    "/api/public/auth/registration",
    summary="User registration. Pending flag on success.",
    status_code=status.HTTP_201_CREATED,
    response_model=UserRegistrationResponse,
    dependencies=[Depends(rate_limit_by_ip())]
)
async def user_registration(
    user: UserRegistrationRequest,
    service: AuthenticationService = Depends()
):
    """Success registration status flag as PENDING for pooling."""
    logger.info("Accessing router for user registrations")
    return await service.register_user(user=user)


# User authentication. Public access
@router.post(
    "/api/public/auth/auth-tokens",
    summary="On success (HTTP 200 OK), grants access + refresh tokens.",
    status_code=status.HTTP_200_OK,
    response_model=UserAuthenticationResponse,
    dependencies=[Depends(rate_limit_by_ip())]
)
async def user_authentication(
    credential: UserAuthenticationRequest,
    request: Request,
    response: Response,
    service: AuthenticationService = Depends()
):
    logger.info("Accessing router for user authentication.")
    
    # Extract client IP (handling proxy X-Forwarded-For header)
    x_forwarded_for = request.headers.get("X-Forwarded-For")
    if x_forwarded_for:
        ip_address = x_forwarded_for.split(",")[0].strip()
    else:
        ip_address = request.client.host if request.client else None
        
    user_agent = request.headers.get("User-Agent")

    auth_response = await service.authenticate_user(
        credential=credential,
        ip_address=ip_address,
        user_agent=user_agent
    )

    # Attach HTTP-Only Cookies on response
    if auth_response and auth_response.auth_token_payload:
        is_secure = settings.COOKIE_SECURE if settings.ENVIRONMENT != "dev" else False
        
        if auth_response.auth_token_payload.access_token:
            response.set_cookie(
                key="access_token",
                value=auth_response.auth_token_payload.access_token,
                httponly=True,
                secure=is_secure,
                samesite=settings.COOKIE_SAMESITE,
                max_age=settings.ACCESS_JWT_EXPIRY_SEC,
                path="/"
            )
        if auth_response.auth_token_payload.refresh_token:
            response.set_cookie(
                key="refresh_token",
                value=auth_response.auth_token_payload.refresh_token,
                httponly=True,
                secure=is_secure,
                samesite=settings.COOKIE_SAMESITE,
                max_age=settings.REFRESH_JWT_EXPIRY_SEC,
                path="/api/public/auth"
            )

    return auth_response
    
    
@router.post(
    "/api/public/auth/refresh-token",
    summary="Extract refresh token in cookies, verify signature using secret key and generate new access-token.",
    status_code=status.HTTP_200_OK,
    response_model=RefreshAuthenticationTokensResponse,
    dependencies=[Depends(rate_limit_by_ip())]
)
async def refresh_tokens(
    request: Request,
    response: Response,
    service: AuthenticationService = Depends()
):
    logger.info("Requesting for new access token.")
    refresh_token = request.cookies.get("refresh_token")
    new_access_token = await service.refresh_authentication_tokens(refresh_token=refresh_token)
    
    if new_access_token and new_access_token.auth_token_payload:
        is_secure = settings.COOKIE_SECURE if settings.ENVIRONMENT != "dev" else False
        if new_access_token.auth_token_payload.access_token:
            response.set_cookie(
                key="access_token",
                value=new_access_token.auth_token_payload.access_token,
                httponly=True,
                secure=is_secure,
                samesite=settings.COOKIE_SAMESITE,
                max_age=settings.ACCESS_JWT_EXPIRY_SEC,
                path="/"
            )
        if new_access_token.auth_token_payload.refresh_token:
            response.set_cookie(
                key="refresh_token",
                value=new_access_token.auth_token_payload.refresh_token,
                httponly=True,
                secure=is_secure,
                samesite=settings.COOKIE_SAMESITE,
                max_age=settings.REFRESH_JWT_EXPIRY_SEC,
                path="/api/public/auth"
            )
            
    return new_access_token


# ======================================================================
# ADMINISTRATIVE USER APPROVAL ENDPOINTS (BIR ANNEX B ITEM 11.A)
# ======================================================================
@router.get(
    "/api/private/admin/users/pending",
    tags=["Administrative User Approvals"],
    summary="List all user registrations pending administrator approval.",
    status_code=status.HTTP_200_OK,
    response_model=List[PendingUserResponse],
    dependencies=[
        Depends(require_user_profile_and_get_id),
        Depends(require_role(RoleName.SUPER_ADMIN, RoleName.ADMIN)),
    ],
)
async def list_pending_user_registrations(
    service: AuthenticationService = Depends(),
):
    """Retrieve all user accounts in PENDING status awaiting vetting."""
    return await service.get_pending_registrations()


@router.post(
    "/api/private/admin/users/{user_id}/approve",
    tags=["Administrative User Approvals"],
    summary="Approve pending user registration and transition status to ACTIVE.",
    status_code=status.HTTP_200_OK,
    response_model=UserApprovalActionResponse,
    dependencies=[
        Depends(require_user_profile_and_get_id),
        Depends(require_role(RoleName.SUPER_ADMIN, RoleName.ADMIN)),
    ],
)
async def approve_user_registration(
    user_id: UUID,
    payload: Optional[ApproveUserRequest] = None,
    service: AuthenticationService = Depends(),
):
    """Approve a PENDING user, assigning an initial role (default: STAFF_USER) and marking account ACTIVE."""
    role_name = payload.role_name if payload and payload.role_name else "STAFF_USER"
    return await service.approve_user_registration(user_id=user_id, role_name=role_name)


@router.post(
    "/api/private/admin/users/{user_id}/reject",
    tags=["Administrative User Approvals"],
    summary="Reject pending user registration and transition status to INACTIVE.",
    status_code=status.HTTP_200_OK,
    response_model=UserApprovalActionResponse,
    dependencies=[
        Depends(require_user_profile_and_get_id),
        Depends(require_role(RoleName.SUPER_ADMIN, RoleName.ADMIN)),
    ],
)
async def reject_user_registration(
    user_id: UUID,
    service: AuthenticationService = Depends(),
):
    """Reject a PENDING user registration, marking the record INACTIVE for audit trail retention."""
    return await service.reject_user_registration(user_id=user_id)
