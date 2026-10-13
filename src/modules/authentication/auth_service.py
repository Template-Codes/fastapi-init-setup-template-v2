from datetime import datetime, timedelta, timezone
import hashlib
import json
from typing import Optional, Tuple
import uuid
from uuid import UUID

from core.settings import settings
from db.cache_session import get_async_cache
from fastapi import Depends
import jwt
from modules.authentication.auth_model import User, UserStatus
from modules.profile.user_profile_repository import UserProfileRepository
from modules.session.session_repo import UserSessionRepository
from sqlalchemy.exc import IntegrityError
from pwdlib import PasswordHash
from loguru import logger
from clients.postgresql import postgres_client_async_session
from sqlalchemy import update
from modules.session.session_model import UserSession
import redis.asyncio as aioredis
import asyncio

from modules.authentication.auth_schema import (
    AuthenticationTokenPayload,
    RefreshAuthenticationTokensResponse,
    UserAuthenticationRequest,
    UserAuthenticationResponse,
    UserRegistrationRequest,
    UserRegistrationResponse,
    PendingUserResponse,
    ApproveUserRequest,
    UserApprovalActionResponse,
)
from exceptions.app_exception import (
    AppException,
    BadRequestException,
    ConflictException,
    InternalServerException,
    NotFoundException,
    UnauthorizedException,
    ForbiddenException,
)
from modules.authentication.auth_repository import AuthenticationRepository
from modules.profile.user_profile_schema import UserProfileResponse
from utils.maintain_cache_key import MaintainCacheKeyUtils
from utils.schema_response import SchemaResponseDetails


class AuthenticationService:
    pwd_context = PasswordHash.recommended()

    def __init__(
            self, 
            auth_repo: AuthenticationRepository = Depends(),
            user_profile_repo: UserProfileRepository = Depends(),
            user_session_repo: UserSessionRepository = Depends(),
            async_cache: aioredis.Redis = Depends(get_async_cache),
            cache_utils: MaintainCacheKeyUtils = Depends()
        ):
        self._auth_repo = auth_repo
        self._user_profile_repo = user_profile_repo
        self._user_session_repo = user_session_repo
        self._async_cache = async_cache
        self._cache_utils = cache_utils

    # ======================================================================
    # USER REGISTRATION | PUBLIC ACCESS
    # ======================================================================
    async def register_user(
        self,
        user: UserRegistrationRequest
    ) -> UserRegistrationResponse:
        """Register user. Plain pass turn into one-way hash."""
        try:
            email = user.email.lower()  # lowercase email for standardization

            # validate if user exists by searching using its email
            is_user_exists = await self._auth_repo.is_email_exists(email)

            if is_user_exists:
                logger.warning(f"User already exists with email: {email}")
                raise ConflictException(
                    message="A user with this email is already registered",
                    error_code="EMAIL_ALREADY_EXISTS"
                )

            hashed_pwd = await asyncio.to_thread(self._hash_password, user.plain_password)
            user_dict = user.model_dump(exclude={"plain_password", "email"})
            user_dict["password_hash"] = hashed_pwd
            user_dict["email"] = email

            # status field auto PENDING by default
            new_user = await self._auth_repo.create(data=user_dict, commit=True)

            return UserRegistrationResponse(
                id=str(new_user.id),
                user_code=new_user.user_code,
                username=new_user.username,
                email=new_user.email,
                status=str(new_user.status.value) if hasattr(new_user.status, "value") else str(new_user.status),
                response_details=SchemaResponseDetails(
                    status=True,
                    description="User registered successfully. Wait for admin acceptance.",
                    count=1
                )
            )

        except AppException:
            # Let custom application exceptions propagate directly
            raise
        except IntegrityError as e:
            logger.warning(f"Database constraint violation: {e}")
            raise ConflictException(
                message="Username or email is already registered",
                error_code="CREDENTIALS_DUPLICATE"
            )
        except Exception as e:
            logger.exception(f"Unexpected error during user registration: {e}")
            raise InternalServerException(
                message="Failed to complete user registration",
                error_code="REGISTRATION_FAILED"
            )


    # ======================================================================
    # ADMIN USER APPROVAL WORKFLOW 
    # ======================================================================
    async def get_pending_registrations(self) -> list[PendingUserResponse]:
        """Fetch all registrations currently awaiting administrator approval."""
        users = await self._auth_repo.get_pending_users()
        return [
            PendingUserResponse(
                id=u.id,
                user_code=u.user_code,
                username=u.username,
                email=u.email,
                status=str(u.status.value) if hasattr(u.status, "value") else str(u.status),
                created_at=u.created_at,
            )
            for u in users
        ]

    async def approve_user_registration(
        self, user_id: UUID, role_name: str | None = "STAFF_USER"
    ) -> UserApprovalActionResponse:
        """Approves a PENDING user registration and transitions status to ACTIVE with assigned role."""
        user = await self._auth_repo.get_by_id(user_id)
        if not user:
            logger.warning(f"User {user_id} not found for approval.")
            raise NotFoundException(message="User not found.")

        if user.status != UserStatus.PENDING:
            logger.warning(f"User {user_id} is in status {user.status}, cannot approve.")
            raise BadRequestException(message=f"User is already in {user.status} status.")

        user.status = UserStatus.ACTIVE
        if role_name:
            await self._auth_repo.assign_role_to_user(user_id=user.id, role_name=role_name)
        await self._auth_repo.db.commit()

        logger.info(f"User {user.username} ({user_id}) approved and activated with role {role_name}.")
        return UserApprovalActionResponse(
            status=True,
            description=f"User {user.username} approved successfully and status set to ACTIVE.",
            user_id=user.id,
            user_code=user.user_code,
            user_status="ACTIVE",
        )

    async def reject_user_registration(self, user_id: UUID) -> UserApprovalActionResponse:
        """Rejects a PENDING user registration and transitions status to INACTIVE."""
        user = await self._auth_repo.get_by_id(user_id)
        if not user:
            logger.warning(f"User {user_id} not found for rejection.")
            raise NotFoundException(message="User not found.")

        if user.status != UserStatus.PENDING:
            logger.warning(f"User {user_id} is in status {user.status}, cannot reject.")
            raise BadRequestException(message=f"User is already in {user.status} status.")

        user.status = UserStatus.INACTIVE
        await self._auth_repo.db.commit()

        logger.info(f"User {user.username} ({user_id}) registration rejected and set to INACTIVE.")
        return UserApprovalActionResponse(
            status=True,
            description=f"User {user.username} registration rejected and status set to INACTIVE.",
            user_id=user.id,
            user_code=user.user_code,
            user_status="INACTIVE",
        )


    # ======================================================================
    # USER AUTHENTICATION FOR ACCESS & REFRESH TOKENS
    # ======================================================================
    async def authenticate_user(
        self,
        credential: UserAuthenticationRequest,
        ip_address: str | None = None,
        user_agent: str | None = None
    ) -> Optional[UserAuthenticationResponse]:
        """
        Verify user credentials
        Verify user authentication 
        Increase failed_login_attempt_cnt in redis within 5 mins window for failed attempt
        Ban account on 5 consecutive failed attempts within 5 mins window
        On success,
            - reset failed_login_attempt_cnt in redis to 0
            - reset banned_until_time to None
            - store in cache user payload including role permissions
            - grant the user authentication tokens
            - save login in sessions table
        Returns UserAuthenticationResponse
        """
        try:
            # get individual payload data
            username = credential.username
            plain_password = credential.plain_password
            
            # get user data by username
            user: User = await self._auth_repo.get_user_by_username(username)
            
            if user is None:
                logger.warning(f"User by username: {username} not found.")
                raise UnauthorizedException(
                    message="Invalid username or password. Please try again."
                )
                
            # == PRE-AUTHENTICATION BRUTE-FORCE LOCKOUT CHECK ==
            ip = ip_address or "unknown_ip"
            is_blocked = await self._cache_utils.is_ip_user_blocked(ip, username)
            if is_blocked:
                logger.warning(f"Blocked login attempt from IP {ip} for username {username}.")
                raise UnauthorizedException(
                    message="Invalid username or password. Please try again."
                )

            # == ACCOUNT STATUS VERIFICATION ==
            now = datetime.now(timezone.utc)
            if user.banned_until_time:
                if now < user.banned_until_time:
                    logger.warning(f"Blocked login attempt for admin-banned user {user.id}.")
                    raise ForbiddenException(
                        message="Account is not in active status. Contact the administrator to activate your account."
                    )
                else:
                    user.banned_until_time = None
                    if user.status == UserStatus.SUSPENDED:
                        user.status = UserStatus.ACTIVE
                    await self._auth_repo.db.commit()

            if user.status != UserStatus.ACTIVE:
                logger.warning(f"User {username} not in active status (status: {user.status}).")
                raise ForbiddenException(
                    message="Account is not in active status. Contact the administrator to activate your account."
                )
            
            # == USER CREDENTIAL VALIDATION ==
            is_pwd_match = await asyncio.to_thread(
                self._verify_password,
                plain_password,
                user.password_hash
            )

            if not is_pwd_match:
                logger.warning(f"Password mismatch for username {username} from IP {ip}.")
                await self._cache_utils.record_failed_login(ip, username)
                raise UnauthorizedException(
                    message="Invalid username or password. Please try again."
                )
                
            # ON SUCCESSFUL LOGIN -> CLEAR REDIS FAILED LOGIN STATE
            await self._cache_utils.clear_failed_login(ip, username)
                
            # == SEARCH USER PROFILE FIRST == 
            user_id: UUID = user.id
            user_profile = await self._user_profile_repo.get_by_id(user_id)
            user_profile_payload: Optional[UserProfileResponse] = None
            is_profile_completed: bool = user_profile is not None
            
            if not is_profile_completed:
                logger.info(f"No user profile yet for user {user_id}. Redirect to set user profile endpoint.")
            else:
                user_profile_payload = UserProfileResponse.model_validate(user_profile)
            

            # == GENERATE AUTHENTICATION TOKENS ==
            logger.info("Generation of access and refresh tokens...")
            new_session_id = uuid.uuid4()
            access_token, refresh_token, refresh_token_exp = self._generate_session_tokens(
                now=now, user_id=str(user_id), session_id=str(new_session_id)
            )
            
            user_status_str = str(user.status.value) if hasattr(user.status, "value") else str(user.status)
            
            # hash tokens.
            refresh_token_hash = hashlib.sha256(refresh_token.encode("utf-8")).hexdigest()
            access_token_hash = hashlib.sha256(access_token.encode("utf-8")).hexdigest()
            session_payload = self._build_session_payload(
                session_id=new_session_id,
                user_id=user_id,
                refresh_token_hash=refresh_token_hash,
                access_token_hash=access_token_hash,
                is_active=True,
                user_status=user_status_str,
                is_profile_completed=is_profile_completed,
                ip_address=ip_address,
                user_agent=user_agent,
                expires_at=refresh_token_exp,
                last_active_at=now,
                last_db_synced_at=now
            )
            
            # store hashed token to postgres
            logger.info("Storing hashed token and session to postgres.")
            db_session_data = {
                "id": new_session_id,
                "user_id": user_id,
                "refresh_token_hash": refresh_token_hash,
                "is_active": True,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "expires_at": refresh_token_exp,
                "last_active_at": now
            }
            new_session = await self._user_session_repo.create(data=db_session_data, commit=True)
            
            # check if successfully committed
            if new_session is None:
                logger.error("User session failed to commit.")
                raise ConflictException(
                    message="User session failed to commit"
                )
            
            # == STORE ACCESS TOKEN IN CACHE ==
            # create cache session key and name
            session_cache_key = self._cache_utils.create_cache_key(
                str(new_session.id), str(user_id)
            )
            session_cache_name = self._cache_utils.create_cache_name(
                str(user_id)
            )
            
            logger.info(f"Caching session for session ID: {new_session.id}")
            await self._session_cache_life_cycle(
                intent="create", key=session_cache_key,
                name=session_cache_name, payload=session_payload
            )
            
            await self._cache_utils.profile_completion_cache(
                user_id=user_id, 
                is_profile_completed=is_profile_completed
            )

            logger.info("Returning all data...")
            return UserAuthenticationResponse(
                session_id=str(new_session.id),
                user_id=str(user_id),
                user_code=user.user_code,
                username=username,
                email=user.email,
                status=str(user.status.value) if hasattr(user.status, "value") else str(user.status),
                is_profile_completed=is_profile_completed,
                auth_token_payload=AuthenticationTokenPayload(
                    # raw tokens
                    access_token=access_token,
                    refresh_token=refresh_token
                ),
                user_profile_payload=user_profile_payload,
                response_details=SchemaResponseDetails(
                    status=True,
                    description="User authenticated successfully.", 
                    count=1
                )
            )
        except AppException:
            raise
        except Exception as e:
            logger.exception(f"Unexpected error during user authentication: {e}")
            raise InternalServerException(
                message="Unexpected error during user authentication."
            )


    # ======================================================================
    # REFRESH TOKENS (RTR + 5-MIN THROTTLED DB SYNC)
    # ======================================================================
    async def refresh_authentication_tokens(
        self, refresh_token: str | None
    ) -> Optional[RefreshAuthenticationTokensResponse]:
        if not refresh_token:
            logger.warning("Refresh token is missing from request.")
            raise UnauthorizedException(message="Invalid or expired session. Please log in again.")

        try:
            # == VERIFY TOKEN SIGNATURE ==
            payload = jwt.decode(
                refresh_token,
                str(settings.REFRESH_JWT_SECRET_KEY),
                algorithms=[settings.JWT_ALGORITHM]
            )
            
            if payload.get("type") != "refresh-token":
                logger.warning(f"Invalid token type: {payload.get('type')}")
                raise UnauthorizedException(
                    message="Invalid or expired session. Please log in again."
                )
            
            # == EXTRACT TOKEN PAYLOAD ==                
            user_id = payload.get("sub")
            session_id = payload.get("sid")
            exp_timestamp = payload.get("exp")
            now = datetime.now(timezone.utc)
            
            if not user_id or not session_id or not exp_timestamp:
                raise UnauthorizedException(message="Invalid or expired session. Please log in again.")

            if int(now.timestamp()) > exp_timestamp:
                logger.warning("Refresh token is already expired.")
                raise UnauthorizedException(message="Invalid or expired session. Please log in again.")

            incoming_token_hash = hashlib.sha256(refresh_token.encode("utf-8")).hexdigest()

            # == INITIALIZE CACHE KEY & NAME ==
            key = self._cache_utils.create_cache_key(session_id=str(session_id), user_id=str(user_id))
            name = self._cache_utils.create_cache_name(str(user_id))
            
            # == 1. SINGLE-AUTHORITATIVE REDIS CACHE VERIFICATION (FAST-PATH) ==
            cached_session_raw = await self._async_cache.get(key)
            session_payload: dict = {}
            
            if cached_session_raw is not None:
                try:
                    session_payload = json.loads(cached_session_raw)
                except Exception:
                    session_payload = {}
            
            # Fast-path: Redis cache hit & session is active (Zero DB queries!)
            if session_payload and session_payload.get("is_active") is True:
                cached_hash = session_payload.get("refresh_token_hash")
                
                # == TOKEN REUSE / THEFT DETECTION ==
                if cached_hash != incoming_token_hash:
                    logger.warning(f"Token reuse detected for session {session_id}! Immediate revocation.")
                    await self._invalidate_refresh_token_request(
                        session_id=str(session_id), key=key, name=name
                    )

                # == GENERATE ROTATED TOKENS (RTR) ==
                new_access_token, new_refresh_token, _ = self._generate_session_tokens(
                    now=now, user_id=str(user_id), session_id=str(session_id)
                )
                
                new_refresh_hash = hashlib.sha256(new_refresh_token.encode("utf-8")).hexdigest()
                new_access_hash = hashlib.sha256(new_access_token.encode("utf-8")).hexdigest()

                # Update Redis payload
                session_payload["refresh_token_hash"] = new_refresh_hash
                session_payload["access_token_hash"] = new_access_hash
                session_payload["last_active_at"] = now.isoformat()
                session_payload["last_db_synced_at"] = now.isoformat()
                
                # Always dispatch non-blocking background task to sync new rotated token hash to DB
                asyncio.create_task(
                    self._sync_session_rotation_db(
                        session_id=str(session_id),
                        new_refresh_token_hash=new_refresh_hash,
                        last_active_at=now
                    )
                )

                # Write rotated payload to Redis
                await self._session_cache_life_cycle(
                    intent="create", key=key, name=name, payload=session_payload
                )

                return RefreshAuthenticationTokensResponse(
                    auth_token_payload=AuthenticationTokenPayload(
                        # raw tokens
                        access_token=new_access_token,
                        refresh_token=new_refresh_token
                    ),
                    response_details=SchemaResponseDetails(
                        status=True,
                        description="Request for new access token successful.",
                        count=1
                    )
                )
            
            # == 2. REDIS CACHE MISS / FALLBACK TO DATABASE ==
            logger.info(f"Redis cache miss/eviction for session {session_id}. Falling back to DB.")
            try:
                session_uuid = UUID(str(session_id))
            except ValueError:
                raise UnauthorizedException(message="Invalid session ID format.")

            user_session = await self._user_session_repo.get_by_id(session_uuid)
            if user_session is None or not user_session.is_active:
                logger.warning(f"Session {session_id} is inactive or not found in DB.")
                await self._invalidate_refresh_token_request(
                    session_id=str(session_id), key=key, name=name
                )

            # Check DB hash matching for token reuse
            if user_session.refresh_token_hash != incoming_token_hash:
                logger.warning(f"Token reuse detected in DB fallback for session {session_id}!")
                await self._invalidate_refresh_token_request(
                    session_id=str(session_id), key=key, name=name
                )

            # Generate rotated tokens
            new_access_token, new_refresh_token, _ = self._generate_session_tokens(
                now=now, user_id=str(user_id), session_id=str(session_id)
            )
            new_refresh_hash = hashlib.sha256(new_refresh_token.encode("utf-8")).hexdigest()
            new_access_hash = hashlib.sha256(new_access_token.encode("utf-8")).hexdigest()

            # Update DB immediately on cache miss recovery
            user_session.refresh_token_hash = new_refresh_hash
            user_session.last_active_at = now
            await self._user_session_repo.db.commit()

            # Re-warm Redis cache
            session_payload = self._build_session_payload(
                session_id=str(user_session.id),
                user_id=str(user_session.user_id),
                refresh_token_hash=new_refresh_hash,
                access_token_hash=new_access_hash,
                is_active=user_session.is_active,
                user_status="ACTIVE",
                is_profile_completed=True,
                ip_address=user_session.ip_address,
                user_agent=user_session.user_agent,
                expires_at=user_session.expires_at,
                last_active_at=now,
                last_db_synced_at=now
            )
            
            await self._session_cache_life_cycle(
                intent="create", key=key, name=name, payload=session_payload
            )

            return RefreshAuthenticationTokensResponse(
                auth_token_payload=AuthenticationTokenPayload(
                    # raw tokens
                    access_token=new_access_token,
                    refresh_token=new_refresh_token
                ),
                response_details=SchemaResponseDetails(
                    status=True,
                    description="Request for new access token successful.",
                    count=1
                )
            )
        except jwt.PyJWTError as e:
            logger.warning(f"Refresh token JWT verification failed: {e}")
            raise UnauthorizedException(message="Invalid or expired session. Please log in again.")
        except AppException:
            raise
        except Exception as e:
            logger.exception(f"Unexpected error during access token refresh: {e}")
            raise InternalServerException(
                message="Unexpected error during access token refresh."
            )
    
    
    # ======================================================================
    # HELPER METHODS
    # ======================================================================
    def _generate_session_tokens(
        self, now: datetime, user_id: str, session_id: str    
    ) -> Tuple[str, str, datetime]:
        access_token_exp = now + timedelta(seconds=settings.ACCESS_JWT_EXPIRY_SEC)
        refresh_token_exp = now + timedelta(seconds=settings.REFRESH_JWT_EXPIRY_SEC)
        
        new_access_token = self._generate_access_tokens(
            sub=user_id, sid=session_id, 
            iat=now, token_exp=access_token_exp
        )
        
        new_refresh_token = self._generate_refresh_token(
            sub=user_id, sid=session_id, 
            iat=now, token_exp=refresh_token_exp
        )
        return new_access_token, new_refresh_token, refresh_token_exp
    
    def _build_session_payload(
        self,
        session_id: UUID | str,
        user_id: UUID | str,
        refresh_token_hash: str,
        access_token_hash: str,
        is_active: bool,
        user_status: str,
        is_profile_completed: bool,
        ip_address: str | None,
        user_agent: str | None,
        expires_at: datetime | str,
        last_active_at: datetime | str,
        last_db_synced_at: datetime | str | None = None
    ) -> dict[str, any]:
        return {
            "id": str(session_id),
            "user_id": str(user_id),
            "refresh_token_hash": refresh_token_hash,
            "access_token_hash": access_token_hash,
            "is_active": is_active,
            "user_status": str(user_status),
            "is_profile_completed": is_profile_completed,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "expires_at": expires_at.isoformat() if isinstance(expires_at, datetime) else str(expires_at),
            "last_active_at": last_active_at.isoformat() if isinstance(last_active_at, datetime) else str(last_active_at),
            "last_db_synced_at": last_db_synced_at.isoformat() if isinstance(last_db_synced_at, datetime) else (str(last_db_synced_at) if last_db_synced_at else last_active_at.isoformat() if isinstance(last_active_at, datetime) else str(last_active_at))
        }

    async def _invalidate_refresh_token_request(
        self, session_id: str, key: str, name: str
    ):
        session_uuid = UUID(session_id)
        
        # == IMMEDIATE DB COMMIT ON REVOCATION BY SESSION ID ==
        try:
            async with postgres_client_async_session() as db_session:
                stmt = (
                    update(UserSession)
                    .where(UserSession.id == session_uuid)
                    .values(is_active=False)
                )
                await db_session.execute(stmt)
                await db_session.commit()
        except Exception as e:
            logger.error(f"Error deactivating session {session_id} in DB: {e}")
        
        # delete in cache
        await self._session_cache_life_cycle(
            intent="delete", payload=None,
            key=key, name=name
        )

        raise UnauthorizedException(
            message="Invalid or expired session. Please log in again."
        )

    async def _sync_session_rotation_db(self, session_id: str, new_refresh_token_hash: str, last_active_at: datetime):
        """Asynchronously updates refresh_token_hash and last_active_at in DB in background using dedicated session."""
        try:
            session_uuid = UUID(session_id)
            async with postgres_client_async_session() as db_session:
                stmt = (
                    update(UserSession)
                    .where(UserSession.id == session_uuid, UserSession.is_active.is_(True))
                    .values(
                        refresh_token_hash=new_refresh_token_hash,
                        last_active_at=last_active_at
                    )
                )
                await db_session.execute(stmt)
                await db_session.commit()
        except Exception as e:
            logger.warning(f"Failed background DB sync for session {session_id}: {e}")

    def _generate_access_tokens(self, sub: str, sid: UUID, iat: datetime, token_exp: datetime) -> str:
        """Generate short lived token."""        
        payload = {
            "sub": sub, "sid": str(sid), "iat": int(iat.timestamp()),
            "type": "access-token", "exp": int(token_exp.timestamp())
        }
        
        encoded_jwt = jwt.encode(
            payload=payload,
            key=str(settings.ACCESS_JWT_SECRET_KEY),
            algorithm=settings.JWT_ALGORITHM
        )
        
        return encoded_jwt
    
    def _generate_refresh_token(self, sub: str, sid: UUID, iat: datetime, token_exp: datetime) -> str:
        """Generate long live token."""
        payload = {
            "sub": sub, "sid": str(sid), "iat": int(iat.timestamp()),
            "type": "refresh-token", "exp": int(token_exp.timestamp())
        }
        
        encoded_jwt = jwt.encode(
            payload=payload,
            key=str(settings.REFRESH_JWT_SECRET_KEY),
            algorithm=settings.JWT_ALGORITHM
        )
        
        return encoded_jwt

    def _hash_password(self, plain_password: str) -> str:
        """Hash plain text password using pwdlib (Argon2id)."""
        logger.info("Hashing plain text password.")
        return self.pwd_context.hash(plain_password)

    def _verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify plain text password against hash using pwdlib."""
        return self.pwd_context.verify(plain_password, hashed_password)


    async def verify_admin_user_credential(self, user_id: UUID, username: str, plain_password: str) -> bool:
        """Verifies that the provided plain password matches the user's password hash in DB."""
        user = await self._auth_repo.get_by_id(user_id)
        if not user or not user.password_hash:
            logger.error(f"User {user_id} not found or no password hash.")
            return False

        if username != user.username:
            logger.warning(f"Invalid username for user {user_id}. Username: {username}, Expected: {user.username}")
            return False
        
        return await asyncio.to_thread(self._verify_password, plain_password, user.password_hash)


    async def _session_cache_life_cycle(
        self, key: str, name: str, 
        payload: dict[str, any] | None = None, intent: str = "create"
    ):
        try:
            if intent.lower().strip() == "create" and payload is not None:
                serializable_payload = json.dumps(payload, default=str)
                await asyncio.gather(
                    # write cache payload with valid kwargs ex and name
                    self._async_cache.set(
                        name=key, value=serializable_payload, ex=settings.REFRESH_JWT_EXPIRY_SEC
                    ),
                    # set cache name to target all cached record at once
                    self._async_cache.sadd(name, key)
                )
            else:
                await asyncio.gather(
                    # delete cached payload using key
                    self._async_cache.delete(key),
                    # delete cached name using name & key
                    self._async_cache.srem(name, key)
                )
        except Exception as e:
            logger.warning(f"Redis session cache operation ({intent}) failed: {e}")
