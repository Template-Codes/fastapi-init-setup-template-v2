import uuid
import pytest
from httpx import AsyncClient
from core.settings import settings
from modules.authentication.auth_model import User, UserStatus
from modules.authentication.auth_service import AuthenticationService

pwd_context = AuthenticationService.pwd_context


@pytest.mark.asyncio
async def test_user_registration_endpoint_missing_secret_header(async_client: AsyncClient):
    """Test POST /api/public/auth/registration fails without valid secret header."""
    payload = {
        "username": "unauth_user",
        "email": "unauth@example.com",
        "plainPassword": "Password123!"
    }
    response = await async_client.post("/api/public/auth/register", json=payload)
    assert response.status_code == 401
    data = response.json()
    assert data["error"]["code"] == "UNAUTHORIZED"


@pytest.mark.asyncio
async def test_user_registration_endpoint_success(async_client: AsyncClient):
    """Test successful user registration via POST /api/public/auth/registration against real DB."""
    unique_id = uuid.uuid4().hex[:8]
    username = f"usr_{unique_id}"
    email = f"user_{unique_id}@example.com"

    headers = {settings.SECRET_HEADER_NAME: settings.SECRET_HEADER_VALUE}
    payload = {
        "username": username,
        "email": email,
        "plainPassword": "Password123!"
    }

    response = await async_client.post(
        "/api/public/auth/register",
        json=payload,
        headers=headers
    )
    assert response.status_code == 201
    data = response.json()

    assert data["username"] == username
    assert data["email"] == email
    assert data["status"] == "PENDING"
    assert data["id"] is not None
    assert data["responseDetails"]["status"] is True


@pytest.mark.asyncio
async def test_user_authentication_and_token_refresh_integration(async_client: AsyncClient, db_session):
    """Integration test: Register active user, authenticate for cookies, refresh access token, and detect token reuse."""
    unique_id = uuid.uuid4().hex[:8]
    username = f"active_{unique_id}"
    email = f"active_{unique_id}@example.com"
    plain_password = "Password123!"

    # 1. Create active user directly in PostgreSQL
    active_user = User(
        username=username,
        email=email,
        password_hash=pwd_context.hash(plain_password),
        status=UserStatus.ACTIVE,
        banned_until_time=None,
    )
    db_session.add(active_user)
    await db_session.flush()

    headers = {settings.SECRET_HEADER_NAME: settings.SECRET_HEADER_VALUE}

    # 2. Authenticate user via POST /api/public/auth/login
    login_payload = {
        "username": username,
        "plainPassword": plain_password
    }
    auth_res = await async_client.post(
        "/api/public/auth/login",
        json=login_payload,
        headers=headers
    )
    assert auth_res.status_code == 200
    auth_data = auth_res.json()
    assert auth_data["username"] == username
    assert auth_data["status"] == "ACTIVE"

    cookies = auth_res.cookies
    assert "access_token" in cookies
    assert "refresh_token" in cookies

    old_refresh_token = cookies["refresh_token"]

    # 3. Refresh access token using granted refresh_token cookie via POST /api/public/auth/refresh-token
    refresh_res = await async_client.post(
        "/api/public/auth/refresh-token",
        headers=headers
    )

    assert refresh_res.status_code == 200
    refresh_data = refresh_res.json()
    assert "authTokenPayload" in refresh_data
    assert "accessToken" in refresh_data["authTokenPayload"]
    assert "refreshToken" in refresh_data["authTokenPayload"]
    assert refresh_res.cookies.get("access_token") is not None
    assert refresh_res.cookies.get("refresh_token") is not None

    # 4. Attempt to reuse old_refresh_token (Token reuse detection -> triggers session revocation -> returns 401)
    async_client.cookies.clear()
    async_client.cookies.set("refresh_token", old_refresh_token, domain="test", path="/api/public/auth")

    reuse_res = await async_client.post(
        "/api/public/auth/refresh-token",
        headers=headers
    )
    assert reuse_res.status_code == 401
    reuse_data = reuse_res.json()
    assert reuse_data["description"] == "Invalid or expired session. Please log in again."
