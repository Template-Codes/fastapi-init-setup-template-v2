from datetime import datetime, timedelta, timezone
import hashlib
import json
import uuid
import jwt
import pytest
from httpx import AsyncClient

from clients.redis import redis_async_client
from core.settings import settings
from modules.audit_trail.audit_trail_model import AuditLog
from modules.authentication.auth_model import User, UserStatus
from shares.enums import ActionName, AuditSeverity
from utils.maintain_cache_key import MaintainCacheKeyUtils


def _create_jwt_token(user_id: uuid.UUID, session_id: uuid.UUID) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "sid": str(session_id),
        "type": "access-token",
        "exp": int((now + timedelta(hours=1)).timestamp()),
    }
    return jwt.encode(
        payload,
        key=str(settings.ACCESS_JWT_SECRET_KEY),
        algorithm=settings.JWT_ALGORITHM,
    )


async def _setup_session_and_roles(
    async_cache,
    user_id: uuid.UUID,
    session_id: uuid.UUID,
    token: str,
    roles: list[str],
) -> None:
    cache_utils = MaintainCacheKeyUtils(async_cache=async_cache)
    session_key = cache_utils.create_cache_key(
        session_id=str(session_id),
        user_id=str(user_id),
    )
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    session_payload = {
        "is_active": True,
        "user_status": "ACTIVE",
        "access_token_hash": token_hash,
    }
    await async_cache.set(session_key, json.dumps(session_payload), ex=3600)

    perm_key = cache_utils.create_user_permission_cache_key(str(user_id))
    perm_payload = {
        "user_id": str(user_id),
        "roles": roles,
        "permissions": [],
    }
    await async_cache.set(perm_key, json.dumps(perm_payload), ex=3600)


@pytest.mark.asyncio
async def test_audit_logs_unauthenticated_returns_401(async_client: AsyncClient):
    """Accessing admin audit logs without token must be rejected with 401."""
    res = await async_client.get("/api/private/admin/audit-logs")
    assert res.status_code == 401
    assert res.json()["error"]["code"] == "UNAUTHORIZED"


@pytest.mark.asyncio
async def test_audit_logs_forbidden_for_non_admin_user(
    async_client: AsyncClient, async_cache
):
    """Accessing admin audit logs with non-admin role must return 403 Forbidden."""
    redis_async_client._redis = async_cache

    user_id = uuid.uuid4()
    session_id = uuid.uuid4()
    token = _create_jwt_token(user_id, session_id)
    await _setup_session_and_roles(
        async_cache, user_id, session_id, token, roles=["PUBLIC_USER"]
    )

    headers = {"Authorization": f"Bearer {token}"}
    res = await async_client.get("/api/private/admin/audit-logs", headers=headers)
    assert res.status_code == 403
    assert res.json()["error"]["code"] == "ROLE_NOT_ASSIGNED"


@pytest.mark.asyncio
async def test_audit_logs_list_and_filter_success_for_admin(
    async_client: AsyncClient, async_cache, db_session
):
    """Admin user can list, paginate, and filter audit logs."""
    redis_async_client._redis = async_cache

    admin_id = uuid.uuid4()
    session_id = uuid.uuid4()
    token = _create_jwt_token(admin_id, session_id)
    await _setup_session_and_roles(
        async_cache, admin_id, session_id, token, roles=["ADMIN"]
    )

    headers = {"Authorization": f"Bearer {token}"}

    admin_user = User(
        id=admin_id,
        username=f"adm_{admin_id.hex[:6]}",
        email=f"adm_{admin_id.hex[:6]}@example.com",
        password_hash="dummy_hash",
        status=UserStatus.ACTIVE,
    )
    db_session.add(admin_user)

    # Seed 2 distinct audit logs
    log1 = AuditLog(
        id=uuid.uuid4(),
        user_id=admin_id,
        action=ActionName.CREATE.value,
        module="AUTHENTICATION",
        resource="REGISTRATION",
        reason="Registration created",
        target_id="user-123",
        severity=AuditSeverity.INFO,
    )
    log2 = AuditLog(
        id=uuid.uuid4(),
        user_id=admin_id,
        action=ActionName.UPDATE.value,
        module="RBAC",
        resource="ROLE",
        reason="Role updated",
        target_id="role-456",
        severity=AuditSeverity.WARNING,
    )
    db_session.add_all([log1, log2])
    await db_session.flush()

    # 1. List all logs without filter
    res = await async_client.get("/api/private/admin/audit-logs", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["totalCount"] >= 2
    assert len(data["items"]) >= 2
    item_ids = [item["id"] for item in data["items"]]
    assert str(log1.id) in item_ids
    assert str(log2.id) in item_ids

    # 2. Filter by action=CREATE
    res_filter_action = await async_client.get(
        "/api/private/admin/audit-logs?action=CREATE", headers=headers
    )
    assert res_filter_action.status_code == 200
    filtered_action_data = res_filter_action.json()
    action_item_ids = [item["id"] for item in filtered_action_data["items"]]
    assert str(log1.id) in action_item_ids
    assert str(log2.id) not in action_item_ids

    # 3. Filter by module=RBAC
    res_filter_module = await async_client.get(
        "/api/private/admin/audit-logs?module=RBAC", headers=headers
    )
    assert res_filter_module.status_code == 200
    filtered_module_data = res_filter_module.json()
    module_item_ids = [item["id"] for item in filtered_module_data["items"]]
    assert str(log2.id) in module_item_ids
    assert str(log1.id) not in module_item_ids


@pytest.mark.asyncio
async def test_audit_log_get_by_id_success_and_not_found(
    async_client: AsyncClient, async_cache, db_session
):
    """Admin user can fetch a single audit log by ID, or receive 404 if absent."""
    redis_async_client._redis = async_cache

    admin_id = uuid.uuid4()
    session_id = uuid.uuid4()
    token = _create_jwt_token(admin_id, session_id)
    await _setup_session_and_roles(
        async_cache, admin_id, session_id, token, roles=["SUPER_ADMIN"]
    )

    headers = {"Authorization": f"Bearer {token}"}

    admin_user = User(
        id=admin_id,
        username=f"sadmin_{admin_id.hex[:6]}",
        email=f"sadmin_{admin_id.hex[:6]}@example.com",
        password_hash="dummy_hash",
        status=UserStatus.ACTIVE,
    )
    db_session.add(admin_user)

    test_log = AuditLog(
        id=uuid.uuid4(),
        user_id=admin_id,
        action=ActionName.DELETE.value,
        module="RBAC",
        resource="ROLE",
        target_id="role-99",
        severity=AuditSeverity.WARNING,
    )
    db_session.add(test_log)
    await db_session.flush()

    # 1. Retrieve existing log
    res = await async_client.get(
        f"/api/private/admin/audit-logs/{test_log.id}", headers=headers
    )
    assert res.status_code == 200
    data = res.json()
    assert data["id"] == str(test_log.id)
    assert data["action"] == "DELETE"
    assert data["module"] == "RBAC"
    assert data["resource"] == "ROLE"

    # 2. Retrieve non-existent log -> 404
    non_existent_id = uuid.uuid4()
    res_404 = await async_client.get(
        f"/api/private/admin/audit-logs/{non_existent_id}", headers=headers
    )
    assert res_404.status_code == 404
    assert res_404.json()["error"]["code"] == "AUDIT_LOG_NOT_FOUND"
