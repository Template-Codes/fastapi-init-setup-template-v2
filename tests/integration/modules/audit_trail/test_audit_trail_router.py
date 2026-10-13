from datetime import datetime, timedelta, timezone
import hashlib
import json
import uuid
import jwt
import pytest
from httpx import AsyncClient

from clients.redis import redis_async_client
from core.settings import settings
from modules.audit_trail.audit_trail_model import AuditExportJob, AuditLog
from modules.authentication.auth_model import User, UserStatus
from shares.enums import ActionName, AuditSeverity, RoleName
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
    res = await async_client.get("/api/private/admin/audit-trail/activity-logs")
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
        async_cache, user_id, session_id, token, roles=[RoleName.PUBLIC_USER.value]
    )

    headers = {"Authorization": f"Bearer {token}"}
    res = await async_client.get("/api/private/admin/audit-trail/activity-logs", headers=headers)
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
        async_cache, admin_id, session_id, token, roles=[RoleName.ADMIN.value]
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
    res = await async_client.get("/api/private/admin/audit-trail/activity-logs", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "pagination" in data
    assert len(data["items"]) >= 2
    item_ids = [item["id"] for item in data["items"]]
    assert str(log1.id) in item_ids
    assert str(log2.id) in item_ids

    # 2. Filter by action=CREATE
    res_filter_action = await async_client.get(
        "/api/private/admin/audit-trail/activity-logs?action=CREATE", headers=headers
    )
    assert res_filter_action.status_code == 200
    filtered_action_data = res_filter_action.json()
    action_item_ids = [item["id"] for item in filtered_action_data["items"]]
    assert str(log1.id) in action_item_ids
    assert str(log2.id) not in action_item_ids

    # 3. Filter by module=RBAC
    res_filter_module = await async_client.get(
        "/api/private/admin/audit-trail/activity-logs?module=RBAC", headers=headers
    )
    assert res_filter_module.status_code == 200
    filtered_module_data = res_filter_module.json()
    module_item_ids = [item["id"] for item in filtered_module_data["items"]]
    assert str(log2.id) in module_item_ids
    assert str(log1.id) not in module_item_ids


@pytest.mark.asyncio
async def test_audit_logs_dashboard_endpoint(
    async_client: AsyncClient, async_cache, db_session
):
    """Admin user can retrieve dashboard initial view with KPIs, filter options, and logs."""
    redis_async_client._redis = async_cache

    admin_id = uuid.uuid4()
    session_id = uuid.uuid4()
    token = _create_jwt_token(admin_id, session_id)
    await _setup_session_and_roles(
        async_cache, admin_id, session_id, token, roles=[RoleName.ADMIN.value]
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

    log = AuditLog(
        id=uuid.uuid4(),
        user_id=admin_id,
        action=ActionName.CREATE.value,
        module="SYSTEM",
        resource="ROLE",
        severity=AuditSeverity.CRITICAL,
    )
    db_session.add(log)
    await db_session.flush()

    res = await async_client.get("/api/private/admin/audit-trail/dashboard", headers=headers)
    assert res.status_code == 200
    data = res.json()

    assert "stats" in data
    assert data["stats"]["eventsLast24h"] >= 1
    assert data["stats"]["criticalEventsLast24h"] >= 1
    assert "filterOptions" in data
    assert len(data["filterOptions"]["modules"]) > 0
    assert len(data["filterOptions"]["severities"]) > 0
    assert "initialLogs" in data
    assert "pagination" in data["initialLogs"]


@pytest.mark.asyncio
async def test_audit_logs_advanced_filters_and_cursor_pagination(
    async_client: AsyncClient, async_cache, db_session
):
    """Admin user can search reason text, filter by actor and severity, and traverse cursors."""
    redis_async_client._redis = async_cache

    admin_id = uuid.uuid4()
    session_id = uuid.uuid4()
    token = _create_jwt_token(admin_id, session_id)
    await _setup_session_and_roles(
        async_cache, admin_id, session_id, token, roles=[RoleName.SUPER_ADMIN.value]
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

    now = datetime.now(timezone.utc)
    log_alpha = AuditLog(
        id=uuid.uuid4(),
        user_id=admin_id,
        user_code="EMP-100",
        username_snapshot="john_doe",
        action=ActionName.UPDATE.value,
        module="AUTHENTICATION",
        resource="USER",
        reason="Suspicious login reset password",
        severity=AuditSeverity.WARNING,
        created_at=now,
    )
    log_beta = AuditLog(
        id=uuid.uuid4(),
        user_id=admin_id,
        user_code="EMP-200",
        username_snapshot="jane_smith",
        action=ActionName.DELETE.value,
        module="SESSION",
        resource="SESSION",
        reason="Revoked inactive terminal",
        severity=AuditSeverity.INFO,
        created_at=now - timedelta(minutes=5),
    )
    db_session.add_all([log_alpha, log_beta])
    await db_session.flush()

    # 1. Reason substring search
    res_search = await async_client.get(
        "/api/private/admin/audit-trail/activity-logs?search=suspicious", headers=headers
    )
    assert res_search.status_code == 200
    search_items = res_search.json()["items"]
    assert len(search_items) >= 1
    assert any(item["id"] == str(log_alpha.id) for item in search_items)
    assert not any(item["id"] == str(log_beta.id) for item in search_items)

    # 2. Who filter: user_code and username
    res_who = await async_client.get(
        "/api/private/admin/audit-trail/activity-logs?user_code=EMP-100&username=john", headers=headers
    )
    assert res_who.status_code == 200
    who_items = res_who.json()["items"]
    assert any(item["id"] == str(log_alpha.id) for item in who_items)
    assert not any(item["id"] == str(log_beta.id) for item in who_items)

    # 3. Severity filter
    res_sev = await async_client.get(
        "/api/private/admin/audit-trail/activity-logs?severity=WARNING", headers=headers
    )
    assert res_sev.status_code == 200
    sev_items = res_sev.json()["items"]
    assert any(item["id"] == str(log_alpha.id) for item in sev_items)

    # 4. Cursor pagination traversal
    res_page1 = await async_client.get(
        "/api/private/admin/audit-trail/activity-logs?limit=1", headers=headers
    )
    assert res_page1.status_code == 200
    page1_data = res_page1.json()
    assert len(page1_data["items"]) == 1
    assert page1_data["pagination"]["hasMore"] is True
    next_cursor = page1_data["pagination"]["nextCursor"]
    assert next_cursor is not None

    res_page2 = await async_client.get(
        f"/api/private/admin/audit-trail/activity-logs?limit=1&cursor={next_cursor}", headers=headers
    )
    assert res_page2.status_code == 200
    page2_data = res_page2.json()
    assert len(page2_data["items"]) == 1
    assert page2_data["items"][0]["id"] != page1_data["items"][0]["id"]


@pytest.mark.asyncio
async def test_record_history_endpoint(
    async_client: AsyncClient, async_cache, db_session
):
    """Admin user can inspect chronological mutation lifecycle of a specific domain record."""
    redis_async_client._redis = async_cache

    admin_id = uuid.uuid4()
    session_id = uuid.uuid4()
    token = _create_jwt_token(admin_id, session_id)
    await _setup_session_and_roles(
        async_cache, admin_id, session_id, token, roles=[RoleName.ADMIN.value]
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

    target_table = "users"
    target_record_id = "target-user-999"

    log_entry1 = AuditLog(
        id=uuid.uuid4(),
        user_id=admin_id,
        target_table=target_table,
        target_id=target_record_id,
        target_code="USR-999",
        action=ActionName.CREATE.value,
        module="AUTHENTICATION",
        resource="USER",
        new_values={"status": "PENDING"},
        severity=AuditSeverity.INFO,
    )
    log_entry2 = AuditLog(
        id=uuid.uuid4(),
        user_id=admin_id,
        target_table=target_table,
        target_id=target_record_id,
        target_code="USR-999",
        action=ActionName.UPDATE.value,
        module="AUTHENTICATION",
        resource="USER",
        old_values={"status": "PENDING"},
        new_values={"status": "ACTIVE"},
        changed_fields=["status"],
        severity=AuditSeverity.INFO,
    )
    db_session.add_all([log_entry1, log_entry2])
    await db_session.flush()

    res = await async_client.get(
        f"/api/private/admin/audit-trail/records/{target_table}/{target_record_id}/history",
        headers=headers,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["targetTable"] == target_table
    assert data["targetId"] == target_record_id
    assert data["targetCode"] == "USR-999"
    assert len(data["history"]) >= 2
    history_ids = [item["id"] for item in data["history"]]
    assert str(log_entry1.id) in history_ids
    assert str(log_entry2.id) in history_ids


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
        async_cache, admin_id, session_id, token, roles=[RoleName.SUPER_ADMIN.value]
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
        f"/api/private/admin/audit-trail/activity-logs/{test_log.id}", headers=headers
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
        f"/api/private/admin/audit-trail/activity-logs/{non_existent_id}", headers=headers
    )
    assert res_404.status_code == 404
    assert res_404.json()["error"]["code"] == "AUDIT_LOG_NOT_FOUND"


@pytest.mark.asyncio
async def test_audit_log_detail_panel_endpoint(
    async_client: AsyncClient, async_cache, db_session
):
    """Admin user can retrieve deep detail panel view with execution context and before/after diff."""
    redis_async_client._redis = async_cache

    admin_id = uuid.uuid4()
    session_id = uuid.uuid4()
    token = _create_jwt_token(admin_id, session_id)
    await _setup_session_and_roles(
        async_cache, admin_id, session_id, token, roles=[RoleName.ADMIN.value]
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

    test_log = AuditLog(
        id=uuid.uuid4(),
        user_id=admin_id,
        user_code="EMP-100",
        username_snapshot="john_doe",
        action=ActionName.UPDATE.value,
        module="AUTHENTICATION",
        resource="USER",
        reason="Updated email and status",
        target_schema="auth",
        target_table="users",
        target_id="usr-555",
        target_code="USR-555",
        old_values={"email": "old@example.com", "status": "PENDING"},
        new_values={"email": "new@example.com", "status": "ACTIVE", "phone": "123456"},
        changed_fields=["email", "status", "phone"],
        is_reversal=False,
        context={"channel": "backoffice_ui"},
        ip_address="10.20.30.40",
        user_agent="Chrome/120.0",
        request_id="req-999-abc",
        severity=AuditSeverity.INFO,
    )
    db_session.add(test_log)
    await db_session.flush()

    res = await async_client.get(
        f"/api/private/admin/audit-trail/activity-logs/{test_log.id}/detail", headers=headers
    )
    assert res.status_code == 200
    data = res.json()

    assert data["id"] == str(test_log.id)
    assert data["operator"]["userCode"] == "EMP-100"
    assert data["context"]["ipAddress"] == "10.20.30.40"
    assert data["context"]["metadata"] == {"channel": "backoffice_ui"}
    assert data["diff"]["totalChanges"] == 3

    change_fields = [c["field"] for c in data["diff"]["changes"]]
    assert "email" in change_fields
    assert "status" in change_fields
    assert "phone" in change_fields


@pytest.mark.asyncio
async def test_audit_log_poll_endpoint(
    async_client: AsyncClient, async_cache, db_session
):
    """Admin user can perform head-check polling indicating new entries count since since_cursor."""
    redis_async_client._redis = async_cache

    admin_id = uuid.uuid4()
    session_id = uuid.uuid4()
    token = _create_jwt_token(admin_id, session_id)
    await _setup_session_and_roles(
        async_cache, admin_id, session_id, token, roles=[RoleName.ADMIN.value]
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

    now = datetime.now(timezone.utc)
    log_past = AuditLog(
        id=uuid.uuid4(),
        user_id=admin_id,
        action=ActionName.CREATE.value,
        module="SYSTEM",
        resource="ROLE",
        created_at=now - timedelta(hours=1),
        severity=AuditSeverity.INFO,
    )
    log_future = AuditLog(
        id=uuid.uuid4(),
        user_id=admin_id,
        action=ActionName.UPDATE.value,
        module="SYSTEM",
        resource="ROLE",
        created_at=now,
        severity=AuditSeverity.INFO,
    )
    db_session.add_all([log_past, log_future])
    await db_session.flush()

    # Encode cursor for log_past
    from modules.audit_trail.audit_trail_repository import encode_cursor
    past_cursor = encode_cursor(log_past.created_at, log_past.sequence_number)

    res = await async_client.get(
        f"/api/private/admin/audit-trail/poll-new-entries?since_cursor={past_cursor}", headers=headers
    )
    assert res.status_code == 200
    data = res.json()
    assert data["hasNewEntries"] is True
    assert data["newEntriesCount"] >= 1
    assert data["latestCursor"] is not None


@pytest.mark.asyncio
async def test_audit_log_export_csv_sync_endpoint(
    async_client: AsyncClient, async_cache, db_session
):
    """Admin user can trigger CSV export within required date range and receive streamed attachment."""
    redis_async_client._redis = async_cache

    admin_id = uuid.uuid4()
    session_id = uuid.uuid4()
    token = _create_jwt_token(admin_id, session_id)
    await _setup_session_and_roles(
        async_cache, admin_id, session_id, token, roles=[RoleName.ADMIN.value]
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

    now = datetime.now(timezone.utc)
    export_payload = {
        "dateFrom": (now - timedelta(days=7)).isoformat(),
        "dateTo": now.isoformat(),
        "fileFormat": "CSV",
        "module": "SYSTEM",
        "rowCap": 5000,
    }

    res = await async_client.post(
        "/api/private/admin/audit-trail/export-logs",
        json=export_payload,
        headers=headers,
    )
    assert res.status_code == 200
    assert "text/csv" in res.headers["content-type"]
    assert "attachment; filename=" in res.headers["content-disposition"]
    assert "id,created_at,sequence_number" in res.text


@pytest.mark.asyncio
async def test_audit_log_export_job_status_and_download(
    async_client: AsyncClient, async_cache, db_session, tmp_path
):
    """Admin user can inspect export job status and download completed artifact."""
    redis_async_client._redis = async_cache

    admin_id = uuid.uuid4()
    session_id = uuid.uuid4()
    token = _create_jwt_token(admin_id, session_id)
    await _setup_session_and_roles(
        async_cache, admin_id, session_id, token, roles=[RoleName.ADMIN.value]
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

    # Create dummy export file in tmp_path
    dummy_file = tmp_path / "test_audit_export.csv"
    dummy_file.write_text("id,action\n1,CREATE\n", encoding="utf-8")

    job = AuditExportJob(
        id=uuid.uuid4(),
        requested_by=admin_id,
        file_format="CSV",
        status="COMPLETED",
        filter_criteria={"module": "AUTHENTICATION"},
        total_rows=1,
        file_path=str(dummy_file),
        sha256_checksum="dummy_checksum_123",
    )
    db_session.add(job)
    await db_session.flush()

    # 1. Check job status
    status_res = await async_client.get(
        f"/api/private/admin/audit-trail/export-jobs/{job.id}",
        headers=headers,
    )
    assert status_res.status_code == 200
    status_data = status_res.json()
    assert status_data["jobId"] == str(job.id)
    assert status_data["status"] == "COMPLETED"
    assert status_data["downloadUrl"] == f"/api/private/admin/audit-trail/export-jobs/{job.id}/download"

    # 2. Download export file
    download_res = await async_client.get(
        f"/api/private/admin/audit-trail/export-jobs/{job.id}/download",
        headers=headers,
    )
    assert download_res.status_code == 200
    assert "text/csv" in download_res.headers["content-type"]
    assert "attachment; filename=" in download_res.headers["content-disposition"]
    assert "id,action" in download_res.text


