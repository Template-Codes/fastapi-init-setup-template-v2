from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
import uuid
import pytest

from exceptions.app_exception import NotFoundException
from modules.audit_trail.audit_trail_model import AuditLog
from modules.audit_trail.audit_trail_schema import AuditLogQueryFilter
from modules.audit_trail.audit_trail_service import AuditTrailService
from shares.enums import ActionName, AuditSeverity, ModuleName, ResourceName


@pytest.fixture
def mock_audit_repo():
    return AsyncMock()


@pytest.fixture
def audit_service(mock_audit_repo):
    return AuditTrailService(audit_repo=mock_audit_repo)


@pytest.mark.asyncio
async def test_log_success(audit_service, mock_audit_repo):
    """Test successful creation of an audit log entry."""
    log_id = uuid.uuid4()
    mock_log = MagicMock(spec=AuditLog)
    mock_log.id = log_id
    mock_audit_repo.create_log.return_value = mock_log

    user_id = uuid.uuid4()
    result = await audit_service.log(
        action=ActionName.CREATE,
        resource=ResourceName.USER,
        module=ModuleName.AUTHENTICATION,
        user_id=user_id,
        target_id="USR-12345",
        reason="Admin created user",
        severity=AuditSeverity.INFO,
    )

    assert result == mock_log
    mock_audit_repo.create_log.assert_awaited_once()
    call_args = mock_audit_repo.create_log.call_args[0][0]
    assert call_args["action"] == "CREATE"
    assert call_args["resource"] == "USER"
    assert call_args["module"] == "AUTHENTICATION"
    assert call_args["user_id"] == user_id
    assert call_args["reason"] == "Admin created user"


@pytest.mark.asyncio
async def test_log_handles_exception_gracefully(audit_service, mock_audit_repo):
    """Test that audit log failure does not propagate exceptions or break callers."""
    mock_audit_repo.create_log.side_effect = Exception("DB connection dropped")

    result = await audit_service.log(
        action=ActionName.UPDATE,
        resource=ResourceName.ROLE,
        reason="Attempting log during failure",
    )

    assert result is None
    mock_audit_repo.create_log.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_logs_success(audit_service, mock_audit_repo):
    """Test paginated retrieval of audit logs."""
    log_1 = MagicMock(
        spec=AuditLog,
        id=uuid.uuid4(),
        created_at=datetime.now(timezone.utc),
        sequence_number=1,
        user_id=uuid.uuid4(),
        user_code="USR-00001",
        username_snapshot="admin",
        severity=AuditSeverity.INFO,
        module="SYSTEM",
        resource="ROLE",
        action="CREATE",
        reason="Created role",
        target_schema=None,
        target_table="roles",
        target_id="1",
        target_code="ADMIN",
        old_values=None,
        new_values=None,
        changed_fields=None,
        is_reversal=False,
        reversal_for_id=None,
        context=None,
        ip_address="127.0.0.1",
        user_agent="Mozilla",
        request_id="req-123",
        session_id=None,
    )
    mock_audit_repo.query_logs.return_value = ([log_1], 1)

    filter_params = AuditLogQueryFilter(page=1, limit=10, module="SYSTEM")
    res = await audit_service.get_logs(filter_params)

    assert res.total_count == 1
    assert len(res.items) == 1
    assert res.items[0].id == log_1.id
    assert res.items[0].action == "CREATE"


@pytest.mark.asyncio
async def test_get_log_by_id_success(audit_service, mock_audit_repo):
    """Test retrieving single audit log by UUID."""
    log_id = uuid.uuid4()
    mock_log = MagicMock(
        spec=AuditLog,
        id=log_id,
        created_at=datetime.now(timezone.utc),
        sequence_number=10,
        user_id=None,
        user_code=None,
        username_snapshot=None,
        severity=AuditSeverity.WARNING,
        module="AUTHENTICATION",
        resource="USER",
        action="LOGIN",
        reason=None,
        target_schema=None,
        target_table=None,
        target_id=None,
        target_code=None,
        old_values=None,
        new_values=None,
        changed_fields=None,
        is_reversal=False,
        reversal_for_id=None,
        context=None,
        ip_address="10.0.0.1",
        user_agent="Postman",
        request_id="req-abc",
        session_id=None,
    )
    mock_audit_repo.get_by_id.return_value = mock_log

    result = await audit_service.get_log_by_id(log_id)
    assert result.id == log_id
    assert result.severity == AuditSeverity.WARNING
    assert result.action == "LOGIN"


@pytest.mark.asyncio
async def test_get_log_by_id_not_found_raises_404(audit_service, mock_audit_repo):
    """Test that requesting non-existent audit log raises 404 NotFoundException."""
    mock_audit_repo.get_by_id.return_value = None
    random_id = uuid.uuid4()

    with pytest.raises(NotFoundException) as exc_info:
        await audit_service.get_log_by_id(random_id)

    assert exc_info.value.status_code == 404
    assert exc_info.value.error_code == "AUDIT_LOG_NOT_FOUND"


@pytest.mark.asyncio
async def test_get_logs_cursor_success(audit_service, mock_audit_repo):
    """Test cursor-based retrieval of audit logs and canonical URL generation."""
    log_id = uuid.uuid4()
    mock_log = MagicMock(
        spec=AuditLog,
        id=log_id,
        created_at=datetime.now(timezone.utc),
        sequence_number=101,
        user_id=uuid.uuid4(),
        user_code="USR-0001",
        username_snapshot="operator",
        severity=AuditSeverity.INFO,
        module="SYSTEM",
        resource="ROLE",
        action="UPDATE",
        reason="Updated role permission",
        target_schema=None,
        target_table="roles",
        target_id="role-1",
        target_code="ROLE_ADMIN",
        old_values={"is_active": True},
        new_values={"is_active": False},
        changed_fields=["is_active"],
        is_reversal=False,
        reversal_for_id=None,
        context=None,
        ip_address="127.0.0.1",
        user_agent="Postman",
        request_id="req-123",
        session_id=None,
    )
    mock_audit_repo.query_logs_cursor.return_value = ([mock_log], True, "mock_cursor_token")

    filter_params = AuditLogQueryFilter(limit=10, module="SYSTEM", action="UPDATE")
    res = await audit_service.get_logs_cursor(filter_params)

    assert len(res.items) == 1
    assert res.items[0].id == log_id
    assert res.pagination.has_more is True
    assert res.pagination.next_cursor == "mock_cursor_token"
    assert "limit=10" in res.pagination.canonical_url
    assert "cursor=mock_cursor_token" in res.pagination.next_url


@pytest.mark.asyncio
async def test_get_dashboard_data_success(audit_service, mock_audit_repo):
    """Test dashboard data assembly with aggregates, filter options, and initial logs."""
    mock_audit_repo.get_dashboard_aggregates.return_value = {
        "events_last_24h": 42,
        "critical_events_last_24h": 2,
        "error_events_last_24h": 5,
    }
    mock_audit_repo.query_logs_cursor.return_value = ([], False, None)

    dashboard = await audit_service.get_dashboard_data()

    assert dashboard.stats.events_last_24h == 42
    assert dashboard.stats.critical_events_last_24h == 2
    assert dashboard.stats.error_events_last_24h == 5
    assert len(dashboard.filter_options.modules) > 0
    assert len(dashboard.filter_options.severities) > 0
    assert len(dashboard.filter_options.actions) > 0
    assert len(dashboard.filter_options.resources) > 0
    assert dashboard.initial_logs.pagination.has_more is False


@pytest.mark.asyncio
async def test_get_record_history_success(audit_service, mock_audit_repo):
    """Test retrieving chronological history for a specific record."""
    log_id = uuid.uuid4()
    mock_log = MagicMock(
        spec=AuditLog,
        id=log_id,
        created_at=datetime.now(timezone.utc),
        sequence_number=1,
        user_id=uuid.uuid4(),
        user_code="ADM-01",
        username_snapshot="admin",
        severity=AuditSeverity.WARNING,
        module="RBAC",
        resource="ROLE",
        action="UPDATE",
        reason="Revoked role",
        target_schema=None,
        target_table="roles",
        target_id="role-xyz",
        target_code="ROLE_XYZ",
        old_values=None,
        new_values=None,
        changed_fields=None,
        is_reversal=False,
        reversal_for_id=None,
        context=None,
        ip_address=None,
        user_agent=None,
        request_id=None,
        session_id=None,
    )
    mock_audit_repo.query_record_history.return_value = ([mock_log], False, None)

    history = await audit_service.get_record_history(
        target_table="roles",
        target_id="role-xyz",
        limit=10,
    )

    assert history.target_table == "roles"
    assert history.target_id == "role-xyz"
    assert history.target_code == "ROLE_XYZ"
    assert len(history.history) == 1
    assert history.history[0].id == log_id

