from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock
import uuid
import pytest

from exceptions.app_exception import NotFoundException
from modules.audit_trail.audit_trail_model import AuditLog
from modules.audit_trail.audit_trail_schema import (
    AuditLogExportRequest,
    AuditLogPollQuery,
    AuditLogQueryFilter,
    ChangeTypeEnum,
    ExportFormatEnum,
)
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


@pytest.mark.asyncio
async def test_get_log_detail_success_with_diff(audit_service, mock_audit_repo):
    """Test detail panel retrieval with context and field-by-field before/after diff."""
    log_id = uuid.uuid4()
    mock_log = MagicMock(
        spec=AuditLog,
        id=log_id,
        created_at=datetime.now(timezone.utc),
        sequence_number=50,
        user_id=uuid.uuid4(),
        user_code="EMP-01",
        username_snapshot="john_doe",
        severity=AuditSeverity.WARNING,
        module="AUTHENTICATION",
        resource="USER",
        action="UPDATE",
        reason="Suspended inactive user",
        target_schema="auth",
        target_table="users",
        target_id="usr-123",
        target_code="USR-123",
        old_values={"status": "ACTIVE", "role": "USER"},
        new_values={"status": "SUSPENDED", "phone": "123456"},
        changed_fields=["status"],
        is_reversal=False,
        reversal_for_id=None,
        context={"client": "web"},
        ip_address="192.168.1.1",
        user_agent="Firefox",
        request_id="req-999",
        session_id=None,
    )
    mock_audit_repo.get_by_id.return_value = mock_log

    detail = await audit_service.get_log_detail(log_id)

    assert detail.id == log_id
    assert detail.operator.user_code == "EMP-01"
    assert detail.target_entity.target_table == "users"
    assert detail.context.ip_address == "192.168.1.1"

    # Verify diff items
    diff_map = {item.field: item for item in detail.diff.changes}
    assert diff_map["status"].change_type == ChangeTypeEnum.MODIFIED
    assert diff_map["status"].old_value == "ACTIVE"
    assert diff_map["status"].new_value == "SUSPENDED"

    assert diff_map["phone"].change_type == ChangeTypeEnum.ADDED
    assert diff_map["phone"].old_value is None
    assert diff_map["phone"].new_value == "123456"

    assert diff_map["role"].change_type == ChangeTypeEnum.REMOVED
    assert diff_map["role"].old_value == "USER"
    assert diff_map["role"].new_value is None


@pytest.mark.asyncio
async def test_poll_new_entries_success(audit_service, mock_audit_repo):
    """Test polling head check indicates new entries count and latest cursor."""
    now = datetime.now(timezone.utc)
    mock_audit_repo.count_new_entries_since.return_value = (5, "latest_cursor_abc", now)

    query = AuditLogPollQuery(since_cursor="old_cursor_xyz", module="AUTHENTICATION")
    res = await audit_service.poll_new_entries(query)

    assert res.has_new_entries is True
    assert res.new_entries_count == 5
    assert res.latest_cursor == "latest_cursor_abc"
    assert res.latest_created_at == now


@pytest.mark.asyncio
async def test_create_export_direct_streaming_under_threshold(audit_service, mock_audit_repo):
    """Test that export matching <= 1,000 rows streams CSV/Excel directly and logs audit event."""
    mock_audit_repo.count_logs_for_export.return_value = 50
    mock_log = MagicMock(
        spec=AuditLog,
        id=uuid.uuid4(),
        created_at=datetime.now(timezone.utc),
        sequence_number=1,
        severity=AuditSeverity.INFO,
        module="SYSTEM",
        resource="ROLE",
        action="CREATE",
        reason="Test export",
        user_id=None,
        user_code=None,
        username_snapshot=None,
        target_table=None,
        target_id=None,
        target_code=None,
        is_reversal=False,
        ip_address=None,
    )
    mock_audit_repo.query_logs_for_export.return_value = [mock_log]

    now = datetime.now(timezone.utc)
    export_req = AuditLogExportRequest(
        date_from=now - timedelta(days=5),
        date_to=now,
        file_format=ExportFormatEnum.CSV,
    )

    admin_id = uuid.uuid4()
    async_res, content, filename, content_type = await audit_service.create_export(
        export_req=export_req,
        current_user_id=admin_id,
        current_user_code="ADM-01",
    )

    assert async_res is None
    assert content is not None
    assert "text/csv" in content_type
    assert filename.startswith("audit_logs_")
    assert filename.endswith(".csv")

    # Verify audit log was created for the export
    mock_audit_repo.create_log.assert_awaited()
    audit_call = mock_audit_repo.create_log.call_args[0][0]
    assert audit_call["action"] == "EXPORT"
    assert audit_call["resource"] == "EXPORT_JOB"


@pytest.mark.asyncio
async def test_create_export_async_job_above_threshold(audit_service, mock_audit_repo):
    """Test that export matching > 1,000 rows registers an AuditExportJob and returns 202 response."""
    mock_audit_repo.count_logs_for_export.return_value = 2500
    job_id = uuid.uuid4()
    mock_job = MagicMock(
        id=job_id,
        status="PENDING",
        requested_at=datetime.now(timezone.utc),
    )
    mock_audit_repo.create_export_job.return_value = mock_job

    now = datetime.now(timezone.utc)
    export_req = AuditLogExportRequest(
        date_from=now - timedelta(days=10),
        date_to=now,
        file_format=ExportFormatEnum.EXCEL,
    )

    admin_id = uuid.uuid4()
    async_res, content, filename, content_type = await audit_service.create_export(
        export_req=export_req,
        current_user_id=admin_id,
        current_user_code="ADM-01",
    )

    assert async_res is not None
    assert async_res.is_async is True
    assert async_res.job_id == job_id
    assert async_res.total_rows_estimated == 2500
    assert content is None


