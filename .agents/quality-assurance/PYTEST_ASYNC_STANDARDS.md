# Pytest Async & Quality Assurance Standards

This document establishes the testing architecture, fixture conventions, transaction rollback isolation, and edge-case testing standards for the XCOM ERP test suite.

---

## 1. Directory Structure (`tests/` Mirror Pattern)

The test suite strictly mirrors the `src/` directory tree:

```
tests/
├── conftest.py                  # Global async fixtures, DB/Redis setup, client overrides
├── unit/                        # Fast, isolated tests using AsyncMock / MagicMock
│   ├── core/
│   ├── dependencies/
│   ├── exceptions/
│   ├── middlewares/
│   ├── modules/<domain>/        # e.g., test_<domain>_service.py, test_<domain>_schema.py
│   └── utils/
└── integration/                 # End-to-end API tests with real test DB & Redis
    └── modules/<domain>/        # e.g., test_<domain>_api.py
```

---

## 2. Test Execution & Configuration

- **Runner**: Always execute tests via `uv run pytest`.
- **Environment**: `pytest_configure` automatically forces `ENVIRONMENT="test"`.
- **Async Mode**: Configured with `asyncio_mode = "auto"` in `pyproject.toml`. Use `async def test_*` freely with `@pytest.mark.asyncio`.

---

## 3. Core Fixtures & Transaction Rollback Isolation

Global fixtures in `tests/conftest.py` ensure 100% test isolation:

- **`prepare_test_database` (session autouse)**: Creates required PostgreSQL schemas (`auth`, `profile`, `session`, `eis`, `accounting`) and runs `Base.metadata.create_all`.
- **`db_session` (function scope)**: Opens a connection on `TEST_DATABASE_URL`, begins a transaction, and **always rolls back on teardown**:
```python
@pytest_asyncio.fixture
async def db_session():
    async with engine.connect() as connection:
        transaction = await connection.begin()
        session_factory = async_sessionmaker(connection, class_=AsyncSession, expire_on_commit=False)
        session = session_factory()
        try:
            yield session
        finally:
            await session.close()
            if transaction.is_active:
                await transaction.rollback()
```
- **`async_cache`**: Connects to `TEST_REDIS_URL` and flushes/closes on cleanup.
- **`async_client`**: Provides `httpx.AsyncClient` with `ASGITransport(app=app)` and overrides `get_async_db` and `get_async_cache`.

---

## 4. Unit Testing & Mock Fixtures

Unit tests must be blazing fast and completely decoupled from external services:
- Mock repositories and cache using `unittest.mock.AsyncMock` (for `async def` methods) and `MagicMock` (for sync helpers).
- Inject mocks directly into service constructors:
```python
@pytest.mark.asyncio
async def test_service_method():
    mock_repo = AsyncMock()
    mock_repo.is_email_exists.return_value = False
    mock_cache = AsyncMock()

    service = MyService(repo=mock_repo, cache=mock_cache)
    result = await service.do_action()
    assert result.status == "SUCCESS"
    mock_repo.create.assert_awaited_once()
```

---

## 5. Mandatory Edge Case & Negative Testing

Every test suite must comprehensively cover failure modes and edge cases:
1. **Validation & Boundaries**: Empty strings, max string lengths, malformed UUIDs/TINs, negative monetary amounts, zero-divisions.
2. **Security & Auth**: Expired JWT tokens, missing Bearer headers, invalid signatures, locked-out accounts.
3. **Database Collisions**: Duplicate email/username `ConflictException`, missing foreign keys, integrity errors.
4. **Regulatory/BIR Invariants**: Mixed-tax VAT math mismatches, missing 5-digit branch code padding, attempts to mutate `POSTED` invoices.
