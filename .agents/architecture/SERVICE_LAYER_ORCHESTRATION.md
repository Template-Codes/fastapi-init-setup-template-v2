# Service Layer & Domain Orchestration Standards

This document establishes architectural standards for the Service Layer across the XCOM ERP backend. The Service Layer acts as the central business coordinator, enforcing domain invariants, managing cross-repository workflows, and maintaining thin, decoupled routers.

---

## 1. Architectural Boundary Separation

The backend follows a strict 3-tier separation of concerns:

```
┌────────────────────────┐  HTTP Request / Response, Cookies, Status Codes, Dependency Injection
│      Router Layer      │  (Thin controller: parameter unpacking & calling service ONLY)
└───────────┬────────────┘
            │ calls
            ▼
┌────────────────────────┐  Business Invariants, Cross-Repo Workflows, Calculations,
│     Service Layer      │  Cache Management, DTO/Schema Mapping, Domain Exceptions
└───────────┬────────────┘
            │ calls
            ▼
┌────────────────────────┐  Direct CRUD & ORM Queries (SQLAlchemy 2.0 select/insert/update/delete)
│    Repository Layer    │  (Zero business logic, isolated by entity schema)
└────────────────────────┘
```

---

## 2. Thin Router Rules

Routers are strictly protocol adapters (HTTP entrypoints). A router MUST NEVER:
- ❌ Access `AsyncSession` directly or construct SQL / SQLAlchemy queries.
- ❌ Import or instantiate database models directly for business logic.
- ❌ Perform multi-repository coordination or transactional sequences.
- ❌ Compute domain rules, tax breakdowns, discount totals, or password hashing.

### Router Responsibilities:
1. Parse HTTP headers, route parameters, cookies, and request bodies via Pydantic.
2. Inject services and auth guards (`service: MyService = Depends()`).
3. Set HTTP cookies / headers on the response when needed (e.g., JWT cookies).
4. Return the typed Pydantic response model with an explicit HTTP status code.

---

## 3. Service Layer Responsibilities

Service classes encapsulate all core business logic and cross-domain orchestration.

### A. Cross-Repository Orchestration
Services coordinate multiple repositories to execute atomic business processes (e.g., creating an invoice, generating general ledger entries, and deducting inventory stock):

```python
class AccountingService:
    def __init__(
        self,
        invoice_repo: InvoiceRepository = Depends(),
        journal_repo: JournalRepository = Depends(),
        inventory_repo: InventoryRepository = Depends(),
        async_cache: aioredis.Redis = Depends(get_async_cache),
    ):
        self._invoice_repo = invoice_repo
        self._journal_repo = journal_repo
        self._inventory_repo = inventory_repo
        self._cache = async_cache
```

### B. Business Invariants & Calculations
All domain math and state validations belong in the service layer:
- Calculating tax splits, volume discount deductions, and currency conversions.
- Validating state transitions (e.g., `DRAFT` ➔ `POSTED`, checking that `POSTED` entries cannot be mutated).
- Hashing passwords and evaluating cryptographic tokens.

### C. Cache & Side-Effect Coordination
- Managing Redis session keys, rate limit quotas, and distributed locks.
- Triggering secondary tasks (e.g., asynchronous event notifications, audit log dispatch).

### D. DTO / Schema Transformations
- Convert incoming Pydantic request models into domain dictionaries / model instances.
- Transform internal ORM entities and join results into typed Pydantic response schemas (`ResponseModel.model_validate(entity)`).

---

## 4. Transaction Boundaries & Atomicity

When a service operation modifies multiple repositories or tables, atomicity must be preserved:

- **Implicit Transaction (Single Repo)**: Rely on `BaseRepository` methods (`create`, `update`, `delete`) with `commit=True` or session autoflush.
- **Cross-Repository Unit of Work**: Wrap multi-step mutations within an atomic transaction block using `async with db.begin():` or passing the shared session context across participating repositories.
- **Rollback on Error**: Ensure any domain failure triggers a full rollback and releases acquired locks/caches cleanly.

---

## 5. Domain Exception Handling

Services must catch lower-level infrastructure failures (e.g., `IntegrityError`, connection timeouts) and translate them into domain-specific `AppException` types:

```python
try:
    return await self._invoice_repo.create(invoice_dict)
except IntegrityError as exc:
    logger.error(f"Database constraint violation on invoice creation: {exc}")
    raise ConflictException(
        message="An invoice with this serial number already exists.",
        error_code="DUPLICATE_INVOICE_NUMBER",
    )
```

**Never let raw ORM or database exceptions bubble directly to the client.**
