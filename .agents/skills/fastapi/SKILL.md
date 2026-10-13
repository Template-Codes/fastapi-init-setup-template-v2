# FastAPI Asynchronous & Architecture Standards

This document establishes the mandatory standards for route structuring, asynchronous I/O, lifespan management, HTTP status handling, and dependency injection across the XCOM ERP backend.

---

## 1. Route Structuring & API Architecture

### Directory & File Conventions
- Every domain module lives under `src/modules/<module_name>/`.
- Route definitions must reside in `<module_name>_router.py`.
- Routers must be registered in `src/main.py` using `app.include_router(router)`.

### Router Configuration
- Instantiate `APIRouter` with explicit OpenAPI `tags` and optional `prefix`:
```python
from fastapi import APIRouter, Depends, status

router = APIRouter(
    prefix="/api/v1/invoices",
    tags=["Accounting: Invoices"],
)
```

### Route Endpoint Standards
- Every route decorator MUST define:
  1. `summary`: Concise human-readable description of what the endpoint does.
  2. `status_code`: Explicit `status.HTTP_*` constant from `fastapi.status`.
  3. `response_model`: Pydantic schema for output serialization and OpenAPI schema generation.
  4. `dependencies`: Router-level or endpoint-level guards (rate limiters, permission checkers).

```python
@router.post(
    "",
    summary="Create and record a new sales invoice",
    status_code=status.HTTP_201_CREATED,
    response_model=SalesInvoiceResponse,
    dependencies=[Depends(rate_limit_by_ip())],
)
async def create_invoice(
    payload: CreateSalesInvoiceRequest,
    current_user_id: UUID = Depends(get_current_user_id),
    service: InvoiceService = Depends(),
) -> SalesInvoiceResponse:
    return await service.create_invoice(payload=payload, user_id=current_user_id)
```

---

## 2. Non-Blocking Asynchronous I/O Invariants

### 100% Async Endpoints & Services
- **All** endpoint functions, service methods, and repository operations must be defined with `async def`.
- Always `await` asynchronous database queries, cache calls, and network requests.

### Zero Blocking Calls on Event Loop
- ❌ **NEVER** use `time.sleep()`. Use `await asyncio.sleep()`.
- ❌ **NEVER** use synchronous `requests` or `urllib`. Use `httpx.AsyncClient`.
- ❌ **NEVER** use blocking synchronous file I/O or drivers in route handlers.
- ❌ **NEVER** use synchronous SQLAlchemy queries (e.g. `session.query()`).

### CPU-Bound Task Offloading
Heavy computational operations (e.g., pandas financial aggregations, ReportLab PDF generation, openpyxl exports) block the single-threaded event loop. Always offload them using `asyncio.to_thread`:

```python
import asyncio

# Offload synchronous/heavy CPU-bound work
pdf_bytes = await asyncio.to_thread(generate_invoice_pdf, invoice_data)
```

---

## 3. Lifespan Context Manager (`@asynccontextmanager`)

All application startup and shutdown hooks must be handled via the modern FastAPI `lifespan` context manager in `src/main.py`. **Do not use deprecated `@app.on_event("startup")` or `@app.on_event("shutdown")`.**

```python
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI
from clients.postgresql import init_db, close_db
from clients.redis import redis_async_client
from loguru import logger

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info("Initializing application services...")
    # 1. Startup: initialize database and cache pools
    await init_db()
    try:
        await redis_async_client.ping()
    except Exception as exc:
        logger.warning(f"Redis unavailable at startup: {exc}")

    yield  # Application runs and handles requests

    # 2. Shutdown: gracefully close and dispose connection pools
    logger.info("Disposing application resources...")
    await close_db()
    await redis_async_client.close()
```

---

## 4. HTTP Status Codes & Error Handling

### Explicit HTTP Status Codes
Always import and use `fastapi.status` constants:
- `status.HTTP_200_OK`: Default for successful `GET`, `PUT`, `PATCH`, and login/token grants.
- `status.HTTP_201_CREATED`: Must be used for resource creation (`POST`).
- `status.HTTP_204_NO_CONTENT`: For successful deletions (`DELETE`) or actions returning no body.
- `status.HTTP_400_BAD_REQUEST`: Malformed business logic or invalid client input.
- `status.HTTP_401_UNAUTHORIZED`: Authentication missing or expired tokens.
- `status.HTTP_403_FORBIDDEN`: Valid token but insufficient permissions/RBAC.
- `status.HTTP_404_NOT_FOUND`: Target entity does not exist.
- `status.HTTP_409_CONFLICT`: Duplicate records, unique constraint collisions.
- `status.HTTP_422_UNPROCESSABLE_ENTITY`: Pydantic schema validation failures.

### Standardized Exception Architecture
Raise domain exceptions inheriting from `AppException` located in `src/exceptions/app_exception.py`. Never return raw error dictionaries from routers:

```python
from exceptions.app_exception import NotFoundException, ConflictException

if not invoice:
    raise NotFoundException(message=f"Invoice {invoice_id} not found.", error_code="INVOICE_NOT_FOUND")

if is_duplicate:
    raise ConflictException(message="Invoice number already exists.", error_code="DUPLICATE_INVOICE_NUMBER")
```

Global handlers registered in `src/main.py` via `register_exception_handlers(app)` will serialize these into consistent JSON error responses.

---

## 5. Dependency Injection (`Depends`) Hierarchy

Follow the Clean Layered Dependency Injection flow: **Router ➔ Service ➔ Repository ➔ AsyncSession / Cache**.

```
┌────────────────────────────────────────────────────────┐
│                   Router Layer                         │
│  service: InvoiceService = Depends()                   │
│  current_user: UUID = Depends(get_current_user_id)     │
└─────────────────────────┬──────────────────────────────┘
                          ▼
┌────────────────────────────────────────────────────────┐
│                   Service Layer                        │
│  repo: InvoiceRepository = Depends()                   │
│  cache: Redis = Depends(get_async_cache)               │
└─────────────────────────┬──────────────────────────────┘
                          ▼
┌────────────────────────────────────────────────────────┐
│                  Repository Layer                      │
│  db: AsyncSession = Depends(get_async_db)              │
└────────────────────────────────────────────────────────┘
```

### Dependency Rules:
1. **Automatic Resolution**: Let FastAPI resolve nested dependencies automatically with `service: MyService = Depends()` when the class constructor specifies typed dependencies.
2. **Session Lifecycle**: Never manually instantiate `AsyncSession` in services or routers; always inject `db: AsyncSession = Depends(get_async_db)`.
3. **Security / Auth**: Protect endpoints using `Depends(get_current_user_id)` or RBAC dependency functions.
4. **Header / Cookie Extraction**: Router handlers may accept `Request` and `Response` objects to read client IP / user agents and set `HTTP-Only` secure cookies.
