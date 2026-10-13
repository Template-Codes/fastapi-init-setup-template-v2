---
# sqlalchemy
Description: 
  Standard practices, model patterns, repository wrappers, and async database conventions for SQLAlchemy 2.0 in the XCOM ERP codebase. Use when creating or modifying ORM models, repositories, database sessions, and executing queries.
---

# SQLAlchemy 2.0 & Repository Standards

This skill documents the exact architectural patterns, ORM conventions, session management, and repository abstractions used in this codebase.

---

## 1. Core Stack & Dependencies

- **SQLAlchemy Version**: `2.0+` (`sqlalchemy[asyncio]>=2.0.30`)
- **Async Runtime Driver**: `asyncpg>=0.29.0` (high-performance async engine)
- **Sync Migration Driver**: `psycopg[binary]>=3.1.19` (used by Alembic CLI)
- **Primary Key Generator**: `uuid6.uuid7()` (time-ordered UUIDv7) via `db.base.generate_uuid`

---

## 2. Model Declarations & Standards

All models must inherit from `db.base.Base` and follow SQLAlchemy 2.0 declarative style with `Mapped[...]` and `mapped_column(...)`. **Never use legacy `Column(...)` or `declarative_base()` syntax.**

### Standard Base & Mixins
- **Base**: `from db.base import Base` (contains `POSTGRES_NAMING_CONVENTION` for deterministic index, unique, check, and foreign key constraint names).
- **Primary Key**: `from db.base import uuid_pk` (maps to `UUID(as_uuid=True)` with UUIDv7 default).
- **Timestamps**: `from db.base import TimestampMixin` (provides `created_at` and `updated_at` in UTC `DateTime(timezone=True)`).

### Multi-Schema Isolation
Models must specify their PostgreSQL schema in `__table_args__`:
```python
from db.base import Base, TimestampMixin, uuid_pk
from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

class MyModel(Base, TimestampMixin):
    __tablename__ = "my_table"
    __table_args__ = {"schema": "accounting"}  # Specify module schema

    id: Mapped[uuid_pk]
    name: Mapped[str] = mapped_column(String(100), nullable=False)
```

### Foreign Keys & Relationships
- Explicitly prefix table names with schema in foreign keys: `ForeignKey("auth.roles.id", ondelete="CASCADE")`.
- Store UUID foreign keys as `UUID(as_uuid=True)`.
- Use `TYPE_CHECKING` guards for cross-module type hints to prevent circular imports:
```python
from typing import TYPE_CHECKING, List, Optional
import uuid
from sqlalchemy import ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

if TYPE_CHECKING:
    from modules.profile.user_profile_model import UserProfile

class User(Base, TimestampMixin):
    __tablename__ = "users"
    __table_args__ = {"schema": "auth"}

    id: Mapped[uuid_pk]
    profile: Mapped[Optional["UserProfile"]] = relationship(
        "UserProfile",
        back_populates="user",
        uselist=False,
        cascade="all, delete-orphan",
    )
```

### Enums
Use Python `Enum` or `(str, Enum)` mapped via SQLAlchemy `Enum(EnumClass, native_enum=True)`:
```python
from enum import Enum as PyEnum
from sqlalchemy import Enum

class UserStatus(str, PyEnum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"

status: Mapped[UserStatus] = mapped_column(
    Enum(UserStatus, native_enum=True),
    default=UserStatus.ACTIVE,
    nullable=False,
)
```

---

## 3. Database Engine & Session Wrappers

- **Engine Configuration**: Singleton created in `src/clients/postgresql.py` (`pool_size=5`, `max_overflow=10`, `pool_pre_ping=True`, `pool_recycle=3600`).
- **Session Factory**: `postgres_client_async_session = async_sessionmaker(engine, expire_on_commit=False)`
- **FastAPI Dependency**: In `src/db/db_session.py`:
```python
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession
from clients.postgresql import postgres_client_async_session

async def get_async_db() -> AsyncGenerator[AsyncSession, None]:
    async with postgres_client_async_session() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
```

---

## 4. Repository Pattern (`src/base/repository.py`)

All domain repositories should inherit from `BaseRepository[ModelType]` and inject `db: AsyncSession = Depends(get_async_db)`:

```python
from typing import Optional
from fastapi import Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from base.repository import BaseRepository
from db.db_session import get_async_db
from modules.accounting.models import Invoice

class InvoiceRepository(BaseRepository[Invoice]):
    def __init__(self, db: AsyncSession = Depends(get_async_db)):
        super().__init__(db, Invoice)

    async def get_by_invoice_number(self, invoice_number: str) -> Optional[Invoice]:
        stmt = select(Invoice).where(Invoice.invoice_number == invoice_number).limit(1)
        result = await self.db.execute(stmt)
        return result.scalars().first()
```

### Available `BaseRepository` Methods
- `get_by_id(id)`: Primary key fetch via `db.get()`.
- `get_by_ids(ids)`: Batch fetch via `.where(pk_column.in_(ids))`.
- `get_all(limit=100, offset=0)`: Paginated fetch.
- `create(data, commit=True)`: Instantiate and persist record.
- `update(db_obj, data, commit=True)`: Update existing record attributes.
- `delete(db_obj, commit=True)`: Remove record.

---

## 5. Async Querying Rules (SQLAlchemy 2.0 Style)

1. **Always use 2.0 `select(...)` statements**:
   - `result = await session.execute(select(Model).where(...))`
   - `instances = result.scalars().all()` or `result.scalars().first()`
   - **Never call legacy `session.query(...)`**.
2. **Existence Checks**:
   - `stmt = select(exists().where(User.email == email))`
   - `is_present = bool((await session.execute(stmt)).scalar())`
3. **Eager Loading**:
   - Use `selectinload` or `joinedload` for relationships when needed:
     `select(User).options(selectinload(User.roles)).where(...)`
4. **Transaction Integrity**:
   - Always let session dependencies or explicit `async with session.begin():` handle commit/rollback boundaries.
