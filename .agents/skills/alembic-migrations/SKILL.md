---
# alembic-migration

Standard operating procedure for creating, modifying, reviewing, and handling Alembic database migrations in the XCOM ERP codebase. Use whenever database schema changes, new tables, columns, indexes, or enums are created or altered.
---

# Alembic Database Migration Guide

This skill governs how database migrations are generated, reviewed, and handled in this codebase using `uv` and Alembic.

---

## 1. Golden Rules & Invariants

> [!CAUTION]
> **CRITICAL EXECUTION RULE (User Runs Migrations):**
> - Notify first the user IF the code implementation will require migration.
> - The AI agent is authorized to generate (`revision --autogenerate`) and edit/refine migration script files.
> - **The AI agent MUST NEVER run the execution commands (`uv run alembic upgrade head`, `uv run alembic downgrade`, etc.) directly on the database.**
> - **The USER is ALWAYS the one to run the migration execution commands.**
> - Once a migration file has been generated and thoroughly reviewed/polished, the agent must present the findings and instruct the user to execute the command.

---

## 2. Pre-Requisite: Register Models in `alembic/env.py`

Before generating a migration for any new or modified module, verify that the module's model is imported in `alembic/env.py`.

Alembic uses `target_metadata = Base.metadata`. If a model is not imported into `alembic/env.py`, its tables and schema definitions will not be recognized during autogeneration:

```python
# In alembic/env.py:
from modules.authentication import auth_model  # noqa: F401
from modules.profile import user_profile_model  # noqa: F401
from modules.session import session_model  # noqa: F401
from modules.audit_trail import audit_trail_model  # noqa: F401
# Add your new module model here when adding a new domain!
```

---

## 3. Migration Generation Workflow

To generate a new migration revision, use the project's `uv` environment runner:

```bash
uv run alembic revision --autogenerate -m "<descriptive_migration_message>"
```

*Example:*
```bash
uv run alembic revision --autogenerate -m "add_sales_invoice_tables_in_accounting_schema"
```

---

## 4. Mandatory Post-Generation Review Checklist

After Alembic generates a file in `alembic/versions/<revision_id>_<message>.py`, **the agent MUST open and thoroughly inspect the generated file** against the following criteria:

1. **Schema Qualification**:
   - Verify all table and constraint operations properly include their schema parameter (e.g., `schema='auth'`, `schema='session'`, `schema='audit_trail'`).
   - Check that foreign keys point to the correct schema-qualified tables (e.g., `fk_table_column_referenced_table`).

2. **PostgreSQL Enums**:
   - Ensure custom PostgreSQL ENUM types are cleanly created in `upgrade()` using `postgresql.ENUM(...)` with `create_type=True` and dropped in `downgrade()`.
   - Prevent duplicate enum creation conflicts.

3. **No Unintended Destructive Changes**:
   - Verify that autogenerate did **NOT** mistakenly generate `drop_table`, `drop_column`, or `drop_index` for tables/indexes from unimported models.
   - Confirm that column nullability changes and defaults match the model declarations.

4. **Symmetric Downgrade**:
   - Inspect the `downgrade()` function to guarantee that every operation in `upgrade()` is cleanly reversed in reverse order.

5. **Deterministic Constraints**:
   - Ensure constraint names conform to `POSTGRES_NAMING_CONVENTION` (`pk_`, `fk_`, `uq_`, `ix_`, `ck_`).

---

## 5. Handoff to User

After generating and validating the migration script:

1. Display the path to the newly generated file (e.g., `alembic/versions/xxxx_name.py`).
2. Provide a brief summary of the schema modifications (tables added, columns altered, indexes created).
3. Request the user to apply the migration with:

```bash
uv run alembic upgrade head
```
