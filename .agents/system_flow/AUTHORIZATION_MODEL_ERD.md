# Hybrid RBAC + ABAC Authorization Model

The authorization model evaluates both **static roles/permissions** and **dynamic contextual attributes**:

```mermaid
erDiagram
    auth_users ||--o{ auth_user_roles : "assigned"
    auth_roles ||--o{ auth_user_roles : "belongs to"
    auth_roles ||--o{ auth_role_permissions : "contains"
    auth_permissions ||--o{ auth_role_permissions : "granted to"
    auth_users ||--o{ session_sessions : "owns"
    auth_users ||--o| profile_user_profiles : "has"

    auth_users {
        uuid id PK "Internal UUIDv7 Primary Key"
        string user_code UK "Human-facing ID (e.g. USR-00001)"
        string username UK
        string email UK
        string password_hash
        enum status "PENDING, ACTIVE, INACTIVE, SUSPENDED"
        smallint failed_login_attempt_cnt
        datetime failed_login_attempt_time
        datetime banned_until_time
        datetime created_at
        datetime updated_at
    }

    auth_roles {
        uuid id PK
        string name UK
        string description
        boolean is_system_role
    }

    auth_permissions {
        uuid id PK
        string code UK
        string module
        string name
        string description
    }

    auth_user_roles {
        uuid user_id PK, FK
        uuid role_id PK, FK
    }

    auth_role_permissions {
        uuid role_id PK, FK
        uuid permission_id PK, FK
        datetime created_at
    }

    session_sessions {
        uuid id PK
        uuid user_id FK
        string refresh_token_hash UK
        boolean is_active
        string ip_address
        text user_agent
        datetime expires_at
        datetime last_active_at
    }

    profile_user_profiles {
        uuid id PK
        uuid user_id FK, UK
        string first_name
        string last_name
    }
```

---

## Dual-Identifier Architecture

The platform separates machine-level database operations from human interaction surfaces:

1. **Internal Identifier (`id: UUID`)**:
   - Time-ordered **UUIDv7** primary key.
   - Used for all foreign keys, relational joins, JWT subject claims (`sub`), and internal Redis cache keys.
   - Never intended for human typing, verbal referencing, or document printing.

2. **User-Facing Identifier (`user_code: VARCHAR(20)`)**:
   - Monotonically increasing sequential code formatted with leading zero padding (`USR-00001`).
   - Powered by PostgreSQL sequence `auth.user_code_seq` (`server_default`).
   - Provides clear, collision-free identification for operators and audit logs.
   - Displayed exclusively on human-facing surfaces: admin session tables, user registration approvals, profile views, audit trail reports, and operator search lookups.

