# Authentication Module - Entity Relationship Diagram (ERD)

This document details the database architecture of the **Authentication (`auth`)** module, which serves as the central identity anchor for the XCOM ERP & CAS platform.

---

## 1. Module ERD

```mermaid
erDiagram
    AUTH_USERS {
        uuid id PK "UUIDv7 primary key"
        varchar user_code UK "USR-XXXXX server default sequence"
        varchar username UK "Case-sensitive unique login"
        varchar email UK "Unique email identifier"
        varchar password_hash "Argon2id cryptographic hash"
        enum status "PENDING|ACTIVE|INACTIVE|SUSPENDED"
        timestamptz banned_until_time "Optional lockout expiration"
        timestamptz created_at "Registration timestamp (UTC)"
        timestamptz updated_at "Last update timestamp (UTC)"
    }

    SESSION_SESSIONS {
        uuid id PK "Session ID"
        uuid user_id FK "FK auth.users.id (CASCADE)"
        varchar refresh_token_hash UK "Refresh token hash"
    }

    PROFILE_USER_PROFILES {
        uuid user_id PK,FK "FK auth.users.id (CASCADE)"
        varchar first_name "Given name"
        varchar last_name "Surname"
    }

    RBAC_USER_ROLES {
        uuid user_id PK,FK "FK auth.users.id (CASCADE)"
        uuid role_id PK,FK "FK rbac.roles.id (CASCADE)"
    }

    AUTH_USERS ||--o{ SESSION_SESSIONS : "owns (1-to-N)"
    AUTH_USERS ||--|| PROFILE_USER_PROFILES : "extends (1-to-1)"
    AUTH_USERS ||--o{ RBAC_USER_ROLES : "assigned (1-to-N)"
```

---

## 2. Table Specifications

### Table: `auth.users`
The root table managing system credentials, identity codes, and account lifecycles.

| Field | Type | Constraints | Description & Purpose |
| :--- | :--- | :--- | :--- |
| `id` | `UUID` | **PK**, Default: `uuid7()` | Time-ordered UUIDv7 ensuring efficient B-tree index insertion and global uniqueness. |
| `user_code` | `VARCHAR(20)` | **UK**, **INDEX**, Non-nullable | Human-readable identifier formatted as `USR-XXXXX`. Generated via PostgreSQL sequence `auth.user_code_seq`. Used on physical receipts, vouchers, and UI displays. |
| `username` | `VARCHAR(50)` | **UK**, **INDEX**, Non-nullable | Unique username used for credential authentication. |
| `email` | `VARCHAR(100)` | **UK**, **INDEX**, Non-nullable | Primary contact email for password resets, 2FA, and official audit notices. |
| `password_hash` | `VARCHAR(255)` | Non-nullable | Argon2id salted password hash. Plaintext passwords are never stored. |
| `status` | `UserStatus` (Enum) | **INDEX**, Non-nullable | Account state: `PENDING` (needs approval), `ACTIVE` (standard), `INACTIVE` (deactivated), `SUSPENDED` (administrative hold). |
| `banned_until_time` | `TIMESTAMPTZ` | Nullable | Expiration timestamp for brute-force rate limit lockouts. If `now() < banned_until_time`, login attempts are rejected. |
| `created_at` | `TIMESTAMPTZ` | Non-nullable | UTC timestamp when the user registered. |
| `updated_at` | `TIMESTAMPTZ` | Non-nullable | UTC timestamp automatically updated on any field modification. |

---

## 3. Key Constraints & Database Logic

1. **Deterministic User Code Sequence (`auth.user_code_seq`)**:
   - The field `user_code` has server default:
     ```sql
     'USR-' || lpad(nextval('auth.user_code_seq')::text, 5, '0')
     ```
   - Guarantees gapless human identifiers across concurrent registrations without application-level race conditions.
2. **Account Lifecycle State Machine**:
   - Only users with `status = 'ACTIVE'` and `banned_until_time IS NULL` (or expired) are permitted to issue JWT authentication tokens.
3. **Cascading Deletions**:
   - Deleting a user in `auth.users` cascades immediately to `session.sessions`, `profile.user_profiles`, and `rbac.user_roles`.
