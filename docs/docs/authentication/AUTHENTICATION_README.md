# Authentication & Authorization System Technical Blueprint

> **System Architecture & Developer Reference Document**  
> **Date & Time Written**: August 16, 2026 at 5:00 PM
> **Document Status**: Production / Boilerplate Standard  
> **Coverage**: Authentication, Hybrid RBAC + ABAC Authorization, Refresh Token Rotation (RTR), Fast-Path Redis Session Verification, Asynchronous DB Throttling, IP-Scoped Brute-Force Mitigation  
> **Exclusions**: Test Suites (`tests/`), Registration (Unchanged)  

---

## 1. Executive Summary & Design Intention

This authentication and authorization subsystem is designed as an enterprise-grade, defense-in-depth foundation for FastAPI applications. It is engineered to serve as a reusable production template to prevent boilerplate rewrite across future projects.

### Core Architectural Principles
- **Defense in Depth**: Authentication checks occur at both the network edge (IP-based rate limiting), middleware layer ([JWTValidator](file:///c:/Users/imper/Documents/ussci/erp/src/middlewares/jwt_validator.py#L16-L183) for 0ms CPU verification + O(1) Redis session checks), controller/router layer (HTTP-Only cookie parsing & JWT validation), service layer (ABAC status checks, Argon2id verification, granular IP+Username lockout), and persistence layer (SHA-256 hashed tokens).
- **Refresh Token Rotation (RTR) & Instant Invalidation**: On every token refresh request (`POST /api/public/auth/refresh-token`), **both** access and refresh tokens are rotated. Presenting an old or previously used refresh token triggers automatic reuse detection, immediately revoking the session across PostgreSQL and Redis.
- **Database I/O Throttling (Fast-Path Architecture)**: Token refresh operations validate against a single authoritative Redis cache in **0.5ms**. Database updates (rotating hashes and timestamp synchronization) are offloaded to non-blocking background tasks (`asyncio.create_task`) using dedicated async sessions (`postgres_client_async_session`), eliminating DB I/O overhead from the request-response hot path.
- **Granular IP + Username Lockout Model**: Brute-force protection tracks failed attempts per `(IP, Username)` pair in Redis. Blocking 5 failed attempts locks out only the offending IP-username combination, preventing cross-IP Denial of Service (DoS) attacks on legitimate users.
- **Single Active Session Enforcement (Option B Exclusive Lock & BIR Annex B Item 11.b Compliance)**: Strictly restricts a user account from concurrent active sessions across multiple terminals. On login, if an active session exists that was active within the idle window (`SESSION_IDLE_TIMEOUT_SEC` = 30 minutes), the second login is rejected with HTTP 409 Conflict (`ACTIVE_SESSION_EXISTS`). If the previous session has been idle for > 30 minutes (e.g. browser closed or computer rebooted), it is automatically retired, allowing the new sign-in without administrative lockout.
- **Zero Raw Secret Exposure**: Plaintext passwords are never stored; they are hashed using **Argon2id** via `pwdlib`. Both access and refresh tokens are hashed using SHA-256 before storage in session payloads and database tables.

---

## 2. Architectural Layer & Component Map

The authentication system is structured into strict architectural layers located under `src/`:

| Layer | Primary Files | Key Responsibilities & Line References |
| :--- | :--- | :--- |
| **API Routers** | [auth_router.py](file:///c:/Users/imper/Downloads/universal/erp/src/modules/authentication/auth_router.py) | Exposes public auth endpoints, sets HTTP-Only cookies for access & refresh tokens, extracts request headers (`X-Forwarded-For`, `User-Agent`). See [auth_router.py:L19-L134](file:///c:/Users/imper/Downloads/universal/erp/src/modules/authentication/auth_router.py#L19-L134). |
| **Service Layer** | [auth_service.py](file:///c:/Users/imper/Downloads/universal/erp/src/modules/authentication/auth_service.py) | Orchestrates Argon2id password hashing, IP+Username brute-force lockout, single active session concurrency guard, dual JWT generation, session creation, Refresh Token Rotation (RTR), and background DB sync. See [auth_service.py](file:///c:/Users/imper/Downloads/universal/erp/src/modules/authentication/auth_service.py). |
| **Edge Middleware** | [jwt_validator.py](file:///c:/Users/imper/Downloads/universal/erp/src/middlewares/jwt_validator.py) | Zero-DB, 3-layer validation middleware injecting pre-verified claims into `request.state` for private routes. See [jwt_validator.py](file:///c:/Users/imper/Downloads/universal/erp/src/middlewares/jwt_validator.py). |
| **Security Guards** | [current_user.py](file:///c:/Users/imper/Downloads/universal/erp/src/dependencies/current_user.py) | FastAPI dependencies for protected endpoints: `get_current_user_id` leveraging `request.state`, and ABAC profile completion guard `require_user_profile_and_get_id`. |
| **Domain Models** | [auth_model.py](file:///c:/Users/imper/Downloads/universal/erp/src/modules/authentication/auth_model.py)<br>[session_model.py](file:///c:/Users/imper/Downloads/universal/erp/src/modules/session/session_model.py) | SQLAlchemy ORM models for users, roles, permissions, junction tables, and session audit logs. |
| **Repositories** | [auth_repository.py](file:///c:/Users/imper/Downloads/universal/erp/src/modules/authentication/auth_repository.py)<br>[session_repo.py](file:///c:/Users/imper/Downloads/universal/erp/src/modules/session/session_repo.py) | Async database access abstractions for user credentials and active session state (`get_active_session_by_user_id`, `deactivate_session_by_id`). |
| **Enums & Constants** | [enums.py](file:///c:/Users/imper/Downloads/universal/erp/src/shares/enums.py) | Standardized system permission strings formatted as `MODULE:RESOURCE:ACTION`. |
| **Cache Utilities** | [maintain_cache_key.py](file:///c:/Users/imper/Downloads/universal/erp/src/utils/maintain_cache_key.py) | Redis key generators, IP+Username failed login tracking, and profile completion status caching. |

---

## 3. Hybrid RBAC + ABAC Authorization Model

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

### Role-Based Access Control (RBAC) Mechanics
- **Permissions**: Defined in [Permission](file:///c:/Users/imper/Documents/ussci/erp/src/modules/authentication/auth_model.py#L34-L51). Formatted programmatically in [SystemPermission](file:///c:/Users/imper/Documents/ussci/erp/src/shares/enums.py#L43-L62) as `MODULE:RESOURCE:ACTION` (e.g., `AUTHENTICATION:USER:CREATE`).
- **Roles**: Groups of permissions defined in [Role](file:///c:/Users/imper/Documents/ussci/erp/src/modules/authentication/auth_model.py#L77-L101) (e.g., `SUPER_ADMIN`, `ADMIN`, `STAFF_USER`).
- **Junction Tables**: [RolePermission](file:///c:/Users/imper/Documents/ussci/erp/src/modules/authentication/auth_model.py#L54-L75) and [UserRole](file:///c:/Users/imper/Documents/ussci/erp/src/modules/authentication/auth_model.py#L103-L119) implement M:N relationships loaded via `lazy="selectin"`.

### Attribute-Based Access Control (ABAC) Mechanics
In addition to RBAC roles, every access decision evaluates contextual attributes:
1. **User Status Attribute** ([UserStatus](file:///c:/Users/imper/Documents/ussci/erp/src/modules/authentication/auth_model.py#L26-L32)): Access is denied unless `user.status == UserStatus.ACTIVE` ([auth_service.py:L166-L170](file:///c:/Users/imper/Documents/ussci/erp/src/modules/authentication/auth_service.py#L166-L170)).
2. **Temporal Ban Expiration Attribute**: Evaluated dynamically at runtime ([auth_service.py:L153-L165](file:///c:/Users/imper/Documents/ussci/erp/src/modules/authentication/auth_service.py#L153-L165)). If `banned_until_time` has expired, the system automatically restores a `SUSPENDED` account back to `ACTIVE`.
3. **Granular IP + Username Lockout Attribute**: Pre-authentication brute-force check ([auth_service.py:L144-L151](file:///c:/Users/imper/Documents/ussci/erp/src/modules/authentication/auth_service.py#L144-L151)). Checks Redis key `failed_login_block:{ip}:{username}`. 5 consecutive failed attempts from the same IP set a 15-minute lockout for that specific IP-username pair.
4. **Environment Attributes**: Client IP and User-Agent are recorded in `session.sessions` ([session_model.py:L35-L36](file:///c:/Users/imper/Documents/ussci/erp/src/modules/session/session_model.py#L35-L36)).
5. **Profile Completion Attribute**: Enforced dynamically by dependency `require_user_profile_and_get_id` ([current_user.py:L70-L108](file:///c:/Users/imper/Documents/ussci/erp/src/dependencies/current_user.py#L70-L108)), returning HTTP 403 `PROFILE_SETUP_REQUIRED` if false.

---

## 4. Authentication & Token Lifecycle Logic Flow

### Diagram 1: User Login & IP-Scoped ABAC Lockout Flowchart
This flowchart details credential verification, Argon2id check, IP+Username brute-force lockout, and initial session creation:

```mermaid
flowchart TD
    A[Client Submits Credentials & IP] --> B[Fetch User by Username from DB]
    B -->|User Not Found| C[Raise 401 Unauthorized]
    B -->|User Found| D{Check Redis IP+Username Lockout<br/>failed_login_block:ip:username}
    
    D -->|Locked Out in Redis| E[Raise 401 Unauthorized: Generic Error]
    D -->|Not Locked Out| F{Check banned_until_time in DB}
    
    F -->|Active Admin Ban| G[Raise 403 Forbidden: Account Inactive]
    F -->|Ban Expired| H[Lift Ban: status = ACTIVE<br/>Commit to DB]
    F -->|No Ban Set| I{Check user.status == ACTIVE}
    H --> I
    
    I -->|Status != ACTIVE| J[Raise 403 Forbidden: Account Inactive]
    I -->|Status == ACTIVE| K[Verify Password via Argon2id]
    
    K -->|Password Invalid| L[Increment failed_login_count:ip:username in Redis]
    L --> M{attempts >= 5 in 15 mins?}
    M -->|Yes| N[Set failed_login_block:ip:username in Redis<br/>TTL = 15 Mins]
    M -->|No| O[Raise 401 Unauthorized: Invalid Credentials]
    N --> O
    
    K -->|Password Valid| P[Clear failed_login state in Redis for ip:username]
    P --> Q[Check User Profile Completion]
    Q --> R{Check Active Session in DB<br/>get_active_session_by_user_id}
    
    R -->|No Active Session| S[Generate Access JWT & Refresh JWT]
    R -->|Active Session Exists| T{now - last_active_at <= 30 mins?<br/>SESSION_IDLE_TIMEOUT_SEC}
    
    T -->|Yes: Recent / Active Terminal| U[Raise 409 Conflict: ACTIVE_SESSION_EXISTS<br/>Generic Message: Active session in progress]
    T -->|No: Stale / Abandoned Session| V[Auto-retire Old Session in DB & Redis<br/>Set is_active = False]
    V --> S
    
    S --> W[Compute SHA-256 Hashes of Both Tokens]
    W --> X[Save Session in PostgreSQL session.sessions]
    X --> Y[Cache Session Payload in Redis<br/>sessions:sid:user:uid]
    Y --> Z[Return Auth Payload & Set HTTP-Only Cookies]
```

---

### Diagram 2: Refresh Token Rotation (RTR) & Fast-Path DB Sync Flowchart
This diagram illustrates the single-authoritative Redis validation path, token rotation, theft detection, and non-blocking background DB sync:

```mermaid
flowchart TD
    A[Client Requests Token Refresh] --> B[Extract refresh_token from Cookies]
    B -->|Cookie Missing| C[Raise 401 Unauthorized]
    B -->|Cookie Present| D[Decode & Verify Refresh JWT Signature]
    
    D -->|Signature Invalid / Expired| E[Raise 401 Unauthorized: Invalid Session]
    D -->|Valid JWT Claims| F[Fetch Redis Cache Key<br/>sessions:sid:user:uid]
    
    F -->|Cache Hit & Session Active| G{Compare Incoming Hash vs<br/>cached refresh_token_hash}
    G -->|Hash Mismatch Token Reuse Detected| H[Immediate Revocation:<br/>Set DB is_active=False<br/>Delete Redis Cache]
    H --> I[Raise 401 Unauthorized: Session Revoked]
    
    G -->|Hash Match Success| J[Generate Rotated Access JWT + Refresh JWT]
    J --> K[Update Redis Cache with New Hashes<br/>access_token_hash & refresh_token_hash]
    K --> L[Dispatch Non-Blocking Background Task<br/>_sync_session_rotation_db]
    L --> M[Return 200 OK & Set New HTTP-Only Cookies]
    
    F -->|Cache Miss / Eviction| N[Fallback to PostgreSQL DB Query]
    N -->|DB Session Inactive or Missing| H
    N -->|DB Session Active & Hash Match| O[Rotate Tokens, Update DB immediately,<br/>Re-warm Redis Cache]
    O --> M
```

---

### Diagram 3: Authentication & Protected Route Request Sequence
End-to-end interaction flow across Client Browser, FastAPI Router, Auth Service, JWTValidator Middleware, PostgreSQL, and Redis Cache:

```mermaid
sequenceDiagram
    autonumber
    actor Client
    participant Router as Auth Router
    participant Service as Auth Service
    participant MW as JWTValidator Middleware
    participant Cache as Redis Cache
    participant DB as PostgreSQL DB

    Note over Client, DB: 1. User Login & Token Issuance
    Client->>Router: POST /api/public/auth/auth-tokens (credentials)
    Router->>Service: authenticate_user(credential, ip, user_agent)
    Service->>DB: Fetch user by username
    Service->>Cache: Check is_ip_user_blocked(ip, username)
    Service->>Service: Verify Argon2id password hash
    Service->>DB: Check get_active_session_by_user_id (Exclusive Lock)
    opt Active Session Exists & Idle > 30m
        Service->>DB: Deactivate stale session (is_active = False)
        Service->>Cache: Delete stale Redis session key
    end
    alt Active Session Exists & Idle <= 30m
        Service-->>Router: 409 Conflict (ACTIVE_SESSION_EXISTS)
        Router-->>Client: 409 Conflict
    else No Active Session or Stale Retired
        Service->>DB: Insert UserSession (refresh_token_hash)
        Service->>Cache: Save session payload (access_token_hash & refresh_token_hash)
        Service-->>Router: UserAuthenticationResponse
        Router-->>Client: 200 OK + Set Cookies (access_token, refresh_token)
    end

    Note over Client, DB: 2. Edge Middleware Protected Route Access
    Client->>MW: GET /api/private/resource (Cookies / Bearer Header)
    MW->>MW: Layer 1: Exclude public routes check
    MW->>MW: Layer 2: Pure CPU signature & expiration check (0ms I/O)
    MW->>Cache: Layer 3: Get sessions:sid:user:uid (O(1) ~0.5ms)
    MW->>MW: Check is_active, user_status, and access_token_hash
    MW->>MW: Inject claims into request.state
    MW-->>Client: Pass request to Endpoint Handler (0ms downstream overhead)

    Note over Client, DB: 3. Refresh Token Rotation (RTR)
    Client->>Router: POST /api/public/auth/refresh-token (refresh_token cookie)
    Router->>Service: refresh_authentication_tokens(refresh_token)
    Service->>Cache: Get sessions:sid:user:uid
    Service->>Service: Verify refresh_token_hash (Theft Check)
    Service->>Service: Rotate Access & Refresh JWTs
    Service->>Cache: Update Redis payload with new token hashes
    Service--)DB: Dispatch background task: _sync_session_rotation_db
    Service-->>Router: RefreshAuthenticationTokensResponse
    Router-->>Client: 200 OK + Set New rotated Cookies
```

---

## 5. Session Cache Payload Specification

The Redis key `sessions:{session_id}:user:{user_id}` contains a complete, self-contained JSON session payload ([auth_service.py:L499-L527](file:///c:/Users/imper/Documents/ussci/erp/src/modules/authentication/auth_service.py#L499-L527)):

| Field Name | Type | Description & Purpose |
| :--- | :--- | :--- |
| `id` | `string (UUID)` | Unique session identifier (`sid`). |
| `user_id` | `string (UUID)` | User account identifier (`sub`). |
| `refresh_token_hash` | `string (SHA-256)` | Hash of currently active refresh token. Used for RTR theft detection. |
| `access_token_hash` | `string (SHA-256)` | Hash of currently active access token. Used by `JWTValidator` to reject stale access tokens. |
| `is_active` | `boolean` | Session active state flag. Checked by middleware layer. |
| `user_status` | `string` | User account lifecycle status (`ACTIVE`, `SUSPENDED`, `PENDING`, `INACTIVE`). |
| `is_profile_completed` | `boolean` | Flag indicating whether user profile setup is complete. |
| `ip_address` | `string / null` | Client IP address at login. |
| `user_agent` | `string / null` | Client User-Agent header string. |
| `expires_at` | `ISO 8601 string` | Refresh token expiration timestamp. |
| `last_active_at` | `ISO 8601 string` | Last request timestamp. |
| `last_db_synced_at` | `ISO 8601 string` | Timestamp of last asynchronous database synchronization. |

---

## 6. API Endpoints Specification

### 1. User Registration
- **Endpoint**: `POST /api/public/auth/registration`
- **Location**: [auth_router.py:L20-L32](file:///c:/Users/imper/Documents/ussci/erp/src/modules/authentication/auth_router.py#L20-L32)
- **Access**: Public (Protected by IP Rate Limiter)
- **Input**: `UserRegistrationRequest` (`username`, `email`, `plain_password`)
- **Behavior**: Standardizes email to lowercase, checks email uniqueness, hashes password with Argon2id, creates `User` record with default `status = UserStatus.PENDING`. Unchanged.

### 2. User Authentication & Token Grant
- **Endpoint**: `POST /api/public/auth/auth-tokens`
- **Location**: [auth_router.py:L37-L91](file:///c:/Users/imper/Documents/ussci/erp/src/modules/authentication/auth_router.py#L37-L91)
- **Access**: Public (Protected by IP Rate Limiter)
- **Input**: `UserAuthenticationRequest` (`username`, `plain_password`)
- **Behavior**: Checks IP+Username Redis lockout, verifies Argon2id password, generates dual JWTs, computes SHA-256 token hashes, persists session in PostgreSQL & Redis, returns payload and sets HTTP-Only cookies.
- **Cookies Set**:
  - `access_token`: Max-Age = `ACCESS_JWT_EXPIRY_SEC`, Path = `/`, HttpOnly = `True`, Secure = `True` (dev override), SameSite = `lax`/`strict`.
  - `refresh_token`: Max-Age = `REFRESH_JWT_EXPIRY_SEC`, Path = `/api/public/auth`, HttpOnly = `True`, Secure = `True`, SameSite = `lax`/`strict`.

### 3. Refresh Tokens (RTR Rotation)
- **Endpoint**: `POST /api/public/auth/refresh-token`
- **Location**: [auth_router.py:L95-L133](file:///c:/Users/imper/Documents/ussci/erp/src/modules/authentication/auth_router.py#L95-L133)
- **Access**: Public (Protected by IP Rate Limiter)
- **Behavior**: Extracts `refresh_token` from HTTP-Only cookie, verifies JWT signature, validates against Redis cache (`sessions:{sid}:user:{uid}`), verifies token hash for theft detection, rotates **both** access and refresh tokens, updates Redis payload instantly, dispatches background task `_sync_session_rotation_db`, and returns new rotated cookies.

---

## 7. Security Mechanics & Technicalities

### Cryptographic Algorithms
1. **Password Hashing**: Argon2id via `pwdlib.PasswordHash.recommended()` ([auth_service.py:L33](file:///c:/Users/imper/Documents/ussci/erp/src/modules/authentication/auth_service.py#L33)). Hashing/verification offloaded to thread pool via `asyncio.to_thread` ([auth_service.py:L70](file:///c:/Users/imper/Documents/ussci/erp/src/modules/authentication/auth_service.py#L70), [L173](file:///c:/Users/imper/Documents/ussci/erp/src/modules/authentication/auth_service.py#L173)).
2. **Token Hashing**: SHA-256 via `hashlib.sha256(token.encode()).hexdigest()` for both access tokens ([auth_service.py:L211](file:///c:/Users/imper/Documents/ussci/erp/src/modules/authentication/auth_service.py#L211)) and refresh tokens ([auth_service.py:L210](file:///c:/Users/imper/Documents/ussci/erp/src/modules/authentication/auth_service.py#L210)).
3. **Dual JWT Keys**: Access and Refresh tokens use independent secret keys (`settings.ACCESS_JWT_SECRET_KEY` and `settings.REFRESH_JWT_SECRET_KEY`) encoded using HMAC-SHA256 (`HS256`).

---

## 8. Developer & AI Agent Quick Reference Guide

### Protecting a New Endpoint
To protect a new private endpoint, rely on [current_user.py](file:///c:/Users/imper/Documents/ussci/erp/src/dependencies/current_user.py) which automatically uses pre-verified claims from `request.state` injected by [JWTValidator](file:///c:/Users/imper/Documents/ussci/erp/src/middlewares/jwt_validator.py#L16-L183):

```python
from fastapi import APIRouter, Depends
from uuid import UUID
from dependencies.current_user import get_current_user_id, require_user_profile_and_get_id

router = APIRouter()

# Option A: Require Valid Authentication Only (0ms overhead)
@router.get("/api/private/resource")
async def get_resource(user_id: UUID = Depends(get_current_user_id)):
    return {"user_id": str(user_id)}

# Option B: Require Valid Authentication AND Completed Profile
@router.get("/api/private/profile-resource")
async def get_profile_resource(user_id: UUID = Depends(require_user_profile_and_get_id)):
    return {"user_id": str(user_id)}
```

### Key Configuration Variables
Defined in [settings.py](file:///c:/Users/imper/Documents/ussci/erp/src/core/settings.py):
- `ACCESS_JWT_SECRET_KEY`: Secret string for access token signing.
- `REFRESH_JWT_SECRET_KEY`: Secret string for refresh token signing.
- `ACCESS_JWT_EXPIRY_SEC`: Access token lifespan (e.g. 900s / 15 mins).
- `REFRESH_JWT_EXPIRY_SEC`: Refresh token lifespan (e.g. 604800s / 7 days).
- `COOKIE_SECURE`: `True` in production (enforces HTTPS), `False` in local dev.
- `COOKIE_SAMESITE`: SameSite cookie policy (`lax` or `strict`).

---

## 9. Session Lifecycle & Administrative Overrides (BIR CAS Annex B Item 11.b)

The session module (`src/modules/session/`) manages individual terminal sessions and provides administrative overrides for active connections:

### Endpoints
1. **User Own Logout**: `POST /api/private/session/logout`
   - Gracefully ends the calling user's active session in PostgreSQL (`is_active = False`) and evicts the session cache from Redis.
   - Clears HTTP-Only authentication cookies (`access_token`, `refresh_token`).
2. **Admin List All Active Sessions Across All Users**: `GET /api/private/admin/sessions`
   - Guarded by `require_role(RoleName.SUPER_ADMIN, RoleName.ADMIN)`.
   - Returns all active terminal sessions enterprise-wide joined with user identity and profile data (`user_id`, `username`, `email`, `roles`, `full_name`, IP address, user-agent, creation date, and last active timestamp) for centralized monitoring, audit, and client-side searching.
3. **Admin Force Logout by Session UUID**: `DELETE /api/private/admin/sessions/{session_id}`
   - Guarded by `require_role(RoleName.SUPER_ADMIN, RoleName.ADMIN)`.
   - Immediately revokes a target terminal session. Any subsequent request from that terminal receives an immediate 401 Unauthorized.
4. **Admin Enterprise-Wide Mass Logout with Sudo Verification**: `POST /api/private/admin/sessions/terminate-all`
   - Guarded by `require_role(RoleName.SUPER_ADMIN, RoleName.ADMIN)` and `verify_sudo_credential`.
   - Requires the executing administrator to supply their own `admin_password` in the JSON request body.
   - Prevents unauthorized mass evictions from unattended administrator workstations.
   - Emergency killswitch that bulk invalidates ALL active sessions across all users in PostgreSQL and purges all related keys from Redis.

---

## 10. Administrative User Approval Lifecycle (BIR CAS Annex B Item 11.a)

Under BIR CAS regulations, newly registered accounts cannot immediately access financial modules or records without prior administrative authorization:

### Workflow
1. **Public Registration**: `POST /api/public/auth/registration`
   - User account is created with `status = PENDING`.
   - Login attempts are blocked with `HTTP 403 Forbidden` ("Account is not in active status").
2. **Pending Users Inspection**: `GET /api/private/admin/users/pending`
   - Guarded by `require_permission(SystemPermission.AUTHENTICATION_USER_READ)`.
   - Returns registered users awaiting administrative vetting.
3. **Account Approval**: `POST /api/private/admin/users/{user_id}/approve`
   - Guarded by `require_permission(SystemPermission.AUTHENTICATION_REGISTRATION_ACCEPT)`.
   - Transitions status to `ACTIVE` and assigns an initial system role (default: `STAFF_USER`).
4. **Account Rejection & Soft Deactivation**: `POST /api/private/admin/users/{user_id}/reject`
   - Guarded by `require_permission(SystemPermission.AUTHENTICATION_REGISTRATION_REJECT)`.
   - Sets status to `INACTIVE`.
   - Physical SQL `DELETE` is prohibited to uphold the 10-year immutable audit trail requirement mandated by BIR regulations.

