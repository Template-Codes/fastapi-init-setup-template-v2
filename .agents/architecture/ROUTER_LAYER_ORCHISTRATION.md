# Router Layer & Endpoint Orchestration Standards

This document establishes architectural standards for designing, routing, guarding, and naming HTTP API endpoints across the application backend. All routers in `src/modules/<domain>/<domain>_router.py` must strictly adhere to these conventions.

---

## 1. Endpoint Naming Conventions

### 1.1 Self-Explanatory & Intent-Driven Naming
- **Never use bare or ambiguous root paths**: Routes like `GET /api/private/admin/rbac` (empty subpath) or generic nouns like `POST /auth-tokens` and `GET /requests` are strictly prohibited.
- **Explicit entity/action naming**: Paths must explicitly declare the resource and intent:
  - Good: `POST /api/public/auth/login` (instead of `/auth-tokens`)
  - Good: `POST /api/public/auth/register` (instead of `/registration`)

### 1.2 The Pluralization Rule for Collections
- **Array / List Responses MUST Be Plural**: If an endpoint returns an array (`List[Schema]` or paginated items `items: List[...]`), the endpoint resource identifier MUST use the plural form:
  - `GET /api/private/admin/users/pending-registrations` (Returns `List[PendingUserResponse]`)
  - `GET /api/private/admin/sessions/active-sessions` (Returns `List[AdminUserSessionListItemResponse]`)
- **Single Object Responses MUST Be Singular**:
  - `GET /api/private/admin/rbac/configuration` (Returns single `RBACConfigResponse`)
  - `GET /api/private/admin/rbac/users/{user_id}/role-perms-summary` (Returns single `UserRBACSummaryResponse`)

### 1.3 RPC-Style Action Endpoints for Complex Mutations
When an endpoint performs an explicit operational mutation (assignment, demotion, termination, rollback, approval), use action verbs:
- `POST /api/private/admin/sessions/{session_id}/terminate`
- `POST /api/private/admin/rbac/users/{user_id}/assign-roles`

---

## 2. Middleware Routing Boundaries: `/api/public/**` vs `/api/private/**`

The system enforces a strict boundary handled by `JWTValidator` (`src/middlewares/jwt_validator.py`):

```
HTTP Request
     │
     ▼
┌───────────────────────────────────────────────┐
│              JWTValidator Middleware          │
└───────────────────────┬───────────────────────┘
                        │
       Is path /api/public/* or in excluded paths?
         ├── YES ──► Bypass JWT validation ──► Route Handler (Rate limited)
         └── NO (Private route)
               │
               ▼
         1. Extract token (Authorization header or access_token cookie)
         2. Verify cryptographic signature & expiration (in-memory CPU)
         3. Validate Redis session key (is_active, user_status, at_hash)
         4. Inject request.state.user_id & request.state.session_id
               │
               ▼
         Downstream Route Handler / Dependency Guards
```

### 2.1 Public Endpoints (`/api/public/*`)
- **No Token Required**: Bypasses `JWTValidator`. Never assumes `request.state.user_id` exists.
- **Rate Limiting**: Public endpoints must be guarded with `rate_limit_by_ip()` while private endpoints with `rate_limit_by_user()` to mitigate brute force and credential stuffing.
- **Secret Header Guard**: Public onboarding/gateway endpoints may require `SECRET_HEADER_NAME` verification.

### 2.2 Private Endpoints (`/api/private/*`)
- **Mandatory Authentication**: Handled automatically by `JWTValidator`. If the token is missing, expired, rotated, or revoked in Redis, the middleware returns `401 Unauthorized` or `403 Forbidden` before executing any route handler.
- **Context Injection**: Downstream dependencies access pre-verified claims via `request.state.user_id` and `request.state.session_id` (0ms DB cost).

---

## 3. Dependency Requirements for Private Endpoints

Private endpoints MUST declare standard dependency guards in their router or route decorator:

```python
router = APIRouter(
    prefix="/api/private/admin/example",
    tags=["Example Admin"],
    dependencies=[
        Depends(require_user_profile_and_get_id),
        Depends(require_role(RoleName.SUPER_ADMIN, RoleName.ADMIN)),
    ],
)
```

### 3.1 Profile Completion Guard (`require_user_profile_and_get_id`)
- **Location**: `src/dependencies/current_user.py`
- **Purpose**: Enforces that authenticated users have completed their mandatory profile onboarding before accessing private resources.
- **Mechanism**: Reads Redis key `user:profile_completed:<user_id>`. In non-production environments (`test`, `dev`), this check is safely bypassed for ease of integration testing.
- **Returns**: Validated `user_id: UUID`.

### 3.2 Role-Based Guard (`require_role(*role_names)`)
- **Location**: `src/dependencies/rbac_guard.py`
- **Purpose**: Enforces minimum authority rank or specific role assignment.
- **Mechanism**:
  1. Reads `user_id` from `request.state.user_id`.
  2. Queries user permissions from Redis (`user_permission:<user_id>`), falling back to DB on cache miss.
  3. `SUPER_ADMIN` holds a global bypass.
  4. Returns `user_id` on match; raises `403 Forbidden` (`ROLE_NOT_ASSIGNED`) if role is not present.

### 3.3 Permission-Based Guard (`require_permission(code)` / `require_any_permission(*codes)`)
- **Location**: `src/dependencies/rbac_guard.py`
- **Purpose**: Enforces granular resource-level permission rights (e.g. `SystemPermission.AUTHENTICATION_USER_READ`).
- **Raises**: `403 Forbidden` (`PERMISSION_DENIED`).

### 3.4 Sudo / Step-Up Credential Guard (`require_sudo_credential`)
- **Location**: `src/dependencies/credential_guard.py`
- **Purpose**: High-risk destructive operations (e.g. `POST /api/private/admin/sessions/terminate-all`) require explicit re-authentication with administrator password in the request body to prevent catastrophic operational mistakes.

---

## 4. Thin Controller Rule

Routers must remain strictly thin:
1. **Never execute ORM queries (`select`, `insert`, `update`, `delete`) in a router**.
2. **Never execute business calculations or policy decisions in a router**.
3. **Routers only**:
   - Unpack request parameters (`Query`, `Path`, `Body`, `Depends`).
   - Call the dedicated `Service` method (`service.<action>(...)`).
   - Manage HTTP cookies or return the Pydantic response model.
