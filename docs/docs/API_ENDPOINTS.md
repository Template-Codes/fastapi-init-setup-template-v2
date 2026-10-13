# Enterprise API Endpoints - Master Reference

This document provides the system-wide catalog of all HTTP API endpoints in the application. It details each endpoint's functional purpose and access controls under enterprise security practices.

---

## 1. Global System Health Endpoint

### `GET /health`
- **Purpose**:
  - Validates service liveness and database/Redis connection health.
  - Returns current environment configuration and application status.
- **Access**: Public.

---

## 2. Master Endpoint Index by Module

| Module | Base Path / Prefix | Endpoints Summary | Detailed Module Docs |
| :--- | :--- | :--- | :--- |
| **Authentication** | `/api/public/auth/*`<br>`/api/private/admin/users/*` | Public registration, Argon2id token issuance, token rotation, and administrative user approval/rejection. | [Authentication Endpoints](/xcom/erp/docs/docs/authentication/API_ENDPOINTS.md) |
| **Session** | `/api/private/session/*`<br>`/api/private/admin/sessions/*` | Session logout, enterprise terminal monitoring, targeted session revocation, and emergency mass termination. | [Session Endpoints](/xcom/erp/docs/docs/session/API_ENDPOINTS.md) |
| **RBAC** | `/api/private/admin/rbac/*` | RBAC hierarchy queries, role assignments, zero-trust demotions, direct permission overrides, historical snapshot audits, rollbacks, and dual-control change requests. | [RBAC Endpoints](/xcom/erp/docs/docs/rbac/API_ENDPOINTS.md) |
| **User Profile** | `/api/private/profile/*` | Personal demographic information, contact numbers, structured addresses, and privacy isolation. | [Profile Endpoints](/xcom/erp/docs/docs/profile/API_ENDPOINTS.md) |
| **Audit Trail** | `/api/private/admin/audit-logs/*` | Read-only administrative activity audit log inspection, multi-attribute filtering (module, resource, action, date range), and UUID detail lookup. | [Audit Trail API Specification](/xcom/erp/docs/apis/audit_trail_api.http) |

---

## 3. Cross-Cutting Middleware & Security Guards

1. **`LoggingMiddleware`**:
   - Injects unique `X-Request-ID` tracing header on every HTTP cycle.
   - Logs client IP, User-Agent, endpoint route, status code, and latency into Loguru structured logs.
2. **`JWTValidator`**:
   - Enforces cryptographic verification of access tokens in HTTP-Only cookies or Authorization Bearer headers.
   - Attaches authenticated `user_id` and `session_id` directly to `request.state`.
3. **`RateLimitByIP`**:
   - Sliding-window rate limiter protecting public endpoints against denial-of-service and credential stuffing attacks.
4. **`RBACGuard` (`require_role` / `require_permission`)**:
   - Non-blocking authorization check enforcing hierarchical rank and permission requirements before endpoint execution.
5. **`CredentialGuard` (`verify_admin_user_credential`)**:
   - Requires re-authentication with password for high-risk operations (e.g. emergency session termination).
