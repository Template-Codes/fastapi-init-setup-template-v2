# Enterprise API Endpoints - Master Reference & BIR Compliance

This document provides the system-wide catalog of all HTTP API endpoints in the XCOM. It details each endpoint's functional purpose and its mandatory statutory necessity under best implementations and security practices.

---

## 1. Global System Health Endpoint

### `GET /health`
- **Purpose**:
  - Validates service liveness and database/Redis connection health.
  - Returns current environment configuration and application status.
- **BIR Necessity**:
  - **Annex B Item 1**: Guarantees system operational readiness and availability for continuous accounting operations.
- **Access**: Public.

---

## 2. Master Endpoint Index by Module

| Module | Base Path / Prefix | Endpoints Summary | Detailed Module Docs |
| :--- | :--- | :--- | :--- |
| **Authentication** | `/api/public/auth/*`<br>`/api/private/admin/users/*` | Public registration, Argon2id token issuance, token rotation, and administrative user approval/rejection. | [Authentication Endpoints](file:///c:/Users/imper/Downloads/xcom/erp/docs/docs/authentication/API_ENDPOINTS.md) |
| **Session** | `/api/private/session/*`<br>`/api/private/admin/sessions/*` | Single-session logout, enterprise terminal monitoring, targeted session revocation, and emergency mass termination. | [Session Endpoints](file:///c:/Users/imper/Downloads/xcom/erp/docs/docs/session/API_ENDPOINTS.md) |
| **RBAC** | `/api/private/admin/rbac/*` | RBAC hierarchy queries, role assignments, zero-trust demotions, direct permission overrides, historical snapshot audits, rollbacks, and dual-control change requests. | [RBAC Endpoints](file:///c:/Users/imper/Downloads/xcom/erp/docs/docs/rbac/API_ENDPOINTS.md) |
| **BIR EIS** | `/api/internal/eis/*` | CAS invoice signing/encryption/transmission, submission inquiry, parent-linked retry chains, and 10-year paginated audit logs. | [BIR EIS Endpoints](file:///c:/Users/imper/Downloads/xcom/erp/docs/docs/eis/API_ENDPOINTS.md) |
| **User Profile** | `/api/private/profile/*` | Personal demographic information, contact numbers, structured tax addresses, and Philippine Data Privacy Act (DPA) isolation. | [Profile Endpoints](file:///c:/Users/imper/Downloads/xcom/erp/docs/docs/profile/API_ENDPOINTS.md) |

---

## 4. Cross-Cutting Middleware & Security Guards

1. **`LoggingMiddleware`**:
   - Injects unique `X-Request-ID` tracing header on every HTTP cycle.
   - Logs client IP, User-Agent, endpoint route, status code, and latency into Loguru structured logs.
   - **BIR Citation**: *Annex B Item 8* (Activity logging).
2. **`JWTValidator`**:
   - Enforces cryptographic verification of access tokens in HTTP-Only cookies.
   - Attaches authenticated `user_id` and `session_id` directly to `request.state`.
   - **BIR Citation**: *Annex B Item 10.g* (User stamping).
3. **`RateLimitByIP`**:
   - Sliding-window rate limiter protecting public endpoints against denial-of-service and credential stuffing attacks.
   - **BIR Citation**: *Annex B Item 11.c* (Brute-force protection).
4. **`RBACGuard` (`require_role`)**:
   - Non-blocking authorization check enforcing hierarchical rank requirements before endpoint execution.
   - **BIR Citation**: *Annex B Item 11.e* (Role-Based Access Control).
5. **`CredentialGuard` (`require_sudo_credential`)**:
   - Requires re-authentication with password within the last 5 minutes for high-risk operations (e.g. emergency session termination).
   - **BIR Citation**: *Annex B Item 11.c* (Administrative security controls).
