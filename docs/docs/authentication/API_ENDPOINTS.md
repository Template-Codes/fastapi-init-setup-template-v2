# Authentication Module - API Endpoints Specification

This document specifies the endpoints belonging to the **Authentication (`auth`)** module (`src/modules/authentication/auth_router.py`), detailing their functional purpose, security controls, and parameter contracts.

---

## 1. Public Authentication Endpoints

### `POST /api/public/auth/register`
- **Purpose**:
  - Accepts new user registration data (username, email, password).
  - Assigns unique sequential identifier (`USR-XXXXX`) via database sequence `auth.user_code_seq`.
  - Hashes raw password using Argon2id.
  - Automatically flags the new user account with status `PENDING`.
- **Access**: Public.
- **Guards & Rate Limiting**:
  - Protected by `rate_limit_by_ip()` to prevent credential stuffing and registration floods.
- **Response**: `HTTP 201 Created` with registration summary and confirmation of `PENDING` state.

---

### `POST /api/public/auth/login`
- **Purpose**:
  - Authenticates username/email and password credentials.
  - Verifies that account status is strictly `ACTIVE`.
  - Checks if the user is currently under a temporary lockout (`banned_until_time`).
  - Records client telemetry (client IP address and User-Agent string) in `session.sessions`.
  - Issues short-lived access JWT and long-lived refresh JWT in secure HTTP-Only cookies.
- **Access**: Public.
- **Guards & Rate Limiting**:
  - Protected by `rate_limit_by_ip()`.
- **Response**: `HTTP 200 OK` with user payload and `Set-Cookie` headers for `access_token` and `refresh_token`.

---

### `POST /api/public/auth/refresh-token`
- **Purpose**:
  - Reads the cryptographic refresh token directly from client HTTP-Only cookie.
  - Validates token signature, expiration, and checks that the session hash remains active in Redis and DB.
  - Issues a refreshed short-lived access token cookie without requiring password re-entry.
- **Access**: Public (requires valid refresh token cookie).
- **Guards & Rate Limiting**:
  - Protected by `rate_limit_by_ip()`.
- **Response**: `HTTP 200 OK` with refreshed access token cookie.

---

## 2. Administrative User Approval Endpoints

### `GET /api/private/admin/users/pending-registrations`
- **Purpose**:
  - Lists all submitted user registrations currently in `PENDING` status awaiting administrator review.
  - Displays user code, username, email, full name, and registration timestamp.
- **Access**: Restricted to `SUPER_ADMIN` and `ADMIN` via `require_role`.
- **Response**: `HTTP 200 OK` with array (`List[PendingUserResponse]`) of pending user records.

---

### `POST /api/private/admin/users/{user_id}/approve`
- **Purpose**:
  - Formally approves a `PENDING` user account.
  - Transitions account status to `ACTIVE`.
  - Assigns an initial organizational role (defaults to `STAFF_USER` if not specified).
  - Logs the approving administrator's ID for audit retention.
- **Access**: Restricted to `SUPER_ADMIN` and `ADMIN` via `require_role`.
- **Response**: `HTTP 200 OK` with approval confirmation and activated role details.

---

### `POST /api/private/admin/users/{user_id}/reject`
- **Purpose**:
  - Rejects an invalid or unauthorized user registration.
  - Transitions account status to `INACTIVE`.
  - Denies system login eligibility.
- **Access**: Restricted to `SUPER_ADMIN` and `ADMIN` via `require_role`.
- **Response**: `HTTP 200 OK` with rejection status confirmation.
