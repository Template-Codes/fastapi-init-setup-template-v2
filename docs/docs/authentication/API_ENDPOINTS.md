# Authentication Module - API Endpoints & BIR Statutory Compliance

This document specifies the endpoints belonging to the **Authentication (`auth`)** module (`src/modules/authentication/auth_router.py`), detailing their functional purpose and regulatory compliance necessity under Philippine BIR CAS rules.

---

## 1. BIR Statutory Compliance Matrix

| Regulation | BIR Requirement | Architectural Implementation in Auth Endpoints |
| :--- | :--- | :--- |
| **Annex B Item 11.a** | Controlled user registration & supervisory vetting | Self-registered accounts enter `PENDING` status. Administrative approval is mandatory before any user can log in. |
| **Annex B Item 10.g** | Every record stamped with creating user's ID | Credential verification binds identity to JWT cookies, establishing the non-forgeable `user_id` injected into all business transactions. |
| **Annex B Item 11.b** | Alphanumeric password complexity & secure hashing | Passwords verified and hashed using Argon2id with salt. Plaintext is never persisted. |
| **Annex B Item 11.c** | Account lockout on consecutive failed sign-ons | Brute-force protection sets `banned_until_time` on user account, blocking further attempts. |
| **Annex B Item 11.i** | Audit trails protected from deletion | User rejection marks accounts `INACTIVE` rather than executing destructive database deletes. |

---

## 2. Public Authentication Endpoints

### `POST /api/public/auth/registration`
- **Purpose**:
  - Accepts new user registration data (username, email, password, personal details).
  - Assigns unique sequential identifier (`USR-XXXXX`) via database sequence `auth.user_code_seq`.
  - Hashes raw password using Argon2id.
  - Automatically flags the new user account with status `PENDING`.
- **BIR Statutory Necessity**:
  - **Annex B Item 11.a**: Prohibits unverified users from gaining immediate access to the accounting database. Self-registered personnel remain quarantined in `PENDING` status until an authorized administrator verifies their identity and business role.
- **Guards & Rate Limiting**:
  - Protected by `rate_limit_by_ip()` to block automated credential stuffing and bot registration floods.
- **Response**: `HTTP 201 Created` with registration summary and confirmation of `PENDING` state.

---

### `POST /api/public/auth/auth-tokens`
- **Purpose**:
  - Authenticates username/email and password credentials.
  - Verifies that account status is strictly `ACTIVE`.
  - Checks if the user is currently under a temporary lockout (`banned_until_time`).
  - Records client telemetry (client IP address and User-Agent string) in `session.sessions`.
  - Issues short-lived access JWT (15 minutes) and long-lived refresh JWT (7 days) in secure HTTP-Only cookies.
- **BIR Statutory Necessity**:
  - **Annex B Item 10.g**: Core identity verification mechanism. Ensures that every subsequent transaction created in the CAS has a verified cryptographic identity for the mandatory `created_by` audit stamp.
  - **Annex B Item 11.c**: Validates account lockout threshold to prevent brute-force sign-on attempts.
- **Guards & Rate Limiting**:
  - Protected by `rate_limit_by_ip()`.
- **Response**: `HTTP 200 OK` with user payload and `Set-Cookie` headers for `access_token` and `refresh_token`.

---

### `POST /api/public/auth/refresh-token`
- **Purpose**:
  - Reads the cryptographic refresh token directly from client HTTP-Only cookie.
  - Validates token signature, expiration, and checks that the session hash remains active in database/Redis.
  - Issues a refreshed short-lived access token cookie without requiring the user to re-type their password.
- **BIR Statutory Necessity**:
  - **Annex B Item 11.c**: Enforces session continuity while minimizing exposure of long-lived access tokens. If an administrator deactivates a user or revokes a session, token refresh is immediately rejected, locking out unauthorized access.
- **Guards & Rate Limiting**:
  - Protected by `rate_limit_by_ip()`.
- **Response**: `HTTP 200 OK` with refreshed access token cookie.

---

## 3. Administrative User Approval Endpoints (Maker-Checker Governance)

### `GET /api/private/admin/users/pending`
- **Purpose**:
  - Lists all submitted user registrations currently in `PENDING` status awaiting supervisory review.
  - Displays user code, username, email, full name, and registration timestamp.
- **BIR Statutory Necessity**:
  - **Annex B Item 11.a & Item 8**: Provides supervisory visibility into unverified access requests, ensuring compliance officers can audit onboarding queues.
- **Access**: Restricted to `SUPER_ADMIN` and `ADMIN` via `require_role`.
- **Response**: `HTTP 200 OK` with array of pending user records.

---

### `POST /api/private/admin/users/{user_id}/approve`
- **Purpose**:
  - Formally approves a `PENDING` user account.
  - Transitions account status to `ACTIVE`.
  - Assigns an initial organizational role (defaults to `STAFF_USER` if not specified).
  - Logs the approving administrator's ID for audit retention.
- **BIR Statutory Necessity**:
  - **Annex B Item 11.a**: Mandates administrative authorization before granting access to electronic accounting books.
  - **Annex B Item 8**: Generates a permanent supervisory audit trail identifying which administrator approved access.
- **Access**: Restricted to `SUPER_ADMIN` and `ADMIN` via `require_role`.
- **Response**: `HTTP 200 OK` with approval confirmation and activated role details.

---

### `POST /api/private/admin/users/{user_id}/reject`
- **Purpose**:
  - Rejects an invalid or unauthorized user registration.
  - Transitions account status to `INACTIVE`.
  - Denies system login eligibility permanently.
- **BIR Statutory Necessity**:
  - **Annex B Item 11.a & 11.i**: Rejected registration records are **not** deleted from the database. Transitioning to `INACTIVE` preserves the applicant's IP, email, and timestamp for historical auditor inspection and non-repudiation.
- **Access**: Restricted to `SUPER_ADMIN` and `ADMIN` via `require_role`.
- **Response**: `HTTP 200 OK` with rejection status confirmation.
