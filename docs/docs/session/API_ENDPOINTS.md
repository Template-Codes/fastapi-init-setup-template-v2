# Session Module - API Endpoints & BIR Statutory Compliance

This document specifies the endpoints belonging to the **Session (`session`)** module (`src/modules/session/session_router.py`), detailing their functional purpose and regulatory compliance necessity under Philippine BIR CAS rules.

---

## 1. BIR Statutory Compliance Matrix

| Regulation | BIR Requirement | Architectural Implementation in Session Endpoints |
| :--- | :--- | :--- |
| **Annex B Item 11.c** | Strictly prevent simultaneous active sessions across multiple terminals | Tracks active sessions in `session.sessions` with composite indexing on `(user_id, is_active)` to detect and prevent unauthorized concurrent terminal usage. |
| **Annex B Item 11.c** | User session termination & boundary controls | User logout invalidates the active database session, deletes HTTP-Only cookies, and adds token to Redis blacklist. |
| **Annex B Item 8** | Enterprise activity log & terminal audit trail | Admin session listing exposes client IP address, User-Agent, and last activity timestamps across all terminals. |
| **Annex B Item 11.h** | Immediate privilege revocation & access termination | Administrative force-logout terminates compromised sessions immediately without waiting for token expiry. |

---

## 2. User Session Endpoints

### `POST /api/private/session/logout`
- **Purpose**:
  - Gracefully ends the calling user's active session.
  - Updates `session.sessions` record: marks `is_active = false`.
  - Blacklists the session token in Redis.
  - Clears `access_token` and `refresh_token` HTTP-Only cookies from the client browser.
- **BIR Statutory Necessity**:
  - **Annex B Item 11.c**: Mandates secure termination of operator sessions upon leaving a terminal to prevent unattended workstations from being used by unauthorized persons to post financial entries.
- **Access**: Private (Authenticated user).
- **Response**: `HTTP 200 OK` confirming session termination and cleared cookies.

---

## 3. Administrative Session Governance Endpoints

### `GET /api/private/admin/sessions`
- **Purpose**:
  - Retrieves all active sessions enterprise-wide across all users.
  - Returns user ID, user code, username, session ID, client IP address, User-Agent, and last activity timestamp.
- **BIR Statutory Necessity**:
  - **Annex B Items 8 & 11.c**: Provides real-time supervisory audit capability to detect unauthorized concurrent terminal logins or connections originating from unauthorized IP ranges.
- **Access**: Restricted to `SUPER_ADMIN` and `ADMIN` via `require_role`.
- **Response**: `HTTP 200 OK` with list of active user sessions and terminal metadata.

---

### `DELETE /api/private/admin/sessions/{session_id}`
- **Purpose**:
  - Administratively force-terminates a specific active session by its UUID.
  - Sets `is_active = false` on target session and immediately invalidates cached session state in Redis.
  - The target terminal is blocked on its very next HTTP request.
- **BIR Statutory Necessity**:
  - **Annex B Item 11.h**: Enforces instant administrative revocation of user access when suspicious terminal behavior or security anomalies are identified.
- **Access**: Restricted to `SUPER_ADMIN` and `ADMIN` via `require_role`.
- **Response**: `HTTP 200 OK` confirming targeted session termination.

---

### `POST /api/private/admin/sessions/terminate-all`
- **Purpose**:
  - Emergency enterprise-wide mass termination of ALL active sessions across all users and terminals.
  - Purges all active sessions in the database and flushes Redis active session keys.
  - Requires step-up sudo password verification by the calling administrator.
- **BIR Statutory Necessity**:
  - **Annex B Items 11.c & 11.h**: Critical incident response control mandated during system breach investigations, unauthorized privilege escalation alerts, or urgent emergency maintenance to immediately freeze all active connections to the accounting ledger.
- **Access**:
  - Restricted to `SUPER_ADMIN` and `ADMIN` via `require_role`.
  - Requires step-up administrative verification via `require_sudo_credential` (password verified within the last 5 minutes).
- **Response**: `HTTP 200 OK` confirming enterprise-wide session purge.
