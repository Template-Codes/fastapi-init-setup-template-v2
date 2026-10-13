# Session Module - API Endpoints Specification

This document specifies the endpoints belonging to the **Session (`session`)** module (`src/modules/session/session_router.py`), detailing their functional purpose, security access controls, and administrative lifecycle operations.

---

## 1. User Session Endpoints

### `POST /api/private/session/logout`
- **Purpose**:
  - Gracefully ends the calling user's active session.
  - Updates `session.sessions` record: marks `is_active = false`.
  - Removes the session key from Redis cache.
  - Clears `access_token` and `refresh_token` HTTP-Only cookies from the client browser.
- **Access**: Private (Authenticated user).
- **Response**: `HTTP 200 OK` confirming session termination and cleared cookies.

---

## 2. Administrative Session Governance Endpoints

### `GET /api/private/admin/sessions/active-sessions`
- **Purpose**:
  - Retrieves all currently active sessions enterprise-wide across all users.
  - Returns user ID, user code, username, session ID, client IP address, User-Agent, and last activity timestamp.
- **Access**: Restricted to `SUPER_ADMIN` and `ADMIN` via `require_role`.
- **Response**: `HTTP 200 OK` with array (`List[AdminUserSessionListItemResponse]`) of active user sessions and terminal metadata.

---

### `DELETE /api/private/admin/sessions/{session_id}/terminate`
- **Purpose**:
  - Administratively force-terminates a specific active session by its UUID.
  - Sets `is_active = false` on target session and immediately invalidates cached session state in Redis.
  - The target terminal is blocked on its very next HTTP request.
- **Access**: Restricted to `SUPER_ADMIN` and `ADMIN` via `require_role`.
- **Response**: `HTTP 200 OK` confirming targeted session termination.

---

### `POST /api/private/admin/sessions/terminate-all`
- **Purpose**:
  - Emergency enterprise-wide mass termination of ALL active sessions across all users and terminals.
  - Requires re-authentication with administrator credentials (`admin_username`, `admin_password`) in the request body to guard against accidental or rogue mass evictions.
  - Marks all sessions inactive in PostgreSQL and purges session cache sets in Redis.
- **Access**: Restricted to `SUPER_ADMIN` and `ADMIN` via `require_role` and `verify_admin_user_credential`.
- **Response**: `HTTP 200 OK` with count of terminated sessions.
