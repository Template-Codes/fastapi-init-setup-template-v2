# RBAC Administration Module - API Endpoints & BIR Statutory Compliance

This document specifies the endpoints belonging to the **Role-Based Access Control (`rbac`)** module (`src/modules/rbac/rbac_router.py`), detailing their functional purpose and regulatory compliance necessity under Philippine BIR CAS rules.

---

## 1. BIR Statutory Compliance Matrix

| Regulation | BIR Requirement | Architectural Implementation in RBAC Endpoints |
| :--- | :--- | :--- |
| **Annex B Item 11.e** | Role-Based Access Control & Segregation of Duties | Endpoints govern roles and atomic permissions, restricting non-administrative users from executing unauthorized accounting entries or overriding programs. |
| **Annex B Item 11.h** | Immediate privilege revocation upon role demotion | Demoting a user (`/demote`) instantly evicts Redis cached permissions and terminates all active sessions for that user across all terminals. |
| **Annex B Item 8 & 11.i** | Tamper-proof audit logs & historical immutability | Historical snapshot endpoints (`/history`) query append-only JSON ledgers proving the exact permissions an operator held when any transaction was posted. |
| **Annex B Item 10.c & 10.f** | Prohibition of unauthorized privilege overrides | Dual-authorization change request endpoints (`/requests/*`) mandate independent supervisor approval before applying privilege escalations. |

---

## 2. Diagnostics & Configuration Discovery

### `GET /api/private/admin/rbac/test-guarded-access`
- **Purpose**:
  - Revocation challenge probe testing administrative access.
  - Returns `200 OK` if caller holds `SUPER_ADMIN` or `ADMIN` privileges; returns `403 Forbidden` immediately upon demotion.
- **BIR Statutory Necessity**:
  - **Annex B Item 11.h**: Provides automated verification that privilege demotions take effect immediately across all middleware without caching lag.
- **Access**: `SUPER_ADMIN`, `ADMIN`.

---

### `GET /api/private/admin/rbac`
- **Purpose**:
  - Retrieves unified RBAC hierarchy: full module-resource-action tree and all active system roles with assigned permission codes.
- **BIR Statutory Necessity**:
  - **Annex B Item 11.e**: Provides tax auditors with an official, inspectable catalog of all system access rights, modules, and authorization boundaries.
- **Access**: `SUPER_ADMIN`, `ADMIN`.

---

## 3. User Authorization Inspection & Historical Auditing

### `GET /api/private/admin/rbac/users-role-perms`
- **Purpose**:
  - Paginated enterprise-wide directory listing all users, their assigned roles, direct permission overrides, and resolved effective permissions.
  - Supports filtering by role, account status, and search by username/code.
- **BIR Statutory Necessity**:
  - **Annex B Items 8 & 11.e**: Facilitates periodic user access reviews and compliance audits of user authorities across all accounting divisions.
- **Access**: `SUPER_ADMIN`, `ADMIN`.

---

### `GET /api/private/admin/rbac/users/{user_id}`
- **Purpose**:
  - Retrieves a specific user's identity summary, assigned roles, direct grants/denials, and effective permissions.
- **BIR Statutory Necessity**:
  - **Annex B Item 11.e**: Verifies the specific operational capabilities of an operator under audit.
- **Access**: `SUPER_ADMIN`, `ADMIN`.

---

### `GET /api/private/admin/rbac/users/{user_id}/history`
- **Purpose**:
  - Retrieves chronological, immutable point-in-time snapshots (`rbac.user_rbac_snapshots`) of a user's roles, direct overrides, and effective permissions.
  - Includes timestamp, modifying administrator ID, and justification reason.
- **BIR Statutory Necessity**:
  - **Annex B Items 8 & 11.i**: Crucial audit evidence. Proves to tax examiners what exact permissions an operator held at the millisecond an invoice, voucher, or journal entry was posted.
- **Access**: `SUPER_ADMIN`, `ADMIN`.

---

### `POST /api/private/admin/rbac/users/{user_id}/rollback`
- **Purpose**:
  - Restores a user's role and permission configuration to a previous point-in-time snapshot.
  - Flushes permission cache and logs rollback justification.
- **BIR Statutory Necessity**:
  - **Annex B Items 8 & 11.e**: Rapid incident remediation. Allows authorized administrators to instantly revert accidental or unauthorized privilege assignments while logging a permanent rollback trail.
- **Access**: `SUPER_ADMIN`, `ADMIN`.

---

## 4. User Role & Permission Mutations

### `PUT /api/private/admin/rbac/users/{user_id}/roles`
- **Purpose**:
  - Additively assigns roles to a target user.
  - Enforces governance barriers: rejects self-mutation and assignments at or above operator rank.
  - Automatically combines default permissions and invalidates user cache.
- **BIR Statutory Necessity**:
  - **Annex B Item 11.e**: Enforces hierarchical separation of duties, ensuring administrators cannot elevate themselves or assign roles beyond their authorization ceiling.
- **Access**: `SUPER_ADMIN`, `ADMIN`.

---

### `POST /api/private/admin/rbac/users/{user_id}/demote`
- **Purpose**:
  - Demotes a user by removing specified roles.
  - Rejects self-demotion and demoting users of equal or higher rank.
  - Rejects demoting the last active Super Admin.
  - **Zero-Trust Enforcement**: Flushes Redis permissions cache and terminates active user sessions immediately.
- **BIR Statutory Necessity**:
  - **Annex B Item 11.h**: Enforces instant revocation. Demoted operators cannot continue executing privileged accounting actions using pre-existing sessions.
- **Access**: `SUPER_ADMIN`, `ADMIN`.

---

### `POST /api/private/admin/rbac/users/{user_id}/permissions`
- **Purpose**:
  - Grants or explicitly denies custom direct permissions for a user with mandatory business justification.
- **BIR Statutory Necessity**:
  - **Annex B Items 8 & 11.e**: Requires documented justification for any exception to standard roles, logged permanently in audit records.
- **Access**: `SUPER_ADMIN`, `ADMIN`.

---

### `DELETE /api/private/admin/rbac/users/{user_id}/permissions`
- **Purpose**:
  - Removes direct permission overrides from a user and invalidates cache.
- **BIR Statutory Necessity**:
  - **Annex B Item 11.e**: Reverts user permissions strictly to their assigned role baselines.
- **Access**: `SUPER_ADMIN`, `ADMIN`.

---

## 5. Role Permission Catalog Governance

### `PUT /api/private/admin/rbac/roles/{role_identifier}/permissions`
- **Purpose**:
  - Updates the bundle of permissions associated with a role.
  - Super Admin permissions are protected as immutable.
  - Invalidates caches for all users currently assigned this role.
- **BIR Statutory Necessity**:
  - **Annex B Item 11.e**: Modifies operational duties while protecting core system administrative definitions.
- **Access**: `SUPER_ADMIN`, `ADMIN`.

---

### `POST /api/private/admin/rbac/roles/batch-assign-permissions`
- **Purpose**:
  - Atomically updates permissions across multiple roles in a single database transaction.
- **BIR Statutory Necessity**:
  - **Annex B Item 11.e**: Atomic privilege alignment across organizational job titles without partial-state corruption.
- **Access**: `SUPER_ADMIN`, `ADMIN`.

---

### `POST /api/private/admin/rbac/roles/{role_identifier}/reset-defaults`
- **Purpose**:
  - Reverts a system role's permissions to its code-defined default preset in `enums.py`.
- **BIR Statutory Necessity**:
  - **Annex B Item 11.e**: Allows rapid restoration of certified baseline permission matrices approved during BIR CAS evaluation.
- **Access**: `SUPER_ADMIN`, `ADMIN`.

---

### `GET /api/private/admin/rbac/roles/history`
- **Purpose**:
  - Retrieves enterprise-wide chronological audit trail of all role permission mutations across all system roles.
  - Supports filtering by role identifier, date ranges (`fromDate`, `toDate`), and pagination (`limit`, `offset`).
- **BIR Statutory Necessity**:
  - **Annex B Items 8 & 11.i**: Enterprise-wide append-only audit trail proving all role modifications and privilege reassignments over time for tax authority and statutory examinations.
- **Access**: `SUPER_ADMIN`, `ADMIN`.

---

### `GET /api/private/admin/rbac/roles/{role_identifier}/history`
- **Purpose**:
  - Retrieves chronological point-in-time snapshots (`rbac.role_permission_snapshots`) for a specific target role.
  - Returns complete serialized permissions array `[{id, code}]`, modifying administrator ID (`changed_by_id`), and change justification.
- **BIR Statutory Necessity**:
  - **Annex B Items 8 & 11.i**: Isolated role auditability. Provides non-repudiation proof of a specific role's permission set during any historical tax period.
- **Access**: `SUPER_ADMIN`, `ADMIN`.

---

### `POST /api/private/admin/rbac/roles/{role_identifier}/rollback`
- **Purpose**:
  - Restores role permissions to a historical snapshot and invalidates affected user caches.
- **BIR Statutory Necessity**:
  - **Annex B Items 8 & 11.e**: Rapid remediation of role definition regressions with permanent audit trail logging.
- **Access**: `SUPER_ADMIN`, `ADMIN`.

---

## 6. Dual-Authorization (Maker-Checker) Workflow

### `GET /api/private/admin/rbac/requests`
- **Purpose**:
  - Lists pending dual-control privilege change requests awaiting hierarchical supervisor review.
- **BIR Statutory Necessity**:
  - **Annex B Item 11.a & Item 8**: Provides supervisory queue for sensitive privilege escalations.
- **Access**: `SUPER_ADMIN`, `ADMIN`.

---

### `POST /api/private/admin/rbac/requests/{request_id}/approve`
- **Purpose**:
  - Approves an RBAC change request.
  - Enforces dual control: requester cannot self-approve (`requested_by_id != reviewed_by_id`).
  - Reviewer rank must strictly exceed requester rank.
  - Applies changes and invalidates target user caches.
- **BIR Statutory Necessity**:
  - **Annex B Items 8, 11.e, 11.i**: Mandates two-person integrity (Maker-Checker) for privilege elevations, preventing unilateral administrative compromise.
- **Access**: `SUPER_ADMIN`, `ADMIN`.

---

### `POST /api/private/admin/rbac/requests/{request_id}/reject`
- **Purpose**:
  - Rejects an RBAC change request with mandatory review notes.
- **BIR Statutory Necessity**:
  - **Annex B Items 8 & 11.i**: Preserves permanent audit record of rejected privilege escalation attempts.
- **Access**: `SUPER_ADMIN`, `ADMIN`.
