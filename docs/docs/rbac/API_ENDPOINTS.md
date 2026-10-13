# RBAC Administration Module - API Endpoints Specification

This document specifies the endpoints belonging to the **Role-Based Access Control (`rbac`)** module (`src/modules/rbac/rbac_router.py`), detailing their functional purpose, security access controls, and administrative lifecycle operations.

---

## 1. Diagnostics & Configuration Discovery

### `GET /api/private/admin/rbac/test-guarded-access`
- **Purpose**:
  - Revocation challenge probe testing administrative access.
  - Returns `200 OK` if caller holds `SUPER_ADMIN` or `ADMIN` privileges; returns `403 Forbidden` immediately upon demotion or cache invalidation.
- **Access**: `SUPER_ADMIN`, `ADMIN`.
- **Response**: `HTTP 200 OK` with status probe payload.

---

### `GET /api/private/admin/rbac/configuration`
- **Purpose**:
  - Retrieves unified RBAC configuration: full module-resource-action hierarchy tree and all active system roles with assigned permission codes.
- **Access**: `SUPER_ADMIN`, `ADMIN`.
- **Response**: `HTTP 200 OK` with complete `RBACConfigResponse` object.

---

## 2. User Authorization Inspection & Historical Auditing

### `GET /api/private/admin/rbac/users-role-perms`
- **Purpose**:
  - Enterprise-wide directory listing all users, their assigned roles, direct permission overrides, and resolved effective permissions.
  - Supports filtering by role, account status, and search by username or user code.
- **Access**: `SUPER_ADMIN`, `ADMIN`.
- **Response**: `HTTP 200 OK` with array (`List[UserRBACListItemResponse]`) of user access summaries.

---

### `GET /api/private/admin/rbac/users/{user_id}/role-perms-summary`
- **Purpose**:
  - Retrieves a specific user's identity summary, assigned roles, direct custom overrides, and effective resolved permissions.
- **Access**: `SUPER_ADMIN`, `ADMIN`.
- **Response**: `HTTP 200 OK` with single `UserRBACSummaryResponse` object.

---

### `GET /api/private/admin/rbac/users/{user_id}/snapshot-histories`
- **Purpose**:
  - Retrieves chronological, immutable point-in-time snapshots of a user's roles, direct overrides, and effective permissions.
  - Supports filtering by `fromDate`, `toDate`, and pagination (`limit`, `offset`).
- **Access**: `SUPER_ADMIN`, `ADMIN`.
- **Response**: `HTTP 200 OK` with array (`List[UserSnapshotHistoryResponse]`) of snapshot records.

---

### `POST /api/private/admin/rbac/users/{user_id}/rollback-snapshot`
- **Purpose**:
  - Restores a user's role and permission configuration to a selected point-in-time snapshot.
  - Flushes permission cache and terminates active sessions if demoted.
- **Access**: `SUPER_ADMIN`, `ADMIN`.
- **Response**: `HTTP 200 OK` with `UserRollbackResponse`.

---

## 3. User Role & Direct Permission Mutations

### `POST /api/private/admin/rbac/users/{user_id}/assign-roles`
- **Purpose**:
  - Additively assigns roles to a target user.
  - Enforces governance barriers: rejects self-mutation and assignments at or above operator rank.
  - Automatically combines default permissions and invalidates user cache.
- **Access**: `SUPER_ADMIN`, `ADMIN`.
- **Response**: `HTTP 200 OK` with `UserRoleAssignmentResponse`.

---

### `POST /api/private/admin/rbac/users/{user_id}/demote-roles`
- **Purpose**:
  - Demotes a user by removing specified roles.
  - Rejects self-demotion and demoting users of equal or higher rank.
  - Rejects demoting the last active Super Admin.
  - **Zero-Trust Enforcement**: Flushes Redis permissions cache and terminates active user sessions immediately.
- **Access**: `SUPER_ADMIN`, `ADMIN`.
- **Response**: `HTTP 200 OK` with `DemoteUserRoleResponse`.

---

### `POST /api/private/admin/rbac/users/{user_id}/assign-direct-permissions`
- **Purpose**:
  - Grants or explicitly denies custom direct permissions for a user with mandatory business justification.
- **Access**: `SUPER_ADMIN`, `ADMIN`.
- **Response**: `HTTP 200 OK` with `UserDirectPermissionsResponse`.

---

### `POST /api/private/admin/rbac/users/{user_id}/revoke-direct-permissions`
- **Purpose**:
  - Removes direct permission overrides from a user and invalidates cache, restoring standard role defaults.
- **Access**: `SUPER_ADMIN`, `ADMIN`.
- **Response**: `HTTP 200 OK` with updated `UserDirectPermissionsResponse`.

---

## 4. Role Permission Catalog Governance

### `PUT /api/private/admin/rbac/roles/{role_identifier}/assign-permissions`
- **Purpose**:
  - Replaces the bundle of permissions associated with a specific role.
  - Super Admin permissions are protected as immutable.
  - Invalidates caches for all users currently assigned this role.
- **Access**: `SUPER_ADMIN`, `ADMIN`.
- **Response**: `HTTP 200 OK` with `RolePermissionAssignmentResponse`.

---

### `POST /api/private/admin/rbac/roles/batch-assign-permissions`
- **Purpose**:
  - Atomically updates permissions across multiple roles in a single database transaction.
- **Access**: `SUPER_ADMIN`, `ADMIN`.
- **Response**: `HTTP 200 OK` with `BatchRolePermissionAssignmentResponse`.

---

### `POST /api/private/admin/rbac/roles/{role_identifier}/reset-default-permissions`
- **Purpose**:
  - Reverts a system role's permissions back to its code-defined default preset in `enums.py`.
- **Access**: `SUPER_ADMIN`, `ADMIN`.
- **Response**: `HTTP 200 OK` with restored `RolePermissionAssignmentResponse`.

---

### `GET /api/private/admin/rbac/roles/snapshot-histories`
- **Purpose**:
  - Retrieves enterprise-wide chronological audit trail of all role permission mutations across all system roles.
  - Supports filtering by role identifier, date ranges (`fromDate`, `toDate`), and pagination (`limit`, `offset`).
- **Access**: `SUPER_ADMIN`, `ADMIN`.
- **Response**: `HTTP 200 OK` with array (`List[RoleSnapshotHistoryResponse]`) of role snapshots.

---

### `GET /api/private/admin/rbac/roles/{role_identifier}/snapshot-histories`
- **Purpose**:
  - Retrieves chronological point-in-time snapshots for a specific target role.
- **Access**: `SUPER_ADMIN`, `ADMIN`.
- **Response**: `HTTP 200 OK` with array (`List[RoleSnapshotHistoryResponse]`) of snapshots for the role.

---

### `POST /api/private/admin/rbac/roles/{role_identifier}/rollback-snapshot`
- **Purpose**:
  - Restores role permissions to a historical snapshot and invalidates affected user caches.
- **Access**: `SUPER_ADMIN`, `ADMIN`.
- **Response**: `HTTP 200 OK` with `RoleRollbackResponse`.

---

## 5. Dual-Authorization (Maker-Checker) Workflow

### `GET /api/private/admin/rbac/change-requests/pending-requests`
- **Purpose**:
  - Lists pending dual-control privilege change requests awaiting hierarchical supervisor review.
- **Access**: `SUPER_ADMIN`, `ADMIN`.
- **Response**: `HTTP 200 OK` with array (`List[RBACChangeRequestResponse]`) of pending requests.

---

### `POST /api/private/admin/rbac/change-requests/{request_id}/approve`
- **Purpose**:
  - Approves an RBAC change request.
  - Enforces dual control: requester cannot self-approve (`requested_by_id != reviewed_by_id`).
  - Reviewer rank must strictly exceed requester rank.
  - Applies changes and invalidates target user caches.
- **Access**: `SUPER_ADMIN`, `ADMIN`.
- **Response**: `HTTP 200 OK` with approved `RBACChangeRequestResponse`.

---

### `POST /api/private/admin/rbac/change-requests/{request_id}/reject`
- **Purpose**:
  - Rejects an RBAC change request with mandatory review notes.
- **Access**: `SUPER_ADMIN`, `ADMIN`.
- **Response**: `HTTP 200 OK` with rejected `RBACChangeRequestResponse`.
