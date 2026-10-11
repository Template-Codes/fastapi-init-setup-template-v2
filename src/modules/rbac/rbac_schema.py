from datetime import datetime
from typing import List, Optional
from uuid import UUID
from pydantic import Field

from base.schema import BaseSchema


class UserPermissionsCachePayload(BaseSchema):
    """Schema representing cached user roles and permissions in Redis."""
    user_id: UUID = Field(..., description="UUID of the user")
    roles: List[str] = Field(default_factory=list, description="List of assigned role names")
    permissions: List[str] = Field(default_factory=list, description="List of assigned permission codes")


class ActionSchema(BaseSchema):
    """Schema for individual action and its canonical permission code."""
    name: str = Field(..., description="Action name (e.g. ACCEPT, CREATE, POST)")
    description: str = Field(..., description="Human-readable action description")
    permission: str = Field(..., description="Canonical permission code (MODULE:RESOURCE:ACTION)")


class ResourceSchema(BaseSchema):
    """Schema for endpoint / entity resource containing actions."""
    name: str = Field(..., description="Resource name (e.g. REGISTRATION, USER)")
    description: str = Field(..., description="Human-readable resource description")
    actions: List[ActionSchema] = Field(default_factory=list, description="Actions available on this resource")


class ModuleSchema(BaseSchema):
    """Schema for high-level system module containing resources."""
    name: str = Field(..., description="Module name (e.g. AUTHENTICATION, PROFILE)")
    description: str = Field(..., description="Human-readable module description")
    resources: List[ResourceSchema] = Field(default_factory=list, description="Resources under this module")


class RoleOverviewSchema(BaseSchema):
    """Schema for system role with description, rank, and active permission codes."""
    id: UUID = Field(..., description="Database UUID of the role")
    name: str = Field(..., description="Role name (e.g. ADMIN, STAFF_USER)")
    rank: int = Field(0, description="Numeric hierarchical rank of the role")
    description: Optional[str] = Field(None, description="Human-readable role description")
    is_system_role: bool = Field(False, description="Whether this is an immutable system role")
    permissions: List[str] = Field(default_factory=list, description="Assigned canonical permission codes")


class RBACConfigResponse(BaseSchema):
    """
    Unified configuration response providing both the hierarchical permission
    tree and all active system roles with their granted permissions.
    """
    modules: List[ModuleSchema] = Field(..., description="Hierarchical module/resource/action tree")
    roles: List[RoleOverviewSchema] = Field(..., description="All active roles and their granted permissions")


class UserRBACSummaryResponse(BaseSchema):
    """Summary of a user's roles, direct custom overrides, and effective permissions."""
    user_id: UUID
    user_code: Optional[str] = None
    username: Optional[str] = None
    highest_rank: int = Field(0, description="Highest numeric rank among assigned roles")
    roles: List[str] = Field(default_factory=list)
    direct_grants: List[str] = Field(default_factory=list, description="Custom direct permission grants")
    direct_revocations: List[str] = Field(default_factory=list, description="Custom direct permission denials")
    permissions: List[str] = Field(default_factory=list, description="Effective permission set")


class RoleSimpleSchema(BaseSchema):
    """Simplified role representation with ID, name, and rank."""
    id: UUID
    name: str
    rank: int = Field(0, description="Hierarchical numeric rank")


class PermissionSimpleSchema(BaseSchema):
    """Simplified permission representation with ID and canonical code."""
    id: UUID
    code: str


class UserRBACListItemResponse(BaseSchema):
    """Enriched user summary with role and permission UUIDs for enterprise list views."""
    user_id: UUID
    user_code: Optional[str] = None
    username: str
    email: str
    status: str
    highest_rank: int = Field(0, description="Highest numeric rank among assigned roles")
    roles: List[RoleSimpleSchema] = Field(default_factory=list)
    direct_grants: List[PermissionSimpleSchema] = Field(default_factory=list)
    direct_revocations: List[PermissionSimpleSchema] = Field(default_factory=list)
    permissions: List[PermissionSimpleSchema] = Field(default_factory=list)


class AssignUserRolesPayload(BaseSchema):
    """Request payload for assigning roles to a user (accepts role names or UUIDs)."""
    roles: List[str] = Field(
        ...,
        min_length=1,
        description="List of role names (e.g. 'ADMIN') or role UUIDs to assign",
    )
    reason: str = Field(
        ...,
        min_length=5,
        max_length=255,
        description="Mandatory justification reason for audit trail",
    )


class AssignRolePermissionsPayload(BaseSchema):
    """Request payload for assigning permissions to a role (accepts permission codes or UUIDs)."""
    permissions: List[str] = Field(
        default_factory=list,
        description="List of canonical permission codes (e.g. 'AUTHENTICATION:USER:READ') or UUIDs",
    )
    reason: str = Field(
        ...,
        min_length=5,
        max_length=255,
        description="Mandatory justification reason for audit trail",
    )


class RoleAssignmentItem(BaseSchema):
    """Single role assignment specification for batch processing."""
    role: str = Field(..., description="Target role name or UUID")
    permissions: List[str] = Field(default_factory=list, description="List of permission codes or UUIDs")


class BatchRolePermissionAssignmentPayload(BaseSchema):
    """Request payload for batch updating permissions across multiple roles."""
    assignments: List[RoleAssignmentItem] = Field(..., min_length=1, description="List of role permission assignments")
    reason: str = Field(
        ...,
        min_length=5,
        max_length=255,
        description="Mandatory justification reason for audit trail",
    )


class AssignUserDirectPermissionsPayload(BaseSchema):
    """Request payload for granting or denying direct custom permissions per user."""
    permissions: List[str] = Field(..., min_length=1, description="List of permission codes or UUIDs")
    is_granted: bool = Field(True, description="True for explicit grant, False for explicit denial")
    reason: str = Field(..., min_length=5, max_length=255, description="Mandatory justification reason for audit trail")


class RemoveUserDirectPermissionsPayload(BaseSchema):
    """Request payload for removing direct custom permission overrides from a user."""
    permissions: List[str] = Field(..., min_length=1, description="List of permission codes or UUIDs to remove")
    reason: str = Field(..., min_length=5, max_length=255, description="Mandatory justification reason for audit trail")


class UserDirectPermissionsResponse(BaseSchema):
    """Response returned upon updating user direct permission overrides."""
    status: bool = True
    message: str
    user_id: UUID
    direct_grants: List[str] = Field(default_factory=list)
    direct_revocations: List[str] = Field(default_factory=list)


class UserRoleAssignmentResponse(BaseSchema):
    """Response returned upon assigning roles to a user."""
    status: bool = True
    message: str
    user_id: UUID
    assigned_roles: List[str] = Field(default_factory=list)
    requires_approval: bool = Field(False, description="True if change was queued as pending approval")
    request_id: Optional[UUID] = Field(None, description="Change request UUID if queued for approval")


class RolePermissionAssignmentResponse(BaseSchema):
    """Response returned upon assigning permissions to a role."""
    status: bool = True
    message: str
    role_id: UUID
    role_name: str
    assigned_permissions: List[str] = Field(default_factory=list)
    requires_approval: bool = Field(False, description="True if change was queued as pending approval")
    request_id: Optional[UUID] = Field(None, description="Change request UUID if queued for approval")


class BatchRolePermissionAssignmentResponse(BaseSchema):
    """Response returned upon batch updating role permissions."""
    status: bool = True
    message: str
    updated_roles: List[str] = Field(default_factory=list)


class ReviewChangeRequestPayload(BaseSchema):
    """Request payload for reviewing (approving or rejecting) an RBAC change request."""
    review_notes: Optional[str] = Field(None, max_length=255, description="Optional reviewer notes")


class RBACChangeRequestResponse(BaseSchema):
    """Response schema representing an RBAC dual-authorization change request."""
    id: UUID
    request_type: str
    target_user_id: Optional[UUID] = None
    target_role_id: Optional[UUID] = None
    requested_payload: str
    status: str
    reason: str
    requested_by_id: UUID
    reviewed_by_id: Optional[UUID] = None
    review_notes: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    created_at: datetime


class OperatorSummarySchema(BaseSchema):
    """Summary of the operator who executed an administrative mutation (None user_id represents SYSTEM)."""
    user_id: Optional[UUID] = None
    username: str = "SYSTEM"


class RoleSnapshotHistoryResponse(BaseSchema):
    """Point-in-time snapshot history item for role permissions."""
    snapshot_id: UUID
    role_id: UUID
    role_name: str
    timestamp: datetime
    permissions: List[PermissionSimpleSchema]
    total_permissions: int
    updated_by: OperatorSummarySchema
    reason: str


class UserSnapshotHistoryResponse(BaseSchema):
    """Point-in-time snapshot history item for user roles and effective permissions."""
    snapshot_id: UUID
    user_id: UUID
    username: str
    timestamp: datetime
    roles: List[RoleSimpleSchema]
    direct_permissions: List[PermissionSimpleSchema]
    effective_permissions: List[PermissionSimpleSchema]
    total_permissions: int
    updated_by: OperatorSummarySchema
    reason: str


class RoleRollbackPayload(BaseSchema):
    """Request payload for rolling back role permissions to a historical snapshot."""
    snapshot_id: UUID = Field(..., description="Target snapshot ID to restore")
    reason: str = Field(..., min_length=5, max_length=255, description="Auditable justification for the rollback")


class RoleRollbackResponse(BaseSchema):
    """Response schema following a role permission rollback."""
    status: bool = True
    message: str
    role_id: UUID
    role_name: str
    restored_from_snapshot_id: UUID
    restored_permissions: List[str]
    total_permissions: int


class UserDirectPermissionItem(BaseSchema):
    """Representation of a direct permission grant or revocation."""
    id: UUID
    code: str
    is_granted: bool


class UserRollbackPayload(BaseSchema):
    """Request payload for rolling back a user's RBAC state to a historical snapshot."""
    snapshot_id: UUID = Field(..., description="Target snapshot ID to restore")
    reason: str = Field(..., min_length=5, max_length=255, description="Auditable justification for the rollback")


class UserRollbackResponse(BaseSchema):
    """Response schema following a user RBAC state rollback."""
    status: bool = True
    message: str
    user_id: UUID
    username: str
    restored_from_snapshot_id: UUID
    restored_roles: List[str]
    restored_direct_permissions: List[UserDirectPermissionItem]
    effective_permissions: List[str]
    total_effective_permissions: int
