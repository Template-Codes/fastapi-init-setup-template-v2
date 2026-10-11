from datetime import datetime, timezone
import json
from typing import List, Optional, Sequence
from uuid import UUID
from fastapi import Depends
from loguru import logger

from exceptions.app_exception import (
    BadRequestException,
    ConflictException,
    ForbiddenException,
    NotFoundException,
)
from modules.rbac.rbac_model import RBACChangeRequestStatus
from modules.authentication.auth_repository import AuthenticationRepository
from modules.rbac.rbac_repository import RBACRepository
from modules.rbac.rbac_schema import (
    AssignUserDirectPermissionsPayload,
    BatchRolePermissionAssignmentPayload,
    BatchRolePermissionAssignmentResponse,
    ModuleSchema,
    OperatorSummarySchema,
    PermissionSimpleSchema,
    RBACChangeRequestResponse,
    RBACConfigResponse,
    ReviewChangeRequestPayload,
    RoleOverviewSchema,
    RolePermissionAssignmentResponse,
    RoleSimpleSchema,
    RoleSnapshotHistoryResponse,
    UserDirectPermissionsResponse,
    UserPermissionsCachePayload,
    UserRBACListItemResponse,
    UserRBACSummaryResponse,
    UserRoleAssignmentResponse,
    UserSnapshotHistoryResponse,
)
from modules.session.session_repo import UserSessionRepository
from shares.enums import (
    ROLE_DEFAULT_PERMISSIONS,
    RoleName,
    SystemPermission,
    build_rbac_hierarchy,
    get_role_rank,
    get_user_highest_rank,
)
from utils.maintain_cache_key import MaintainCacheKeyUtils


class RBACService:
    """
    Service handling RBAC configuration resolution, Redis caching,
    governance refusal rules, hierarchical dual-control change requests,
    and immediate cache/session revocation.
    """

    def __init__(
        self,
        rbac_repo: RBACRepository = Depends(),
        auth_repo: AuthenticationRepository = Depends(),
        session_repo: UserSessionRepository = Depends(),
        cache_utils: MaintainCacheKeyUtils = Depends(),
    ):
        self.rbac_repo = rbac_repo
        self.auth_repo = auth_repo
        self.session_repo = session_repo
        self.cache_utils = cache_utils


    async def get_or_cache_user_permissions(self, user_id: UUID) -> UserPermissionsCachePayload:
        """
        Retrieves user roles and permissions from Redis cache (~0.5ms).
        On cache miss, queries PostgreSQL DB via RBACRepository, warms Redis cache, and returns payload.
        """
        user_id_str = str(user_id)
        key = self.cache_utils.create_user_permission_cache_key(user_id_str)

        try:
            cached_raw = await self.cache_utils.async_cache.get(key)
            if cached_raw is not None:
                data = json.loads(cached_raw) if isinstance(cached_raw, (str, bytes)) else cached_raw
                return UserPermissionsCachePayload(
                    user_id=UUID(str(data.get("user_id", user_id))),
                    roles=data.get("roles", []),
                    permissions=data.get("permissions", []),
                )
        except Exception as e:
            logger.warning(f"Error reading user permissions from Redis for user {user_id}: {e}")

        logger.info(f"Redis cache miss for user_permission:{user_id}. Querying PostgreSQL DB...")
        db_payload = await self.rbac_repo.get_user_roles_and_permissions(user_id)

        await self.cache_utils.cache_user_permissions(user_id_str, db_payload)

        return UserPermissionsCachePayload(
            user_id=user_id,
            roles=db_payload.get("roles", []),
            permissions=db_payload.get("permissions", []),
        )


    async def invalidate_user_permissions(self, user_id: UUID) -> None:
        """
        Invalidates cached permissions for a user in Redis.
        Must be called post-commit when mutating roles or direct permissions.
        """
        await self.cache_utils.invalidate_user_permission_cache(str(user_id))


    async def get_rbac_configuration(self) -> RBACConfigResponse:
        """
        Returns unified RBAC configuration containing both:
        1. Hierarchical Module -> Resource -> Action tree directly from enums.py (source of truth).
        2. All active database roles with their ranks and granted permission codes.
        """
        hierarchy_modules = build_rbac_hierarchy()
        roles_entities = await self.rbac_repo.get_all_roles()

        roles_overview = [
            RoleOverviewSchema(
                id=r.id,
                name=r.name,
                rank=get_role_rank(r.name),
                description=r.description,
                is_system_role=r.is_system_role,
                permissions=[p.code for p in r.permissions],
            )
            for r in roles_entities
        ]

        return RBACConfigResponse(
            modules=[ModuleSchema.model_validate(m) for m in hierarchy_modules],
            roles=roles_overview,
        )


    async def get_user_rbac_summary(self, user_id: UUID) -> UserRBACSummaryResponse:
        """Retrieves user's assigned roles, direct grants, explicit denials, and effective permissions."""
        user = await self.auth_repo.get_by_id(user_id)
        if not user:
            logger.warning(f"User {user_id} not found when retrieving RBAC summary.")
            raise NotFoundException(message="User not found.", error_code="USER_NOT_FOUND")

        db_payload = await self.rbac_repo.get_user_roles_and_permissions(user_id)
        highest_rank = get_user_highest_rank(db_payload.get("roles", []))

        return UserRBACSummaryResponse(
            user_id=user.id,
            user_code=user.user_code,
            username=user.username,
            highest_rank=highest_rank,
            roles=db_payload.get("roles", []),
            direct_grants=db_payload.get("direct_grants", []),
            direct_revocations=db_payload.get("direct_revocations", []),
            permissions=db_payload.get("permissions", []),
        )


    async def list_all_users_rbac_summary(
        self,
        role: Optional[str] = None,
        search: Optional[str] = None,
        status_filter: Optional[str] = None,
    ) -> List[UserRBACListItemResponse]:
        """
        Retrieves enterprise-wide user list with assigned roles and effective permissions,
        including database UUIDs for both roles and permissions.
        Optimized with a single batched database query.
        """
        valid_role_names = {r.value for r in RoleName}
        valid_perm_codes = {p.value for p in SystemPermission}

        users = await self.rbac_repo.get_all_users_with_rbac_details(
            role=role,
            search=search,
            status_filter=status_filter,
        )

        results: List[UserRBACListItemResponse] = []
        for u in users:
            active_roles = [r for r in u.roles if r.name in valid_role_names]
            role_schemas = [
                RoleSimpleSchema(
                    id=r.id,
                    name=r.name,
                    rank=get_role_rank(r.name),
                )
                for r in active_roles
            ]
            highest_rank = get_user_highest_rank([r.name for r in active_roles])

            effective_perms_map: dict[str, PermissionSimpleSchema] = {}
            for r in active_roles:
                for p in r.permissions:
                    if p.code in valid_perm_codes:
                        effective_perms_map[p.code] = PermissionSimpleSchema(id=p.id, code=p.code)

            direct_grants: List[PermissionSimpleSchema] = []
            direct_revocations: List[PermissionSimpleSchema] = []

            for up in u.direct_permissions:
                p = up.permission
                if p and p.code in valid_perm_codes:
                    schema_item = PermissionSimpleSchema(id=p.id, code=p.code)
                    if up.is_granted:
                        direct_grants.append(schema_item)
                        effective_perms_map[p.code] = schema_item
                    else:
                        direct_revocations.append(schema_item)
                        effective_perms_map.pop(p.code, None)

            sorted_effective = sorted(effective_perms_map.values(), key=lambda p: p.code)

            results.append(
                UserRBACListItemResponse(
                    user_id=u.id,
                    user_code=u.user_code,
                    username=u.username,
                    email=u.email,
                    status=str(u.status.value) if hasattr(u.status, "value") else str(u.status),
                    highest_rank=highest_rank,
                    roles=role_schemas,
                    direct_grants=direct_grants,
                    direct_revocations=direct_revocations,
                    permissions=sorted_effective,
                )
            )

        return results


    async def _capture_user_rbac_snapshot(
        self,
        user_id: UUID,
        changed_by_id: UUID,
        reason: str,
    ) -> None:
        """
        Captures an immutable point-in-time snapshot of user roles, direct permissions,
        and resolved effective permissions.
        """
        self.rbac_repo.db.expire_all()
        user_rbac_user = await self.rbac_repo.get_user_with_rbac_details(user_id)
        if not user_rbac_user:
            return

        valid_role_names = {r.value for r in RoleName}
        valid_perm_codes = {p.value for p in SystemPermission}

        active_roles = [r for r in user_rbac_user.roles if r.name in valid_role_names]
        roles_payload = [
            {"id": str(r.id), "name": r.name, "rank": get_role_rank(r.name)}
            for r in active_roles
        ]

        direct_permissions_payload = []
        effective_map: dict[str, dict] = {}

        # 1. Role-based permissions
        for r in active_roles:
            for p in r.permissions:
                if p.code in valid_perm_codes:
                    effective_map[p.code] = {"id": str(p.id), "code": p.code}

        # 2. Direct permissions
        for up in user_rbac_user.direct_permissions:
            p = up.permission
            if p and p.code in valid_perm_codes:
                direct_permissions_payload.append({
                    "id": str(p.id),
                    "code": p.code,
                    "is_granted": up.is_granted,
                })
                if up.is_granted:
                    effective_map[p.code] = {"id": str(p.id), "code": p.code}
                else:
                    effective_map.pop(p.code, None)

        effective_permissions_payload = sorted(list(effective_map.values()), key=lambda x: x["code"])

        await self.rbac_repo.create_user_rbac_snapshot(
            user_id=user_id,
            roles_payload=roles_payload,
            direct_permissions_payload=direct_permissions_payload,
            effective_permissions_payload=effective_permissions_payload,
            changed_by_id=changed_by_id,
            reason=reason,
        )


    async def assign_roles_to_user(
        self,
        operator_id: UUID,
        user_id: UUID,
        role_identifiers: Sequence[str],
        reason: str,
    ) -> UserRoleAssignmentResponse:
        """
        Assigns or updates roles for a target user with strict governance refusals:
        1. Operators cannot modify their own roles (self-mutation refused).
        2. Operators cannot modify users with equal or higher rank.
        3. Operators cannot assign roles with rank equal to or exceeding their own rank.
        4. Cannot demote the last remaining active Super Admin.
        5. Dual-authorization: Privilege elevations by non-super-admins create pending change requests.
        6. Immediate session revocation on demotion.
        """
        # Refusal 1: Self-mutation prevention
        if operator_id == user_id:
            logger.warning(f"Operator {operator_id} attempted self-mutation of roles.")
            raise ForbiddenException(
                message="Operators cannot modify their own assigned roles.",
                error_code="CANNOT_MODIFY_OWN_ROLES",
            )

        # Retrieve operator context
        operator_payload = await self.get_or_cache_user_permissions(operator_id)
        operator_rank = get_user_highest_rank(operator_payload.roles)

        # Retrieve target user context
        target_user = await self.auth_repo.get_by_id(user_id)
        if not target_user:
            logger.warning(f"User {user_id} not found for role assignment.")
            raise NotFoundException(message="User not found.", error_code="USER_NOT_FOUND")

        target_payload = await self.get_or_cache_user_permissions(user_id)
        target_current_rank = get_user_highest_rank(target_payload.roles)

        # Refusal 2: Hierarchy boundary (target user rank vs operator rank)
        if operator_rank < 100 and target_current_rank >= operator_rank:
            logger.warning(
                f"Operator {operator_id} (rank {operator_rank}) attempted to modify target {user_id} (rank {target_current_rank})."
            )
            raise ForbiddenException(
                message="Cannot modify roles for users with equal or higher rank.",
                error_code="INSUFFICIENT_ROLE_RANK",
            )

        # Resolve role identifiers
        matched_roles = await self.rbac_repo.resolve_roles(role_identifiers)
        if len(matched_roles) != len(role_identifiers):
            logger.warning(
                f"Invalid or inactive roles provided for user {user_id}: requested {role_identifiers}"
            )
            raise BadRequestException(
                message="One or more specified role names/IDs do not exist or are no longer active in enums.",
                error_code="INVALID_ROLE_ID",
            )

        # Refusal 3: Operator assigning role at or above own rank
        for r in matched_roles:
            r_rank = get_role_rank(r.name)
            if operator_rank < 100 and r_rank >= operator_rank:
                logger.warning(
                    f"Operator {operator_id} (rank {operator_rank}) attempted to assign role '{r.name}' (rank {r_rank})."
                )
                raise ForbiddenException(
                    message=f"Cannot assign role '{r.name}' with rank {r_rank} equal to or exceeding operator rank {operator_rank}.",
                    error_code="ROLE_RANK_ESCALATION",
                )

        # Refusal 4: Lockout protection - last Super Admin demotion refusal
        target_is_super = RoleName.SUPER_ADMIN.value in target_payload.roles
        new_has_super = any(r.name == RoleName.SUPER_ADMIN.value for r in matched_roles)
        if target_is_super and not new_has_super:
            super_count = await self.rbac_repo.count_active_super_admins()
            if super_count <= 1:
                logger.warning(
                    f"Attempted to demote the last active SUPER_ADMIN user {user_id}. Refused."
                )
                raise ConflictException(
                    message="Cannot demote the last remaining active Super Admin.",
                    error_code="CANNOT_DEMOTE_LAST_SUPER_ADMIN",
                )

        new_highest_rank = max((get_role_rank(r.name) for r in matched_roles), default=0)

        # Refusal 5 / Workflow: Non-super-admin privilege elevation requires dual authorization
        if operator_rank < 100 and new_highest_rank > target_current_rank:
            req = await self.rbac_repo.create_change_request(
                request_type="ROLE_ASSIGNMENT",
                target_user_id=user_id,
                target_role_id=None,
                requested_payload=json.dumps({"roles": [r.name for r in matched_roles]}),
                reason=reason,
                requested_by_id=operator_id,
            )
            await self.rbac_repo.db.commit()
            logger.info(
                f"Role elevation for user {user_id} queued as change request {req.id} by operator {operator_id}."
            )
            return UserRoleAssignmentResponse(
                status=True,
                message="Role elevation request submitted for hierarchical approval.",
                user_id=user_id,
                assigned_roles=target_payload.roles,
                requires_approval=True,
                request_id=req.id,
            )

        # Direct execution: Apply role assignment
        role_ids = [r.id for r in matched_roles]
        assigned_role_names = await self.rbac_repo.assign_roles_to_user(user_id, role_ids)
        await self._capture_user_rbac_snapshot(user_id, operator_id, reason)
        await self.rbac_repo.db.commit()

        # Invalidate permission cache post-commit
        await self.invalidate_user_permissions(user_id)

        # Immediate Session Revocation on demotion or reduction
        if new_highest_rank < target_current_rank or len(matched_roles) < len(target_payload.roles):
            deactivated_count = await self.session_repo.deactivate_all_active_by_user_id(user_id)
            logger.info(
                f"Demoted user {user_id}: deactivated {deactivated_count} active sessions."
            )

        logger.info(
            f"Successfully assigned roles {assigned_role_names} to user {user_id} by operator {operator_id}."
        )

        return UserRoleAssignmentResponse(
            status=True,
            message=f"Successfully updated roles for user {target_user.username}.",
            user_id=user_id,
            assigned_roles=assigned_role_names,
            requires_approval=False,
            request_id=None,
        )


    async def assign_direct_permissions_to_user(
        self,
        operator_id: UUID,
        user_id: UUID,
        payload: AssignUserDirectPermissionsPayload,
    ) -> UserDirectPermissionsResponse:
        """
        Grants or denies direct custom permissions to a user with strict governance:
        1. Operators cannot modify their own permissions.
        2. Operators cannot modify users with equal or higher rank.
        3. Grant ceiling: Operator cannot grant permissions they do not possess.
        4. Immediate session revocation on explicit denials.
        """
        # Refusal 1: Self-mutation prevention
        if operator_id == user_id:
            raise ForbiddenException(
                message="Operators cannot modify their own direct permissions.",
                error_code="CANNOT_MODIFY_OWN_PERMISSIONS",
            )

        operator_payload = await self.get_or_cache_user_permissions(operator_id)
        operator_rank = get_user_highest_rank(operator_payload.roles)

        target_user = await self.auth_repo.get_by_id(user_id)
        if not target_user:
            raise NotFoundException(message="User not found.", error_code="USER_NOT_FOUND")

        target_payload = await self.get_or_cache_user_permissions(user_id)
        target_rank = get_user_highest_rank(target_payload.roles)

        # Refusal 2: Hierarchy check
        if operator_rank < 100 and target_rank >= operator_rank:
            raise ForbiddenException(
                message="Cannot modify permissions for users with equal or higher rank.",
                error_code="INSUFFICIENT_ROLE_RANK",
            )

        # Refusal 3: Grant ceiling check (cannot grant what you don't possess)
        if payload.is_granted and operator_rank < 100:
            operator_perms = set(operator_payload.permissions)
            for p_code in payload.permissions:
                if p_code not in operator_perms:
                    raise ForbiddenException(
                        message=f"Grant ceiling exceeded: operator does not possess permission '{p_code}'.",
                        error_code="GRANT_CEILING_EXCEEDED",
                    )

        # Resolve permissions
        matched_perms = await self.rbac_repo.resolve_permissions(payload.permissions)
        if len(matched_perms) != len(payload.permissions):
            raise BadRequestException(
                message="One or more specified permission codes/IDs do not exist or are no longer active in enums.",
                error_code="INVALID_PERMISSION_ID",
            )

        perm_ids = [p.id for p in matched_perms]
        await self.rbac_repo.assign_user_direct_permissions(
            user_id=user_id,
            permission_ids=perm_ids,
            is_granted=payload.is_granted,
            assigned_by_id=operator_id,
            reason=payload.reason,
        )
        await self._capture_user_rbac_snapshot(user_id, operator_id, payload.reason)
        await self.rbac_repo.db.commit()

        # Invalidate permission cache post-commit
        await self.invalidate_user_permissions(user_id)

        # Deactivate active sessions if explicit denial
        if not payload.is_granted:
            await self.session_repo.deactivate_all_active_by_user_id(user_id)

        updated_summary = await self.rbac_repo.get_user_roles_and_permissions(user_id)

        return UserDirectPermissionsResponse(
            status=True,
            message=f"Successfully updated direct permissions for user {target_user.username}.",
            user_id=user_id,
            direct_grants=updated_summary.get("direct_grants", []),
            direct_revocations=updated_summary.get("direct_revocations", []),
        )


    async def remove_direct_permissions_from_user(
        self,
        operator_id: UUID,
        user_id: UUID,
        permissions: Sequence[str],
        reason: str,
    ) -> UserDirectPermissionsResponse:
        """Removes direct permission overrides for a user."""
        if operator_id == user_id:
            raise ForbiddenException(
                message="Operators cannot modify their own direct permissions.",
                error_code="CANNOT_MODIFY_OWN_PERMISSIONS",
            )

        operator_payload = await self.get_or_cache_user_permissions(operator_id)
        operator_rank = get_user_highest_rank(operator_payload.roles)

        target_user = await self.auth_repo.get_by_id(user_id)
        if not target_user:
            raise NotFoundException(message="User not found.", error_code="USER_NOT_FOUND")

        target_payload = await self.get_or_cache_user_permissions(user_id)
        target_rank = get_user_highest_rank(target_payload.roles)

        if operator_rank < 100 and target_rank >= operator_rank:
            raise ForbiddenException(
                message="Cannot modify permissions for users with equal or higher rank.",
                error_code="INSUFFICIENT_ROLE_RANK",
            )

        matched_perms = await self.rbac_repo.resolve_permissions(permissions)
        if len(matched_perms) != len(permissions):
            raise BadRequestException(
                message="One or more specified permission codes/IDs do not exist or are no longer active in enums.",
                error_code="INVALID_PERMISSION_ID",
            )

        perm_ids = [p.id for p in matched_perms]
        await self.rbac_repo.remove_user_direct_permissions(user_id, perm_ids)
        await self._capture_user_rbac_snapshot(user_id, operator_id, reason)
        await self.rbac_repo.db.commit()

        await self.invalidate_user_permissions(user_id)

        updated_summary = await self.rbac_repo.get_user_roles_and_permissions(user_id)

        return UserDirectPermissionsResponse(
            status=True,
            message=f"Successfully removed direct permission overrides for user {target_user.username}.",
            user_id=user_id,
            direct_grants=updated_summary.get("direct_grants", []),
            direct_revocations=updated_summary.get("direct_revocations", []),
        )


    async def assign_permissions_to_role(
        self,
        operator_id: UUID,
        role_identifier: str,
        permission_identifiers: Sequence[str],
        reason: str,
    ) -> RolePermissionAssignmentResponse:
        """
        Replaces assigned permissions for a given role:
        1. SUPER_ADMIN role permissions are immutable.
        2. Operator cannot edit roles with rank equal to or exceeding their own rank.
        3. Operator cannot grant permissions they do not possess (grant ceiling).
        4. Flushes Redis caches for all users holding this role.
        """
        role = await self.rbac_repo.get_role_by_identifier(role_identifier)
        if not role:
            logger.warning(f"Role '{role_identifier}' not found or inactive for permission assignment.")
            raise NotFoundException(
                message="Role not found or is no longer active in enums.",
                error_code="ROLE_NOT_FOUND",
            )

        # Refusal 1: Immutability of SUPER_ADMIN permissions
        if role.name == RoleName.SUPER_ADMIN.value:
            logger.warning("Attempted mutation of immutable SUPER_ADMIN role permissions.")
            raise ForbiddenException(
                message="Super Admin role permissions are immutable and cannot be altered.",
                error_code="SUPER_ADMIN_IMMUTABLE",
            )

        # Operator rank check
        operator_payload = await self.get_or_cache_user_permissions(operator_id)
        operator_rank = get_user_highest_rank(operator_payload.roles)
        role_rank = get_role_rank(role.name)

        # Refusal 2: Hierarchy check
        if operator_rank < 100 and role_rank >= operator_rank:
            raise ForbiddenException(
                message=f"Cannot modify permissions for role '{role.name}' with rank {role_rank} equal to or exceeding operator rank {operator_rank}.",
                error_code="ROLE_RANK_ESCALATION",
            )

        # Refusal 3: Grant ceiling check
        if operator_rank < 100:
            operator_perms = set(operator_payload.permissions)
            for p_code in permission_identifiers:
                if p_code not in operator_perms:
                    raise ForbiddenException(
                        message=f"Grant ceiling exceeded: operator does not possess permission '{p_code}'.",
                        error_code="GRANT_CEILING_EXCEEDED",
                    )

        # Resolve permission codes or UUIDs
        matched_perms = []
        if permission_identifiers:
            matched_perms = await self.rbac_repo.resolve_permissions(permission_identifiers)
            if len(matched_perms) != len(permission_identifiers):
                raise BadRequestException(
                    message="One or more specified permission codes/IDs do not exist or are no longer active in enums.",
                    error_code="INVALID_PERMISSION_ID",
                )

        perm_ids = [p.id for p in matched_perms]
        assigned_perm_codes = await self.rbac_repo.assign_permissions_to_role(
            role.id, perm_ids
        )

        # Capture immutable point-in-time snapshot
        perm_payload = [{"id": str(p.id), "code": p.code} for p in matched_perms]
        await self.rbac_repo.create_role_permission_snapshot(
            role_id=role.id,
            permissions_payload=perm_payload,
            changed_by_id=operator_id,
            reason=reason,
        )

        await self.rbac_repo.db.commit()

        # Invalidate cache post-commit for all users holding this role
        affected_user_ids = await self.rbac_repo.get_user_ids_by_role(role.id)
        for u_id in affected_user_ids:
            await self.invalidate_user_permissions(u_id)

        logger.info(
            f"Updated permissions for role '{role.name}' and invalidated cache for {len(affected_user_ids)} users."
        )

        return RolePermissionAssignmentResponse(
            status=True,
            message=f"Successfully updated permissions for role '{role.name}'.",
            role_id=role.id,
            role_name=role.name,
            assigned_permissions=assigned_perm_codes,
            requires_approval=False,
            request_id=None,
        )


    async def batch_assign_role_permissions(
        self,
        operator_id: UUID,
        payload: BatchRolePermissionAssignmentPayload,
    ) -> BatchRolePermissionAssignmentResponse:
        """Atomically updates permissions across multiple roles in a single operation."""
        operator_payload = await self.get_or_cache_user_permissions(operator_id)
        operator_rank = get_user_highest_rank(operator_payload.roles)
        operator_perms = set(operator_payload.permissions)

        updated_role_names: List[str] = []
        all_affected_user_ids: set[UUID] = set()

        for item in payload.assignments:
            role = await self.rbac_repo.get_role_by_identifier(item.role)
            if not role:
                raise NotFoundException(
                    message=f"Role '{item.role}' not found or inactive.",
                    error_code="ROLE_NOT_FOUND",
                )

            if role.name == RoleName.SUPER_ADMIN.value:
                raise ForbiddenException(
                    message="Super Admin role permissions are immutable and cannot be altered.",
                    error_code="SUPER_ADMIN_IMMUTABLE",
                )

            role_rank = get_role_rank(role.name)
            if operator_rank < 100 and role_rank >= operator_rank:
                raise ForbiddenException(
                    message=f"Cannot modify permissions for role '{role.name}' with rank {role_rank} equal to or exceeding operator rank {operator_rank}.",
                    error_code="ROLE_RANK_ESCALATION",
                )

            if operator_rank < 100:
                for p_code in item.permissions:
                    if p_code not in operator_perms:
                        raise ForbiddenException(
                            message=f"Grant ceiling exceeded: operator does not possess permission '{p_code}'.",
                            error_code="GRANT_CEILING_EXCEEDED",
                        )

            matched_perms = []
            if item.permissions:
                matched_perms = await self.rbac_repo.resolve_permissions(item.permissions)
                if len(matched_perms) != len(item.permissions):
                    raise BadRequestException(
                        message=f"One or more permission codes for role '{item.role}' do not exist or are inactive.",
                        error_code="INVALID_PERMISSION_ID",
                    )

            perm_ids = [p.id for p in matched_perms]
            await self.rbac_repo.assign_permissions_to_role(role.id, perm_ids)

            # Capture immutable point-in-time snapshot
            perm_payload = [{"id": str(p.id), "code": p.code} for p in matched_perms]
            await self.rbac_repo.create_role_permission_snapshot(
                role_id=role.id,
                permissions_payload=perm_payload,
                changed_by_id=operator_id,
                reason=payload.reason,
            )

            updated_role_names.append(role.name)

            affected_users = await self.rbac_repo.get_user_ids_by_role(role.id)
            all_affected_user_ids.update(affected_users)

        await self.rbac_repo.db.commit()

        for u_id in all_affected_user_ids:
            await self.invalidate_user_permissions(u_id)

        logger.info(
            f"Batch assigned permissions for roles: {updated_role_names}. Invalidated {len(all_affected_user_ids)} user caches."
        )

        return BatchRolePermissionAssignmentResponse(
            status=True,
            message=f"Successfully batch updated permissions for {len(updated_role_names)} roles.",
            updated_roles=updated_role_names,
        )


    async def reset_role_to_defaults(
        self,
        operator_id: UUID,
        role_identifier: str,
    ) -> RolePermissionAssignmentResponse:
        """Resets a role's permissions back to its code-defined ROLE_DEFAULT_PERMISSIONS preset."""
        role = await self.rbac_repo.get_role_by_identifier(role_identifier)
        if not role:
            raise NotFoundException(
                message=f"Role '{role_identifier}' not found.",
                error_code="ROLE_NOT_FOUND",
            )

        if role.name == RoleName.SUPER_ADMIN.value:
            raise ForbiddenException(
                message="Super Admin role permissions are immutable and cannot be altered.",
                error_code="SUPER_ADMIN_IMMUTABLE",
            )

        try:
            r_enum = RoleName(role.name)
        except ValueError:
            raise BadRequestException(
                message=f"Role '{role.name}' is not a defined system role enum.",
                error_code="ROLE_NOT_FOUND",
            )

        default_perms = ROLE_DEFAULT_PERMISSIONS.get(r_enum, set())
        perm_codes = [p.value for p in default_perms]
        return await self.assign_permissions_to_role(
            operator_id=operator_id,
            role_identifier=role.name,
            permission_identifiers=perm_codes,
            reason="Reset to code-defined default permissions.",
        )


    async def list_pending_change_requests(
        self,
        operator_id: UUID,
    ) -> List[RBACChangeRequestResponse]:
        """Lists pending change requests awaiting review."""
        requests = await self.rbac_repo.get_pending_change_requests()
        return [
            RBACChangeRequestResponse(
                id=req.id,
                request_type=req.request_type,
                target_user_id=req.target_user_id,
                target_role_id=req.target_role_id,
                requested_payload=req.requested_payload,
                status=req.status.value if hasattr(req.status, "value") else str(req.status),
                reason=req.reason,
                requested_by_id=req.requested_by_id,
                reviewed_by_id=req.reviewed_by_id,
                review_notes=req.review_notes,
                created_at=req.created_at,
                reviewed_at=req.reviewed_at,
            )
            for req in requests
        ]


    async def review_change_request(
        self,
        operator_id: UUID,
        request_id: UUID,
        payload: ReviewChangeRequestPayload,
        is_approved: bool,
    ) -> RBACChangeRequestResponse:
        """
        Reviews and processes an RBAC change request.
        Adheres to hierarchical authority:
        - Self-approval is strictly forbidden (dual control).
        - Reviewer's rank must strictly exceed requester's rank.
        - Reviewer's rank must be equal to or exceed requested role's rank.
        """
        req = await self.rbac_repo.get_change_request_by_id(request_id)
        if not req:
            raise NotFoundException(
                message="Change request not found.",
                error_code="CHANGE_REQUEST_NOT_FOUND",
            )

        if req.status != RBACChangeRequestStatus.PENDING:
            raise ConflictException(
                message=f"Change request is already {req.status.value}.",
                error_code="CHANGE_REQUEST_ALREADY_PROCESSED",
            )

        # Dual Control: Refuse self-approval
        if req.requested_by_id == operator_id:
            raise ForbiddenException(
                message="Operators cannot approve their own change requests (dual-control violation).",
                error_code="CANNOT_SELF_APPROVE",
            )

        # Hierarchical Authority Check
        operator_payload = await self.get_or_cache_user_permissions(operator_id)
        operator_rank = get_user_highest_rank(operator_payload.roles)

        requester_payload = await self.get_or_cache_user_permissions(req.requested_by_id)
        requester_rank = get_user_highest_rank(requester_payload.roles)

        if operator_rank < 100 and operator_rank <= requester_rank:
            raise ForbiddenException(
                message="Insufficient rank to review this change request. Reviewer rank must exceed requester rank.",
                error_code="INSUFFICIENT_REVIEWER_RANK",
            )

        parsed_data = json.loads(req.requested_payload) if req.requested_payload else {}

        if is_approved:
            if req.request_type == "ROLE_ASSIGNMENT" and req.target_user_id:
                requested_roles = parsed_data.get("roles", [])
                max_req_rank = max((get_role_rank(r) for r in requested_roles), default=0)
                if operator_rank < 100 and operator_rank < max_req_rank:
                    raise ForbiddenException(
                        message="Reviewer rank must be equal to or higher than the requested role rank.",
                        error_code="INSUFFICIENT_REVIEWER_RANK",
                    )

                matched_roles = await self.rbac_repo.resolve_roles(requested_roles)
                role_ids = [r.id for r in matched_roles]
                await self.rbac_repo.assign_roles_to_user(req.target_user_id, role_ids)
                await self._capture_user_rbac_snapshot(
                    req.target_user_id,
                    operator_id,
                    f"Approved change request {req.id}: {req.reason}",
                )

            req.status = RBACChangeRequestStatus.APPROVED
            req.reviewed_by_id = operator_id
            req.review_notes = payload.review_notes
            req.reviewed_at = datetime.now(timezone.utc)
            await self.rbac_repo.db.commit()

            if req.target_user_id:
                await self.invalidate_user_permissions(req.target_user_id)
        else:
            req.status = RBACChangeRequestStatus.REJECTED
            req.reviewed_by_id = operator_id
            req.review_notes = payload.review_notes
            req.reviewed_at = datetime.now(timezone.utc)
            await self.rbac_repo.db.commit()

        logger.info(
            f"Change request {request_id} was {'APPROVED' if is_approved else 'REJECTED'} by operator {operator_id}."
        )

        return RBACChangeRequestResponse(
            id=req.id,
            request_type=req.request_type,
            target_user_id=req.target_user_id,
            target_role_id=req.target_role_id,
            requested_payload=req.requested_payload,
            status=req.status.value if hasattr(req.status, "value") else str(req.status),
            reason=req.reason,
            requested_by_id=req.requested_by_id,
            reviewed_by_id=req.reviewed_by_id,
            review_notes=req.review_notes,
            created_at=req.created_at,
            reviewed_at=req.reviewed_at,
        )


    async def sync_enums_to_db(self) -> dict:
        """Invokes idempotent synchronization of enums with database tables."""
        return await self.rbac_repo.sync_enums_to_db()


    async def get_all_roles_permission_history(
        self,
        role_identifier: Optional[str] = None,
        from_date: Optional[datetime] = None,
        to_date: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[RoleSnapshotHistoryResponse]:
        """
        Retrieves chronological point-in-time permission snapshots across all roles
        or filtered by a specific role.
        """
        role_id: Optional[UUID] = None
        if role_identifier:
            role = await self.rbac_repo.get_role_by_identifier(role_identifier)
            if not role:
                logger.warning(f"Role '{role_identifier}' not found for history query.")
                raise NotFoundException(
                    message=f"Role '{role_identifier}' not found or is no longer active in enums.",
                    error_code="ROLE_NOT_FOUND",
                )
            role_id = role.id

        snapshots = await self.rbac_repo.get_role_permission_history(
            role_id=role_id,
            from_date=from_date,
            to_date=to_date,
            limit=limit,
            offset=offset,
        )

        results: List[RoleSnapshotHistoryResponse] = []
        for s in snapshots:
            perms = [
                PermissionSimpleSchema(id=UUID(p["id"]), code=p["code"])
                for p in s.permissions_payload
            ]
            results.append(
                RoleSnapshotHistoryResponse(
                    snapshot_id=s.id,
                    role_id=s.role_id,
                    role_name=s.role.name if s.role else "UNKNOWN",
                    timestamp=s.created_at,
                    permissions=perms,
                    total_permissions=len(perms),
                    updated_by=OperatorSummarySchema(
                        user_id=s.changed_by.id if s.changed_by else s.changed_by_id,
                        username=s.changed_by.username if s.changed_by else "SYSTEM",
                    ),
                    reason=s.reason,
                )
            )
        return results

    async def get_role_permission_history(
        self,
        role_identifier: str,
        from_date: Optional[datetime] = None,
        to_date: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[RoleSnapshotHistoryResponse]:
        """
        Retrieves chronological point-in-time permission snapshots for a role.
        """
        return await self.get_all_roles_permission_history(
            role_identifier=role_identifier,
            from_date=from_date,
            to_date=to_date,
            limit=limit,
            offset=offset,
        )


    async def get_user_rbac_history(
        self,
        user_id: UUID,
        from_date: Optional[datetime] = None,
        to_date: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[UserSnapshotHistoryResponse]:
        """
        Retrieves chronological point-in-time role and permission snapshots for a user.
        """
        target_user = await self.auth_repo.get_by_id(user_id)
        if not target_user:
            logger.warning(f"User {user_id} not found for history query.")
            raise NotFoundException(
                message=f"User '{user_id}' not found.",
                error_code="USER_NOT_FOUND",
            )

        snapshots = await self.rbac_repo.get_user_rbac_history(
            user_id=user_id,
            from_date=from_date,
            to_date=to_date,
            limit=limit,
            offset=offset,
        )

        results: List[UserSnapshotHistoryResponse] = []
        for s in snapshots:
            roles = [
                RoleSimpleSchema(
                    id=UUID(r["id"]),
                    name=r["name"],
                    rank=r.get("rank", get_role_rank(r["name"])),
                )
                for r in s.roles_payload
            ]
            direct_perms = [
                PermissionSimpleSchema(id=UUID(p["id"]), code=p["code"])
                for p in s.direct_permissions_payload
                if p.get("is_granted", True)
            ]
            effective_perms = [
                PermissionSimpleSchema(id=UUID(p["id"]), code=p["code"])
                for p in s.effective_permissions_payload
            ]
            results.append(
                UserSnapshotHistoryResponse(
                    snapshot_id=s.id,
                    user_id=s.user_id,
                    username=s.user.username if s.user else target_user.username,
                    timestamp=s.created_at,
                    roles=roles,
                    direct_permissions=direct_perms,
                    effective_permissions=effective_perms,
                    total_permissions=len(effective_perms),
                    updated_by=OperatorSummarySchema(
                        user_id=s.changed_by.id if s.changed_by else s.changed_by_id,
                        username=s.changed_by.username if s.changed_by else "SYSTEM",
                    ),
                    reason=s.reason,
                )
            )
        return results
