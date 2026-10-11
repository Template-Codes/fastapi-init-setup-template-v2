from datetime import datetime
from typing import Dict, List, Optional, Sequence, Tuple
from uuid import UUID

from base.repository import BaseRepository
from db.db_session import get_async_db
from exceptions.app_exception import InternalServerException
from fastapi import Depends
from loguru import logger
from modules.authentication.auth_model import User, UserStatus
from modules.rbac.rbac_model import (
    Permission,
    RBACChangeRequest,
    RBACChangeRequestStatus,
    Role,
    RolePermission,
    RolePermissionSnapshot,
    UserPermission,
    UserRBACSnapshot,
    UserRole,
)
from shares.enums import (
    ACTION_DESCRIPTIONS,
    ROLE_DEFAULT_PERMISSIONS,
    ROLE_DESCRIPTIONS,
    ActionName,
    RoleName,
    SystemPermission,
    get_role_rank,
)
from sqlalchemy import String, cast, delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload


class RBACRepository(BaseRepository[Role]):
    """Repository for database operations related to Roles and Permissions."""

    def __init__(
        self, 
        db: AsyncSession = Depends(get_async_db)
    ):
        super().__init__(db, Role)


    async def get_user_roles_and_permissions(
        self, user_id: UUID
    ) -> Dict[str, any]:
        """
        Fetches all assigned role names, direct user grants, direct user revocations,
        and resolved effective permission codes for a given user UUID.
        
        Effective Formula:
        Effective = (RolePermissions UNION DirectGrants) MINUS DirectRevocations
        """
        try:
            valid_role_names = {r.value for r in RoleName}
            valid_perm_codes = {p.value for p in SystemPermission}

            # 1. Fetch assigned role names
            role_stmt = (
                select(Role.name)
                .join(UserRole, UserRole.role_id == Role.id)
                .where(UserRole.user_id == user_id)
            )
            role_res = await self.db.execute(role_stmt)
            roles: List[str] = [r[0] for r in role_res.fetchall() if r[0] in valid_role_names]

            # 2. Fetch role-granted permission codes
            role_perm_stmt = (
                select(Permission.code)
                .join(RolePermission, RolePermission.permission_id == Permission.id)
                .join(UserRole, UserRole.role_id == RolePermission.role_id)
                .where(UserRole.user_id == user_id)
            )
            role_perm_res = await self.db.execute(role_perm_stmt)
            role_perms = set(p[0] for p in role_perm_res.fetchall() if p[0] in valid_perm_codes)

            # 3. Fetch direct user grants and explicit denials
            direct_stmt = (
                select(Permission.code, UserPermission.is_granted)
                .join(UserPermission, UserPermission.permission_id == Permission.id)
                .where(UserPermission.user_id == user_id)
            )
            direct_res = await self.db.execute(direct_stmt)
            direct_rows = direct_res.fetchall()

            direct_grants = [r[0] for r in direct_rows if r[1] is True and r[0] in valid_perm_codes]
            direct_revocations = [r[0] for r in direct_rows if r[1] is False and r[0] in valid_perm_codes]

            # 4. Resolve Effective Permissions
            effective_perms = (role_perms | set(direct_grants)) - set(direct_revocations)

            return {
                "user_id": str(user_id),
                "roles": roles,
                "direct_grants": direct_grants,
                "direct_revocations": direct_revocations,
                "permissions": sorted(list(effective_perms)),
            }
        except Exception as e:
            logger.error(f"Failed to query roles and permissions for user {user_id}: {e}")
            raise InternalServerException(
                message="Error querying user roles and permissions.",
                error_code="USER_ROLE_PERMISSION_FAILED"
            )


    async def count_active_super_admins(self) -> int:
        """Counts active users holding SUPER_ADMIN role."""
        stmt = (
            select(func.count(UserRole.user_id))
            .join(Role, Role.id == UserRole.role_id)
            .where(Role.name == RoleName.SUPER_ADMIN.value)
        )
        res = await self.db.execute(stmt)
        return res.scalar_one() or 0


    async def assign_user_direct_permissions(
        self,
        user_id: UUID,
        permission_ids: List[UUID],
        is_granted: bool,
        assigned_by_id: Optional[UUID],
        reason: str,
    ) -> None:
        """Assigns direct custom permission grants or explicit denials to a user."""
        try:
            del_stmt = delete(UserPermission).where(
                UserPermission.user_id == user_id,
                UserPermission.permission_id.in_(permission_ids),
            )
            await self.db.execute(del_stmt)

            for p_id in permission_ids:
                self.db.add(
                    UserPermission(
                        user_id=user_id,
                        permission_id=p_id,
                        is_granted=is_granted,
                        assigned_by_id=assigned_by_id,
                        reason=reason,
                    )
                )
            await self.db.flush()
        except Exception as e:
            logger.error(f"Failed to assign direct user permissions for user {user_id}: {e}")
            raise InternalServerException(
                message="Failed to update user direct permissions.",
                error_code="USER_PERMISSION_ASSIGNMENT_FAILED",
            )


    async def remove_user_direct_permissions(
        self, user_id: UUID, permission_ids: List[UUID]
    ) -> None:
        """Removes direct permission overrides for a user."""
        try:
            del_stmt = delete(UserPermission).where(
                UserPermission.user_id == user_id,
                UserPermission.permission_id.in_(permission_ids),
            )
            await self.db.execute(del_stmt)
            await self.db.flush()
        except Exception as e:
            logger.error(f"Failed to remove direct permissions for user {user_id}: {e}")
            raise InternalServerException(
                message="Failed to remove user direct permissions.",
                error_code="USER_PERMISSION_REMOVAL_FAILED",
            )


    async def create_change_request(
        self,
        request_type: str,
        target_user_id: Optional[UUID],
        target_role_id: Optional[UUID],
        requested_payload: str,
        reason: str,
        requested_by_id: UUID,
    ) -> RBACChangeRequest:
        """Creates a pending dual-authorization change request."""
        try:
            req = RBACChangeRequest(
                request_type=request_type,
                target_user_id=target_user_id,
                target_role_id=target_role_id,
                requested_payload=requested_payload,
                status=RBACChangeRequestStatus.PENDING,
                reason=reason,
                requested_by_id=requested_by_id,
            )
            self.db.add(req)
            await self.db.flush()
            return req
        except Exception as e:
            logger.error(f"Failed to create RBAC change request: {e}")
            raise InternalServerException(
                message="Failed to create RBAC change request.",
                error_code="CHANGE_REQUEST_CREATE_FAILED",
            )


    async def get_change_request_by_id(self, request_id: UUID) -> Optional[RBACChangeRequest]:
        """Fetch change request by UUID."""
        stmt = select(RBACChangeRequest).where(RBACChangeRequest.id == request_id)
        res = await self.db.execute(stmt)
        return res.scalar_one_or_none()


    async def get_pending_change_requests(self) -> List[RBACChangeRequest]:
        """Fetch all change requests with PENDING status."""
        stmt = (
            select(RBACChangeRequest)
            .where(RBACChangeRequest.status == RBACChangeRequestStatus.PENDING)
            .order_by(RBACChangeRequest.created_at.asc())
        )
        res = await self.db.execute(stmt)
        return list(res.scalars().all())


    async def get_all_users_with_rbac_details(
        self,
        role: Optional[str] = None,
        search: Optional[str] = None,
        status_filter: Optional[str] = None,
    ) -> List[User]:
        """
        Fetches all users with eager-loaded roles, role permissions, and direct permissions
        in a batched single-operation pipeline (N+1 safe).
        """
        try:
            stmt = (
                select(User)
                .options(
                    selectinload(User.roles).selectinload(Role.permissions),
                    selectinload(User.direct_permissions).selectinload(UserPermission.permission),
                )
                .order_by(User.user_code.asc())
            )

            # Optional status filter
            if status_filter:
                clean_status = status_filter.strip().upper()
                try:
                    stmt = stmt.where(User.status == UserStatus(clean_status))
                except ValueError:
                    stmt = stmt.where(cast(User.status, String) == clean_status)

            # Optional search filter (case-insensitive partial match on username, user_code, or email)
            if search:
                pattern = f"%{search.strip().lower()}%"
                stmt = stmt.where(
                    or_(
                        func.lower(User.username).like(pattern),
                        func.lower(User.user_code).like(pattern),
                        func.lower(User.email).like(pattern),
                    )
                )

            # Optional role filter (by role name or role UUID)
            if role:
                role_val = role.strip()
                stmt = stmt.join(UserRole, UserRole.user_id == User.id).join(Role, Role.id == UserRole.role_id)
                try:
                    role_uuid = UUID(role_val)
                    stmt = stmt.where(or_(Role.id == role_uuid, func.upper(Role.name) == role_val.upper()))
                except ValueError:
                    stmt = stmt.where(func.upper(Role.name) == role_val.upper())

            res = await self.db.execute(stmt)
            return list(res.scalars().unique().all())
        except Exception as e:
            logger.error(f"Failed to query all users with RBAC details: {e}")
            raise InternalServerException(
                message="Error querying enterprise user RBAC details.",
                error_code="USER_RBAC_LIST_FAILED",
            )


    async def get_user_with_rbac_details(self, user_id: UUID) -> Optional[User]:
        """Fetches a single user with eagerly loaded roles, role permissions, and direct permissions."""
        stmt = (
            select(User)
            .options(
                selectinload(User.roles).selectinload(Role.permissions),
                selectinload(User.direct_permissions).selectinload(UserPermission.permission),
            )
            .where(User.id == user_id)
        )
        res = await self.db.execute(stmt)
        return res.scalar_one_or_none()


    async def get_all_roles(self) -> List[Role]:
        """Fetches active roles defined in enums.py with active permissions loaded."""
        try:
            valid_role_names = {r.value for r in RoleName}
            valid_perm_codes = {p.value for p in SystemPermission}

            stmt = (
                select(Role)
                .options(selectinload(Role.permissions))
                .where(Role.name.in_(valid_role_names))
                .order_by(Role.name.asc())
            )
            res = await self.db.execute(stmt)
            roles = list(res.scalars().all())

            # Filter permissions inside each role to active SystemPermission enums
            for r in roles:
                r.permissions = [p for p in r.permissions if p.code in valid_perm_codes]

            return roles
        except Exception as e:
            logger.error(f"Failed to fetch roles: {e}")
            raise InternalServerException(
                message="Failed to retrieve system roles.",
                error_code="ROLES_QUERY_FAILED"
            )


    async def get_role_by_identifier(self, identifier: str) -> Optional[Role]:
        """Fetch active role by either UUID string or role name with active permissions loaded."""
        valid_role_names = {r.value for r in RoleName}
        valid_perm_codes = {p.value for p in SystemPermission}

        stmt = select(Role).options(selectinload(Role.permissions))
        try:
            parsed_uuid = UUID(identifier)
            stmt = stmt.where(Role.id == parsed_uuid)
        except (ValueError, AttributeError):
            stmt = stmt.where(Role.name == identifier)

        res = await self.db.execute(stmt)
        role = res.scalar_one_or_none()
        if role and role.name in valid_role_names:
            role.permissions = [p for p in role.permissions if p.code in valid_perm_codes]
            return role
        return None


    async def get_role_by_id(self, role_id: UUID) -> Optional[Role]:
        """Fetch a single active role by its UUID with active permissions eagerly loaded."""
        return await self.get_role_by_identifier(str(role_id))


    async def resolve_roles(self, identifiers: Sequence[str]) -> List[Role]:
        """Batch resolves role names or UUID strings to active Role models."""
        if not identifiers:
            return []
        valid_role_names = {r.value for r in RoleName}

        uuid_list = []
        name_list = []
        for item in identifiers:
            try:
                uuid_list.append(UUID(str(item)))
            except (ValueError, AttributeError):
                name_list.append(str(item))

        conditions = []
        if uuid_list:
            conditions.append(Role.id.in_(uuid_list))
        if name_list:
            conditions.append(Role.name.in_(name_list))

        if not conditions:
            return []

        stmt = (
            select(Role)
            .options(selectinload(Role.permissions))
            .where(Role.name.in_(valid_role_names))
            .where(or_(*conditions))
        )
        res = await self.db.execute(stmt)
        roles = list(res.scalars().all())
        valid_perm_codes = {p.value for p in SystemPermission}
        for r in roles:
            r.permissions = [p for p in r.permissions if p.code in valid_perm_codes]
        return roles


    async def resolve_permissions(self, identifiers: Sequence[str]) -> List[Permission]:
        """Batch resolves permission codes or UUID strings to active Permission models."""
        if not identifiers:
            return []
        valid_perm_codes = {p.value for p in SystemPermission}

        uuid_list = []
        code_list = []
        for item in identifiers:
            try:
                uuid_list.append(UUID(str(item)))
            except (ValueError, AttributeError):
                code_list.append(str(item))

        conditions = []
        if uuid_list:
            conditions.append(Permission.id.in_(uuid_list))
        if code_list:
            conditions.append(Permission.code.in_(code_list))

        if not conditions:
            return []

        stmt = (
            select(Permission)
            .where(Permission.code.in_(valid_perm_codes))
            .where(or_(*conditions))
        )
        res = await self.db.execute(stmt)
        return list(res.scalars().all())


    async def get_all_permissions(self) -> List[Permission]:
        """Fetch active permissions defined in enums.py."""
        valid_perm_codes = {p.value for p in SystemPermission}
        stmt = (
            select(Permission)
            .where(Permission.code.in_(valid_perm_codes))
            .order_by(Permission.module.asc(), Permission.code.asc())
        )
        res = await self.db.execute(stmt)
        return list(res.scalars().all())


    async def get_roles_by_ids(self, role_ids: List[UUID]) -> Sequence[Role]:
        """Fetch roles matching the given list of UUIDs using BaseRepository."""
        return await self.get_by_ids(role_ids)


    async def get_permissions_by_ids(self, permission_ids: List[UUID]) -> List[Permission]:
        """Fetch permissions matching the given list of UUIDs."""
        stmt = select(Permission).where(Permission.id.in_(permission_ids))
        res = await self.db.execute(stmt)
        return list(res.scalars().all())


    async def assign_roles_to_user(self, user_id: UUID, role_ids: List[UUID]) -> List[str]:
        """
        Additively assigns roles to a user without overwriting existing assignments.
        Compounds roles and returns list of all currently assigned role names.
        """
        try:
            # Find currently assigned role IDs for user
            existing_stmt = select(UserRole.role_id).where(UserRole.user_id == user_id)
            existing_res = await self.db.execute(existing_stmt)
            existing_role_ids = set(existing_res.scalars().all())

            # Insert only new assignments
            for r_id in role_ids:
                if r_id not in existing_role_ids:
                    self.db.add(UserRole(user_id=user_id, role_id=r_id))

            await self.db.flush()

            # Query all currently assigned role names for the user
            role_stmt = (
                select(Role.name)
                .join(UserRole, UserRole.role_id == Role.id)
                .where(UserRole.user_id == user_id)
                .order_by(Role.name.asc())
            )
            role_res = await self.db.execute(role_stmt)
            return list(role_res.scalars().all())
        except Exception as e:
            logger.error(f"Failed to assign roles to user {user_id}: {e}")
            raise InternalServerException(
                message="Failed to update user roles.",
                error_code="USER_ROLE_ASSIGNMENT_FAILED"
            )


    async def replace_user_roles(self, user_id: UUID, role_ids: List[UUID]) -> List[str]:
        """
        Replaces all assigned roles for a user with the provided role_ids.
        Used for exact point-in-time state rollbacks. Returns list of assigned role names.
        """
        try:
            # Delete current assignments
            del_stmt = delete(UserRole).where(UserRole.user_id == user_id)
            await self.db.execute(del_stmt)

            # Insert new assignments
            for r_id in role_ids:
                self.db.add(UserRole(user_id=user_id, role_id=r_id))

            await self.db.flush()

            # Query assigned role names
            role_stmt = select(Role.name).where(Role.id.in_(role_ids)).order_by(Role.name.asc())
            role_res = await self.db.execute(role_stmt)
            return list(role_res.scalars().all())
        except Exception as e:
            logger.error(f"Failed to replace roles for user {user_id}: {e}")
            raise InternalServerException(
                message="Failed to replace user roles.",
                error_code="USER_ROLE_REPLACEMENT_FAILED"
            )


    async def demote_user_roles(
        self, user_id: UUID, role_ids_to_remove: List[UUID]
    ) -> Tuple[List[str], List[str]]:
        """
        Demotes a user by removing specified role IDs from user_roles.
        Returns a tuple of (removed_role_names, remaining_role_names).
        """
        try:
            # Query the names of the roles being removed
            remove_stmt = (
                select(Role.name)
                .join(UserRole, UserRole.role_id == Role.id)
                .where(UserRole.user_id == user_id, Role.id.in_(role_ids_to_remove))
                .order_by(Role.name.asc())
            )
            remove_res = await self.db.execute(remove_stmt)
            removed_role_names = list(remove_res.scalars().all())

            # Delete the specified assignments
            del_stmt = delete(UserRole).where(
                UserRole.user_id == user_id,
                UserRole.role_id.in_(role_ids_to_remove)
            )
            await self.db.execute(del_stmt)
            await self.db.flush()

            # Query remaining assigned role names
            remaining_stmt = (
                select(Role.name)
                .join(UserRole, UserRole.role_id == Role.id)
                .where(UserRole.user_id == user_id)
                .order_by(Role.name.asc())
            )
            remaining_res = await self.db.execute(remaining_stmt)
            remaining_role_names = list(remaining_res.scalars().all())

            return removed_role_names, remaining_role_names
        except Exception as e:
            logger.error(f"Failed to demote roles for user {user_id}: {e}")
            raise InternalServerException(
                message="Failed to demote user roles.",
                error_code="USER_ROLE_DEMOTION_FAILED"
            )


    async def assign_permissions_to_role(
        self, role_id: UUID, permission_ids: List[UUID]
    ) -> List[str]:
        """
        Replaces all assigned permissions for a role with the provided permission_ids.
        Returns list of newly assigned permission codes.
        """
        try:
            # Delete current assignments
            del_stmt = delete(RolePermission).where(RolePermission.role_id == role_id)
            await self.db.execute(del_stmt)

            # Insert new assignments
            for p_id in permission_ids:
                self.db.add(RolePermission(role_id=role_id, permission_id=p_id))

            await self.db.flush()

            # Query assigned permission codes
            perm_stmt = select(Permission.code).where(Permission.id.in_(permission_ids))
            perm_res = await self.db.execute(perm_stmt)
            return [p[0] for p in perm_res.fetchall()]
        except Exception as e:
            logger.error(f"Failed to assign permissions to role {role_id}: {e}")
            raise InternalServerException(
                message="Failed to update role permissions.",
                error_code="ROLE_PERMISSION_ASSIGNMENT_FAILED"
            )


    async def get_user_ids_by_role(self, role_id: UUID) -> List[UUID]:
        """Retrieves all user IDs who are assigned a given role."""
        stmt = select(UserRole.user_id).where(UserRole.role_id == role_id)
        res = await self.db.execute(stmt)
        return [r[0] for r in res.fetchall()]


    async def sync_enums_to_db(self) -> dict:
        """
        Idempotent synchronization and lifespan pruning helper.
        1. Ensures all roles and permissions defined in `enums.py` exist with rich descriptions.
        2. Links default bulk permissions according to `ROLE_DEFAULT_PERMISSIONS`.
        3. Lifespan Pruning (Non-destructive): Detaches obsolete associations from
           auth.role_permissions and auth.user_roles without deleting audit table rows.
        """
        roles_synced = 0
        perms_synced = 0
        valid_role_names = {r.value for r in RoleName}
        valid_perm_codes = {p.value for p in SystemPermission}

        # 1. Sync Roles
        role_map: dict[str, Role] = {}
        for r_enum in RoleName:
            stmt = select(Role).options(
                selectinload(Role.permissions)
            ).where(Role.name == r_enum.value)

            res = await self.db.execute(stmt)
            role = res.scalar_one_or_none()
            desc = ROLE_DESCRIPTIONS.get(r_enum, f"System role for {r_enum.value}")

            if not role:
                role = Role(
                    name=r_enum.value,
                    description=desc,
                    is_system_role=True,
                )
                self.db.add(role)
                await self.db.flush()
                roles_synced += 1
            else:
                if role.description != desc:
                    role.description = desc
                    self.db.add(role)
            role_map[r_enum.value] = role

        # 2. Sync Permissions
        perm_map: dict[str, Permission] = {}
        for p_enum in SystemPermission:
            code_str = p_enum.value
            parts = code_str.split(":")
            module_name = parts[0]
            res_name = parts[1] if len(parts) > 1 else ""
            act_name = parts[2] if len(parts) > 2 else ""

            display_name = f"{res_name} {act_name}".strip()
            desc = ""
            try:
                desc = ACTION_DESCRIPTIONS.get(ActionName(act_name), f"System permission for {display_name}")
            except ValueError:
                desc = f"System permission for {display_name}"

            stmt = select(Permission).where(Permission.code == code_str)
            res = await self.db.execute(stmt)
            perm = res.scalar_one_or_none()
            if not perm:
                perm = Permission(
                    code=code_str,
                    module=module_name,
                    name=display_name,
                    description=desc,
                )
                self.db.add(perm)
                await self.db.flush()
                perms_synced += 1
            else:
                if perm.description != desc or perm.name != display_name or perm.module != module_name:
                    perm.description = desc
                    perm.name = display_name
                    perm.module = module_name
                    self.db.add(perm)
            perm_map[code_str] = perm

        # 3. Sync Default Role Permissions
        links_added = 0
        roles_with_added_links: dict[UUID, list[str]] = {}
        for r_enum, perm_set in ROLE_DEFAULT_PERMISSIONS.items():
            role = role_map.get(r_enum.value)
            if not role:
                continue
            existing_perm_ids = {p.id for p in role.permissions}
            for p_enum in perm_set:
                code_str = p_enum.value if hasattr(p_enum, "value") else str(p_enum)
                perm = perm_map.get(code_str)
                if perm and perm.id not in existing_perm_ids:
                    self.db.add(RolePermission(role_id=role.id, permission_id=perm.id))
                    links_added += 1
                    if role.id not in roles_with_added_links:
                        roles_with_added_links[role.id] = []
                    roles_with_added_links[role.id].append(perm.code)

        # 4. Lifespan Pruning: Detach obsolete permissions & roles from junction tables
        # Pre-query affected roles holding obsolete permissions
        obsolete_perm_subq = select(Permission.id).where(Permission.code.notin_(valid_perm_codes))
        roles_with_obsolete_perms_stmt = (
            select(RolePermission.role_id)
            .where(RolePermission.permission_id.in_(obsolete_perm_subq))
            .distinct()
        )
        roles_with_obsolete_res = await self.db.execute(roles_with_obsolete_perms_stmt)
        roles_with_pruned_perm_ids = set(roles_with_obsolete_res.scalars().all())

        # Detach obsolete permissions from role_permissions
        prune_perm_stmt = delete(RolePermission).where(RolePermission.permission_id.in_(obsolete_perm_subq))
        prune_perm_res = await self.db.execute(prune_perm_stmt)
        pruned_perm_links = prune_perm_res.rowcount or 0

        # Pre-query affected users holding obsolete roles
        obsolete_role_subq = select(Role.id).where(Role.name.notin_(valid_role_names))
        users_with_obsolete_roles_stmt = (
            select(UserRole.user_id)
            .where(UserRole.role_id.in_(obsolete_role_subq))
            .distinct()
        )
        users_with_obsolete_res = await self.db.execute(users_with_obsolete_roles_stmt)
        users_with_pruned_role_ids = set(users_with_obsolete_res.scalars().all())

        # Detach obsolete roles from user_roles and role_permissions
        prune_user_roles_stmt = delete(UserRole).where(UserRole.role_id.in_(obsolete_role_subq))
        prune_user_roles_res = await self.db.execute(prune_user_roles_stmt)
        pruned_user_role_links = prune_user_roles_res.rowcount or 0

        await self.db.flush()

        # 5. Emit System-Originated Snapshots for delta changes
        # Role snapshots
        all_affected_role_ids = set(roles_with_added_links.keys()) | roles_with_pruned_perm_ids
        for r_id in all_affected_role_ids:
            stmt = (
                select(Permission.id, Permission.code)
                .join(RolePermission, RolePermission.permission_id == Permission.id)
                .where(RolePermission.role_id == r_id)
                .where(Permission.code.in_(valid_perm_codes))
                .order_by(Permission.code.asc())
            )
            r_perms_res = await self.db.execute(stmt)
            perm_payload = [{"id": str(p[0]), "code": p[1]} for p in r_perms_res.fetchall()]

            reasons = []
            if r_id in roles_with_added_links:
                reasons.append(f"linked {len(roles_with_added_links[r_id])} default permission(s)")
            if r_id in roles_with_pruned_perm_ids:
                reasons.append("pruned obsolete permission links")
            reason_str = f"System startup enum synchronization: {', '.join(reasons)}"

            await self.create_role_permission_snapshot(
                role_id=r_id,
                permissions_payload=perm_payload,
                changed_by_id=None,
                reason=reason_str,
            )

        # User snapshots for accounts that had obsolete roles detached
        for u_id in users_with_pruned_role_ids:
            user_rbac_user = await self.get_user_with_rbac_details(u_id)
            if user_rbac_user:
                active_roles = [r for r in user_rbac_user.roles if r.name in valid_role_names]
                roles_payload = [
                    {"id": str(r.id), "name": r.name, "rank": get_role_rank(r.name)}
                    for r in active_roles
                ]
                direct_permissions_payload = []
                effective_map = {}
                for r in active_roles:
                    for p in r.permissions:
                        if p.code in valid_perm_codes:
                            effective_map[p.code] = {"id": str(p.id), "code": p.code}
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

                await self.create_user_rbac_snapshot(
                    user_id=u_id,
                    roles_payload=roles_payload,
                    direct_permissions_payload=direct_permissions_payload,
                    effective_permissions_payload=effective_permissions_payload,
                    changed_by_id=None,
                    reason="System startup lifespan pruning: detached obsolete role(s)",
                )

        await self.db.commit()
        logger.info(
            f"RBAC enum sync & lifespan pruning completed: {roles_synced} roles, {perms_synced} perms synced, "
            f"{links_added} links added, {pruned_perm_links} obsolete perm links pruned, "
            f"{pruned_user_role_links} obsolete user role links pruned."
        )
        return {
            "roles_synced": roles_synced,
            "permissions_synced": perms_synced,
            "links_added": links_added,
            "pruned_perm_links": pruned_perm_links,
            "pruned_user_role_links": pruned_user_role_links,
        }


    async def create_role_permission_snapshot(
        self,
        role_id: UUID,
        permissions_payload: list,
        changed_by_id: Optional[UUID],
        reason: str,
    ) -> RolePermissionSnapshot:
        """Records an immutable point-in-time snapshot of role permissions."""
        snapshot = RolePermissionSnapshot(
            role_id=role_id,
            permissions_payload=permissions_payload,
            changed_by_id=changed_by_id,
            reason=reason,
        )
        self.db.add(snapshot)
        await self.db.flush()
        return snapshot


    async def create_user_rbac_snapshot(
        self,
        user_id: UUID,
        roles_payload: list,
        direct_permissions_payload: list,
        effective_permissions_payload: list,
        changed_by_id: Optional[UUID],
        reason: str,
    ) -> UserRBACSnapshot:
        """Records an immutable point-in-time snapshot of user roles, direct permissions, and effective permissions."""
        snapshot = UserRBACSnapshot(
            user_id=user_id,
            roles_payload=roles_payload,
            direct_permissions_payload=direct_permissions_payload,
            effective_permissions_payload=effective_permissions_payload,
            changed_by_id=changed_by_id,
            reason=reason,
        )
        self.db.add(snapshot)
        await self.db.flush()
        return snapshot


    async def get_role_permission_history(
        self,
        role_id: Optional[UUID] = None,
        from_date: Optional[datetime] = None,
        to_date: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[RolePermissionSnapshot]:
        """Fetches chronological snapshot history across all roles or for a specific role with date filters."""
        stmt = (
            select(RolePermissionSnapshot)
            .options(
                selectinload(RolePermissionSnapshot.role),
                selectinload(RolePermissionSnapshot.changed_by),
            )
        )
        if role_id is not None:
            stmt = stmt.where(RolePermissionSnapshot.role_id == role_id)
        if from_date:
            stmt = stmt.where(RolePermissionSnapshot.created_at >= from_date)
        if to_date:
            stmt = stmt.where(RolePermissionSnapshot.created_at <= to_date)

        stmt = stmt.order_by(RolePermissionSnapshot.created_at.desc()).limit(limit).offset(offset)
        res = await self.db.execute(stmt)
        return res.scalars().all()


    async def get_user_rbac_history(
        self,
        user_id: UUID,
        from_date: Optional[datetime] = None,
        to_date: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[UserRBACSnapshot]:
        """Fetches chronological snapshot history for a specific user with date filters."""
        stmt = (
            select(UserRBACSnapshot)
            .options(
                selectinload(UserRBACSnapshot.user),
                selectinload(UserRBACSnapshot.changed_by),
            )
            .where(UserRBACSnapshot.user_id == user_id)
        )
        if from_date:
            stmt = stmt.where(UserRBACSnapshot.created_at >= from_date)
        if to_date:
            stmt = stmt.where(UserRBACSnapshot.created_at <= to_date)

        stmt = stmt.order_by(UserRBACSnapshot.created_at.desc()).limit(limit).offset(offset)
        res = await self.db.execute(stmt)
        return res.scalars().all()


    async def get_role_permission_snapshot_by_id(
        self,
        snapshot_id: UUID,
    ) -> Optional[RolePermissionSnapshot]:
        """Fetches a specific role permission snapshot with eager loaded relationships."""
        stmt = (
            select(RolePermissionSnapshot)
            .options(
                selectinload(RolePermissionSnapshot.role),
                selectinload(RolePermissionSnapshot.changed_by),
            )
            .where(RolePermissionSnapshot.id == snapshot_id)
        )
        res = await self.db.execute(stmt)
        return res.scalar_one_or_none()


    async def get_user_rbac_snapshot_by_id(
        self,
        snapshot_id: UUID,
    ) -> Optional[UserRBACSnapshot]:
        """Fetches a specific user RBAC snapshot with eager loaded relationships."""
        stmt = (
            select(UserRBACSnapshot)
            .options(
                selectinload(UserRBACSnapshot.user),
                selectinload(UserRBACSnapshot.changed_by),
            )
            .where(UserRBACSnapshot.id == snapshot_id)
        )
        res = await self.db.execute(stmt)
        return res.scalar_one_or_none()


    async def restore_user_direct_permissions(
        self,
        user_id: UUID,
        direct_permissions_payload: list,
        assigned_by_id: UUID,
        reason: str,
    ) -> None:
        """Wipes current direct permission overrides for a user and restores the snapshot's direct permissions."""
        del_stmt = delete(UserPermission).where(UserPermission.user_id == user_id)
        await self.db.execute(del_stmt)

        for item in direct_permissions_payload:
            p_id = UUID(item["id"]) if isinstance(item["id"], str) else item["id"]
            is_granted = item.get("is_granted", True)
            self.db.add(
                UserPermission(
                    user_id=user_id,
                    permission_id=p_id,
                    is_granted=is_granted,
                    assigned_by_id=assigned_by_id,
                    reason=reason,
                )
            )
        await self.db.flush()
