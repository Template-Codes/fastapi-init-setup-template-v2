from loguru import logger
from pwdlib import PasswordHash
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

# pyrefly: ignore [missing-import]
from alembic.seeds.base_seeder import BaseSeeder
from core.settings import settings
from modules.authentication.auth_model import User, UserStatus
from modules.rbac.rbac_model import Permission, Role, RolePermission, UserRole
from modules.profile.user_profile_model import UserGender, UserProfile
from modules.session import session_model  # noqa: F401
from shares.enums import RoleName, SystemPermission


class SystemSeeder(BaseSeeder):
    """
    Production-safe system seeder.
    Populates core system roles, system permissions, role-permission links,
    and initializes an active Super Admin user for immediate testing & administration.
    """

    pwd_context = PasswordHash.recommended()

    async def seed(self, session: AsyncSession) -> None:
        logger.info("--- Starting System Seeding ---")

        # ------------------------------------------------------------------
        # 1. Seed System Roles
        # ------------------------------------------------------------------
        roles_data = [
            {
                "name": RoleName.SUPER_ADMIN.value,
                "description": "System Super Administrator with full root access",
                "is_system_role": True,
            },
            {
                "name": RoleName.ADMIN.value,
                "description": "System Administrator for managing users and registrations",
                "is_system_role": True,
            },
            {
                "name": RoleName.STAFF_USER.value,
                "description": "Standard internal system employee/user",
                "is_system_role": True,
            },
            {
                "name": RoleName.PUBLIC_USER.value,
                "description": "External public or limited guest user",
                "is_system_role": True,
            },
        ]

        roles_map: dict[str, Role] = {}
        for r_info in roles_data:
            stmt = select(Role).options(selectinload(Role.permissions)).where(Role.name == r_info["name"])
            res = await session.execute(stmt)
            existing_role = res.scalar_one_or_none()

            if not existing_role:
                new_role = Role(
                    name=r_info["name"],
                    description=r_info["description"],
                    is_system_role=r_info["is_system_role"],
                )
                session.add(new_role)
                await session.flush()
                # Refresh with options so relationship is initialized asynchronously
                stmt_ref = select(Role).options(selectinload(Role.permissions)).where(Role.id == new_role.id)
                res_ref = await session.execute(stmt_ref)
                roles_map[r_info["name"]] = res_ref.scalar_one()
                logger.info(f"Created system role: {r_info['name']}")
            else:
                roles_map[r_info["name"]] = existing_role
                logger.info(f"System role already exists: {r_info['name']}")

        # ------------------------------------------------------------------
        # 2. Seed System Permissions
        # ------------------------------------------------------------------
        permissions_map: dict[str, Permission] = {}
        for sys_perm in SystemPermission:
            code_str = sys_perm.value
            module_name = code_str.split(":")[0]
            display_name = code_str.replace(":", " ")

            stmt = select(Permission).where(Permission.code == code_str)
            res = await session.execute(stmt)
            existing_perm = res.scalar_one_or_none()

            if not existing_perm:
                new_perm = Permission(
                    code=code_str,
                    module=module_name,
                    name=display_name,
                    description=f"System permission for {display_name}",
                )
                session.add(new_perm)
                await session.flush()
                permissions_map[code_str] = new_perm
                logger.info(f"Created system permission: {code_str}")
            else:
                permissions_map[code_str] = existing_perm

        # ------------------------------------------------------------------
        # 3. Map Permissions to Roles (RolePermission table)
        # ------------------------------------------------------------------
        async def link_role_permissions(role: Role, perms: list[Permission]):
            existing_perm_ids = {p.id for p in role.permissions}
            for perm in perms:
                if perm.id not in existing_perm_ids:
                    rp = RolePermission(role_id=role.id, permission_id=perm.id)
                    session.add(rp)

        # Super Admin gets all system permissions
        all_permissions = list(permissions_map.values())
        await link_role_permissions(roles_map[RoleName.SUPER_ADMIN.value], all_permissions)

        # Admin gets all authentication & profile permissions
        await link_role_permissions(roles_map[RoleName.ADMIN.value], all_permissions)

        # Staff user gets read/profile permissions
        staff_perms = [
            permissions_map[SystemPermission.PROFILE_USER_READ.value],
            permissions_map[SystemPermission.PROFILE_USER_UPDATE.value],
        ]
        await link_role_permissions(roles_map[RoleName.STAFF_USER.value], staff_perms)

        await session.flush()
        logger.info("Mapped default permissions to system roles.")

        # ------------------------------------------------------------------
        # 4. Seed Initial Super Admin User (Bypasses manual admin approval)
        # ------------------------------------------------------------------
        sa_username = settings.SEED_SUPERADMIN_USERNAME
        sa_email = settings.SEED_SUPERADMIN_EMAIL
        sa_password = settings.SEED_SUPERADMIN_PASSWORD

        stmt = select(User).options(selectinload(User.roles)).where(
            (User.username == sa_username) | (User.email == sa_email)
        )
        res = await session.execute(stmt)
        existing_sa = res.scalar_one_or_none()

        if not existing_sa:
            hashed_pwd = self.pwd_context.hash(sa_password)
            sa_user = User(
                user_code="USR-00001",
                username=sa_username,
                email=sa_email,
                password_hash=hashed_pwd,
                status=UserStatus.ACTIVE,  # Direct ACTIVE status to bypass approval flow!
            )
            session.add(sa_user)
            await session.flush()

            # Attach SUPER_ADMIN role via UserRole junction
            ur = UserRole(user_id=sa_user.id, role_id=roles_map[RoleName.SUPER_ADMIN.value].id)
            session.add(ur)

            # Create UserProfile for Super Admin
            sa_profile = UserProfile(
                user_id=sa_user.id,
                first_name="System",
                last_name="SuperAdmin",
                gender=UserGender.OTHERS,
                cellphone_number="+0000000000",
                country="Philippines",
            )
            session.add(sa_profile)
            await session.flush()

            logger.info(
                f"Successfully seeded Super Admin user: {sa_username} ({sa_email}) [Status: ACTIVE]"
            )
        else:
            logger.info(f"Super Admin user already exists: {sa_username}")

        logger.info("--- Completed System Seeding ---")
