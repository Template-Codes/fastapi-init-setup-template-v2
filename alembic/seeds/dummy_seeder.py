from loguru import logger
from pwdlib import PasswordHash
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

# pyrefly: ignore [missing-import]
from alembic.seeds.base_seeder import BaseSeeder
from core.settings import settings
from modules.authentication.auth_model import User, UserStatus
from modules.rbac.rbac_model import Role, UserRole
from modules.profile.user_profile_model import UserGender, UserProfile
from modules.session import session_model  # noqa: F401
from shares.enums import RoleName


class DummySeeder(BaseSeeder):
    """
    Dev/Test dummy data seeder.
    Populates sample accounts and user profiles for local testing.
    STRICTLY blocked from running in production environment.
    """

    pwd_context = PasswordHash.recommended()

    async def seed(self, session: AsyncSession) -> None:
        if settings.ENVIRONMENT == "prod":
            raise RuntimeError(
                "CRITICAL SECURITY GUARD: Dummy seeder cannot be executed in production environment!"
            )

        logger.info("--- Starting Dummy Seeding (Development / Testing) ---")

        # Fetch system roles
        stmt = select(Role)
        res = await session.execute(stmt)
        roles = {r.name: r for r in res.scalars().all()}

        dummy_password = "Password@123"
        hashed_pwd = self.pwd_context.hash(dummy_password)

        dummy_users = [
            {
                "user_code": "USR-00004",
                "username": "pending_user",
                "email": "pending@system.local",
                "status": UserStatus.PENDING,
                "role_name": RoleName.STAFF_USER.value,
                "first_name": "Pending",
                "last_name": "TestUser",
                "gender": UserGender.MALE,
                "cellphone_number": "+12345678901",
            },
            {
                "user_code": "USR-00003",
                "username": "staff_user",
                "email": "staff@system.local",
                "status": UserStatus.ACTIVE,
                "role_name": RoleName.STAFF_USER.value,
                "first_name": "John",
                "last_name": "Doe",
                "gender": UserGender.MALE,
                "cellphone_number": "+12345678902",
            },
            {
                "user_code": "USR-00002",
                "username": "admin_user",
                "email": "admin_test@system.local",
                "status": UserStatus.ACTIVE,
                "role_name": RoleName.ADMIN.value,
                "first_name": "Jane",
                "last_name": "Smith",
                "gender": UserGender.FEMALE,
                "cellphone_number": "+12345678903",
            },
        ]

        for u_data in dummy_users:
            stmt = select(User).options(selectinload(User.roles)).where(User.username == u_data["username"])
            res = await session.execute(stmt)
            existing_user = res.scalar_one_or_none()

            if not existing_user:
                new_user = User(
                    user_code=u_data["user_code"],
                    username=u_data["username"],
                    email=u_data["email"],
                    password_hash=hashed_pwd,
                    status=u_data["status"],
                )
                session.add(new_user)
                await session.flush()

                # Assign role if exists via UserRole junction
                if u_data["role_name"] in roles:
                    role_obj = roles[u_data["role_name"]]
                    ur = UserRole(user_id=new_user.id, role_id=role_obj.id)
                    session.add(ur)

                # Create profile
                user_profile = UserProfile(
                    user_id=new_user.id,
                    first_name=u_data["first_name"],
                    last_name=u_data["last_name"],
                    gender=u_data["gender"],
                    cellphone_number=u_data["cellphone_number"],
                    country="Philippines",
                )
                session.add(user_profile)
                await session.flush()

                logger.info(
                    f"Seeded dummy user: {u_data['username']} [{u_data['status'].value}] with role {u_data['role_name']}"
                )
            else:
                logger.info(f"Dummy user already exists: {u_data['username']}")

        logger.info("--- Completed Dummy Seeding ---")
