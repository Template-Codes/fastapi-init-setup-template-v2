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
            # 1 Admin (complete requirement)
            {
                "username": "admin1",
                "email": "admin1@system.local",
                "status": UserStatus.ACTIVE,
                "role_name": RoleName.ADMIN.value,
                "profile": {
                    "first_name": "Admin",
                    "last_name": "One",
                    "gender": UserGender.FEMALE,
                    "cellphone_number": "+639170000002",
                    "street": "456 Corporate Ave",
                    "city": "Valenzuela",
                    "province_state": "Metro Manila",
                    "postal_code": "1440",
                    "country": "Philippines",
                },
            },
            # 2 Staff users (complete requirements)
            {
                "username": "staff1",
                "email": "staff1@system.local",
                "status": UserStatus.ACTIVE,
                "role_name": RoleName.STAFF_USER.value,
                "profile": {
                    "first_name": "Staff",
                    "last_name": "One",
                    "gender": UserGender.MALE,
                    "cellphone_number": "+639170000003",
                    "street": "789 Factory Rd",
                    "city": "Valenzuela",
                    "province_state": "Metro Manila",
                    "postal_code": "1440",
                    "country": "Philippines",
                },
            },
            {
                "username": "staff2",
                "email": "staff2@system.local",
                "status": UserStatus.ACTIVE,
                "role_name": RoleName.STAFF_USER.value,
                "profile": {
                    "first_name": "Staff",
                    "last_name": "Two",
                    "gender": UserGender.FEMALE,
                    "cellphone_number": "+639170000004",
                    "street": "790 Factory Rd",
                    "city": "Valenzuela",
                    "province_state": "Metro Manila",
                    "postal_code": "1440",
                    "country": "Philippines",
                },
            },
            # 2 Public users (incomplete requirements - no profile record)
            {
                "username": "public1",
                "email": "public1@system.local",
                "status": UserStatus.ACTIVE,
                "role_name": RoleName.PUBLIC_USER.value,
                "profile": None,
            },
            {
                "username": "public2",
                "email": "public2@system.local",
                "status": UserStatus.PENDING,
                "role_name": RoleName.PUBLIC_USER.value,
                "profile": None,
            },
        ]

        for u_data in dummy_users:
            stmt = select(User).options(selectinload(User.roles)).where(User.username == u_data["username"])
            res = await session.execute(stmt)
            existing_user = res.scalar_one_or_none()

            if not existing_user:
                new_user = User(
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

                # Create profile if complete requirements provided
                p_info = u_data["profile"]
                if p_info:
                    user_profile = UserProfile(
                        user_id=new_user.id,
                        first_name=p_info["first_name"],
                        last_name=p_info["last_name"],
                        gender=p_info["gender"],
                        cellphone_number=p_info["cellphone_number"],
                        street=p_info.get("street"),
                        city=p_info.get("city"),
                        province_state=p_info.get("province_state"),
                        postal_code=p_info.get("postal_code"),
                        country=p_info.get("country", "Philippines"),
                    )
                    session.add(user_profile)
                    await session.flush()
                    profile_status = "profile: COMPLETE"
                else:
                    profile_status = "profile: INCOMPLETE (no profile)"

                logger.info(
                    f"Seeded user: {u_data['username']} [{u_data['status'].value}] "
                    f"role: {u_data['role_name']}, {profile_status}"
                )
            else:
                logger.info(f"Dummy user already exists: {u_data['username']}")

        logger.info("--- Completed Dummy Seeding ---")
