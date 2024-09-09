from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.api_v1.schemas.user_schemas import UserSchema
from src.auth.utils import hash_password
from src.core.database.models import User


async def create_user(
    session: AsyncSession,
    user_in: UserSchema,
) -> User:
    stmt = select(User).where(User.username == user_in.username)
    result = await session.execute(stmt)
    user = result.scalars().first()
    if user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"User with username {user_in.username} already exists",
        )

    password = hash_password(user_in.password)
    create_new_user = User(
        username=user_in.username,
        email=user_in.email,
        password=password,
        active=user_in.active,
    )

    session.add(create_new_user)
    await session.commit()
    return create_new_user
