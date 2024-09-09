from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from starlette import status

from src.api_v1.cruds.user_crud import create_user
from src.api_v1.dependencies.security_dependencies import (
    validate_auth_user,
    http_bearer,
    get_current_active_auth_user,
)
from src.api_v1.schemas.token_schemas import TokenInfo
from src.api_v1.schemas.user_schemas import UserSchema, UserOut
from src.auth.create_token import (
    create_access_token,
    create_refresh_token,
    REFRESH_TOKEN_TYPE,
)
from src.core.database.db_helper import db_helper
from src.core.database.models import User

router = APIRouter(prefix="/auth", tags=["Auth"], dependencies=[Depends(http_bearer)])


@router.post("/login/", response_model=TokenInfo)
def auth_user_issue_jwt(
    user: UserSchema = Depends(validate_auth_user),
):
    access_token = create_access_token(user)
    refresh_token = create_refresh_token(user)
    return TokenInfo(
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.post(
    "/refresh/",
    response_model=TokenInfo,
    response_model_exclude_none=True,  # если в TokenInfo будет поле с None, то мы его скроем
)
def auth_refresh_jwt(
    user: UserSchema = Depends(get_current_active_auth_user(REFRESH_TOKEN_TYPE)),
):
    access_token = create_access_token(user)
    return TokenInfo(
        access_token=access_token,
    )


@router.post(
    "/register/",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    user_in: UserSchema,
    session: AsyncSession = Depends(db_helper.get_db),
) -> User:
    return await create_user(session=session, user_in=user_in)
