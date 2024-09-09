from fastapi import APIRouter, Depends

from src.api_v1.dependencies.security_dependencies import (
    get_current_active_auth_user,
    get_current_token_payload,
    http_bearer,
)
from src.api_v1.schemas.user_schemas import UserSchema
from src.auth.create_token import ACCESS_TOKEN_TYPE

router = APIRouter(tags=["Users"], dependencies=[Depends(http_bearer)])


@router.get("/users/me/")
async def read_users_me(
    payload: dict = Depends(get_current_token_payload),
    user: UserSchema = Depends(get_current_active_auth_user(ACCESS_TOKEN_TYPE)),
):
    iat = payload.get("iat")
    return {
        "id": user.id,
        "email": user.email,
        "username": user.username,
        "logged_at_in": iat,
    }
