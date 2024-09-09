from datetime import timedelta

from src.api_v1.schemas.user_schemas import UserSchema
from src.auth import utils as auth_utils
from src.core.config import settings


TOKEN_TYPE_FIELD = "type"
ACCESS_TOKEN_TYPE = "access"
REFRESH_TOKEN_TYPE = "refresh"


def create_jwt(
    token_type: str,
    token_data: dict,
    expire_minutes: int = settings.auth_jwt.access_token_expire_minutes,
    expire_timedelta: timedelta | None = None,
) -> str:
    """
    Функция для создания токена access/refresh
    :param token_type: тип токена access/refresh
    :param token_data: полезная нагрузка payload
    :param expire_minutes: время жизни токена
    :param expire_timedelta: время жизни токена timedelta
    :return: access или refresh токен
    """
    jwt_payload = {TOKEN_TYPE_FIELD: token_type}
    jwt_payload.update(token_data)
    return auth_utils.encode_jwt(
        payload=jwt_payload,
        expire_minutes=expire_minutes,
        expire_timedelta=expire_timedelta,
    )


def create_access_token(user: UserSchema) -> str:
    """
    Функция для создания access токена
    :param user: юзер
    :return: JWT token
    """
    jwt_payload = {
        # subject
        "sub": user.id,
        "username": user.username,
        "email": user.email,
        # "logged_in_at"
    }
    return create_jwt(
        token_type=ACCESS_TOKEN_TYPE,
        token_data=jwt_payload,
        expire_minutes=settings.auth_jwt.access_token_expire_minutes,
    )


def create_refresh_token(user: UserSchema) -> str:
    """
    Функция для создания refresh token
    :param user: юзер
    :return: refresh token
    """
    jwt_payload = {
        "sub": user.id,
        # "username": user.username,
    }
    return create_jwt(
        token_type=REFRESH_TOKEN_TYPE,
        token_data=jwt_payload,
        expire_timedelta=timedelta(days=settings.auth_jwt.refresh_token_expire_days),
    )
