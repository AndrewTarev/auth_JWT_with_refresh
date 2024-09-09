from fastapi import Depends, status, HTTPException, Form
from fastapi.security import (
    OAuth2PasswordBearer,
    HTTPBearer,
)
from jwt import InvalidTokenError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api_v1.schemas.user_schemas import UserOut, UserSchema
from src.auth.utils import (
    validate_password,
    decode_jwt,
    TOKEN_TYPE_FIELD,
    ACCESS_TOKEN_TYPE,
    REFRESH_TOKEN_TYPE,
)
from src.core.database.db_helper import db_helper
from src.core.database.models import User


"""
HTTPBearer - используется для обработки "Bearer" токенов, которые обычно передаются в заголовке Authorization 
HTTP-запроса.

HTTPAuthorizationCredentials — это класс, который используется для представления учетных данных, передаваемых в
HTTP заголовке Authorization.

OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login") - автоматически подставляет учетные данные из эндпоинта /login

1. Атрибуты:
   - scheme: Строка, которая представляет тип схемы авторизации, например, "Bearer", "Basic" и т. д.
   - credentials: Строка, которая содержит учетные данные (например, токен или пароль).

2. Использование:
   Обычно HTTPAuthorizationCredentials используется вместе с Depends, чтобы извлечь и проверить файл аутентификации из
заголовка запроса.
"""

http_bearer = HTTPBearer(auto_error=False)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


async def validate_auth_user(
    # form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    username: str = Form(...),
    password: str = Form(...),
    session: AsyncSession = Depends(db_helper.get_db),
) -> UserOut:
    stmt = select(User).where(User.username == username)
    res = await session.execute(stmt)
    user = res.scalars().first()

    if not user or validate_password(password, user.password) is False:
        raise HTTPException(
            status_code=400,
            detail="Incorrect username or password",
        )

    if not user.active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User inactive",
        )

    return user


def get_current_token_payload(
    token: str = Depends(oauth2_scheme),
):
    """
    Берем из заголовка JWT, декодируем и возвращаем payload
    :param token: с помощью OAuth2PasswordBearer мы автоматически получам токен при аутентификации в форме запроса
    :return: Позволяет вытащить токен из заголовка Authorization
    """
    try:
        payload = decode_jwt(token=token)
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"invalid token error",
        )
    return payload


def validate_token_type(
    payload: dict,
    token_type: str,
) -> bool:
    """
    Функция которая получает на вход payload и тип токена, если они совпадают, то возвращает True.
    Предназначена чтобы различать рефреш токен и эксесс
    :param payload: полезную нагрузку
    :param token_type: тип токена access/refresh
    :return: True/False
    """
    current_token_type = payload.get(TOKEN_TYPE_FIELD)
    if current_token_type == token_type:
        return True
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=f"invalid token type {current_token_type!r} expected {token_type!r}",
    )


async def get_user_by_token_sub(
    payload: dict,
    session: AsyncSession = Depends(db_helper.get_db),
):
    """
    Эта функция служит для поиска юзера в БД, на вход получает payload, оттуда берем id юзера и ищем
    """
    user_id: int = payload.get("sub")
    # сюда можно добавить проверку jti(id tokena), что он не находится в блэклисте
    user = await session.get(User, user_id)
    if user:
        return user
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="token invalid (user not found)",
    )


class UserGetterFromToken:
    """
    Этот класс валидирует токен(access/refresh) и возвращает юзера
    """

    def __init__(self, token_type: str):
        self.token_type = token_type

    async def __call__(
        self,
        payload: dict = Depends(get_current_token_payload),
        session: AsyncSession = Depends(db_helper.get_db),
    ):
        validate_token_type(payload, self.token_type)
        return await get_user_by_token_sub(payload, session)


def get_current_active_auth_user(token_type: str):
    def wrapper(
        user: UserSchema = Depends(UserGetterFromToken(token_type)),
    ):
        """
        Функция для проверки активен ли юзер
        :param user: юзер
        :return: активный юзер
        """
        if user.active:
            return user
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="inactive user",
        )

    return wrapper


# def get_current_active_auth_user(
#     user: UserSchema = Depends(UserGetterFromToken(ACCESS_TOKEN_TYPE)),
# ):
#     """
#     Функция для проверки активен ли юзер
#     :param user: юзер
#     :return: активный юзер
#     """
#     if user.active:
#         return user
#     raise HTTPException(
#         status_code=status.HTTP_403_FORBIDDEN,
#         detail="inactive user",
#     )
