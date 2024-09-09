import uuid
from datetime import timedelta
import datetime

import bcrypt
import jwt

from src.core.config import settings


TOKEN_TYPE_FIELD = "type"
ACCESS_TOKEN_TYPE = "access"
REFRESH_TOKEN_TYPE = "refresh"


def encode_jwt(
    payload: dict,
    private_key: str = settings.auth_jwt.private_key_path.read_text(),
    algorithm: str = settings.auth_jwt.algorithm,
    expire_minutes: int = settings.auth_jwt.access_token_expire_minutes,
    expire_timedelta: timedelta | None = None,
):
    """
    Функция для кодирования данных в JWT
    :param payload: данные для кодирования
    :param private_key: путь к приватному ключу
    :param algorithm: алгоритм шифрования
    :param expire_minutes: срок жизни токена
    :param expire_timedelta: указываем через сколько закончится срок жизни токена
    :return: JWT token
    """
    to_encode = payload.copy()
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    if expire_timedelta:
        expire = now + expire_timedelta
    else:
        expire = now + timedelta(minutes=expire_minutes)
    to_encode.update(
        exp=expire,
        iat=now,  # Время когда был выпущен токен
        jti=str(
            uuid.uuid4()
        ),  # json token identifier айди токена (для блэк листа например)
    )
    encoded = jwt.encode(
        to_encode,
        private_key,
        algorithm=algorithm,
    )
    return encoded


def decode_jwt(
    token: str | bytes,
    public_key: str = settings.auth_jwt.public_key_path.read_text(),
    algorithm: str = settings.auth_jwt.algorithm,
):
    """
    Функция для расшифровки JWT
    :param token: JWT token
    :param public_key: путь к публичному ключу
    :param algorithm: алгоритм шифрования
    :return:
    """
    decoded = jwt.decode(
        token,
        public_key,
        algorithms=[algorithm],
    )
    return decoded


def hash_password(password: str) -> bytes:
    """
    Функция для шифрования пароля
    :param password: принимает пароль
    :return: хэшированный пароль в bytes
    """
    salt = bcrypt.gensalt()
    pwd_bytes: bytes = password.encode("utf-8")
    return bcrypt.hashpw(pwd_bytes, salt)


def validate_password(
    password: str,
    hashed_password: bytes,
) -> bool:
    """
    Функция для проверки соответствия пароля
    :param password: пароль который вводит пользователь
    :param hashed_password: хэшированный пароль из БД
    :return: True or False
    """
    return bcrypt.checkpw(
        password=password.encode(),
        hashed_password=hashed_password,
    )
