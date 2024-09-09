# Аутентификация в FastAPI | Токены Access + Refresh

Refresh token (токен обновления) — это тип токена, который используется в системах аутентификации для получения нового 
токена доступа (access token) после того, как срок его действия истек. Токены доступа обычно имеют короткий срок 
хранения для повышения безопасности, в то время как токены обновления имеют более длительный или даже неограниченный 
срок действия.


## Строим нашу JWT auth

1. Установить библиотеку можно с помощью команды:
   - poetry add "pyjwt[crypto]"
2. Сгенерируем public и secret key
   - скопируйте команды для создания ключей из *src/auth/README.md*
   - создайте папку certs и выполните команды
   - не забудьте добавить /certs в .gitignore
3. Укажем в нашем core/config пути к нашим ключам
   ```
   src/core/config
   
   class AuthJWT(BaseModel):
       private_key_path: Path = BASE_DIR / "src" / "certs" / "jwt-private.pem"
       public_key_path: Path = BASE_DIR / "src" / "certs" / "jwt-public.pem"
       algorithm: str = "RS256"
       access_token_expire_minutes: int = 15
       refresh_token_expire_days: int = 30
   ```
4. Напишем функции которые помогут создавать токены и парсить их.
   ```
   src/auth/utils.py
   
   def encode_jwt():
       """Функция для кодирования данных в JWT"""
       pass
       
   def decode_jwt():
      """Функция для расшифровки JWT"""
      pass
   ```
5. Прежде чем выдавать пользователю токен, нужно его аутонтефицировать, для этого напишем эндпоинт с аутентификацией
   - добавим schemas для валидации пользователя
   ```
   src/api_v1/schemas/user_schemas.py
      
   class UserSchema(BaseModel):
      pass
   
   class UserOut(UserSchema):
      pass
   ```
   - добавим функции для шифровки и проверки пароля с помощью библиотеки bcrypt
   ```
   src/auth/utils
   
   poetry add bcrypt
   
   def hash_password(password: str) -> bytes:
       """Функция для шифрования пароля"""
       pass
   
   def validate_password(
       password: str,
       hashed_password: bytes,
   ) -> bool:
       """Функция для проверки соответствия пароля"""
       pass   
   ```
6. Создаем роутер для создания юзера
   ```
   src/api_v1/routers/user_router.py
   
   @router.post(
       "/register",
       response_model=UserOut,
       status_code=status.HTTP_201_CREATED,
   )
   async def register_user(
       user_in: UserSchema,
       session: AsyncSession = Depends(db_helper.get_db),
   ):
       return await create_user(session=session, user_in=user_in)
   ```
7. Создаем роутер для аутентификации по логину и паролю, который после проверки пользователя сгенерирует JWT токен
   - для начала создадим валидатор для возвращаемого токена
   ```
   src/api_v1/schemas/token_schemas.py
   
   class TokenInfo(BaseModel):
       access_token: str
       refresh_token: str | None = None
       token_type: str = "Bearer"
   ```
   - создаем роутер для аутентификации
   ```
   src/api_v1/routers/demo_jwt_auth.py
   
   @router.post("/login", response_model=TokenInfo)
   async def login(
       user: UserSchema = Depends(validate_auth_user),
   ) -> TokenInfo:
      access_token = create_access_token(user)
      refresh_token = create_refresh_token(user)
      return TokenInfo(
         access_token=access_token,
         refresh_token=refresh_token,
   )
   ```
   - создадим функцию для создания access токена
   ```
   src/auth/create_token.py
   
   def create_access_token(user: UserSchema) -> str:
      """Функция для создания access токена"""
      pass
   ```
   - создадим функцию для создания токенов access/refresh
   ```
   src/auth/create_token.py
   
   def create_jwt(
       token_type: str,
       token_data: dict,
       expire_minutes: int = settings.auth_jwt.access_token_expire_minutes,
       expire_timedelta: timedelta | None = None,
   ) -> str:
       """Функция для создания токена access/refresh"""
       pass
   ```
   - создадим функцию для создания refresh токена
   ```
   src/auth/create_token.py

   def create_refresh_token(user: UserSchema) -> str:
       """Функция для создания refresh token"""
       pass
   ```
   - создаем функцию которая будет валидировать логин и пароль введеные юзером
   ```
   src/api_v1/dependencies/security_dependencies.py
   
   oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/login")
   
   async def validate_auth_user(
       # form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
       username: str = Form(...),
       password: str = Form(...),
       session: AsyncSession = Depends(db_helper.get_db),
   ) -> UserOut:
      pass
   ```
   
8. Научим пользователя выпускать новый access token при помощи refresh
   - создадим эндпоинт для выпуска refresh token
   ```
   src/api_v1/routers/demo_jwt_auth.py
   
   @router.post(
       "/refresh/",
       response_model=TokenInfo,
       response_model_exclude_none=True,  # если в TokenInfo будет поле с None, то мы его скроем
   )
   def auth_refresh_jwt(
       # todo: validate user is active!!
       user: UserSchema = Depends(get_current_active_auth_user(REFRESH_TOKEN_TYPE)),
   ):
       access_token = create_access_token(user)
       return TokenInfo(
           access_token=access_token,
       )
   ```
   - напишем функцию проверяющую активен ли пользователь get_current_active_auth_user
   ```
   src/api_v1/dependencies/security_dependencies.py
   
   def get_current_active_auth_user(token_type: str):
       def wrapper(
           user: UserSchema = Depends(UserGetterFromToken(token_type)),
       ):
           """Функция для проверки активен ли юзер"""
   ```
   - напишем класс который проверяет токен(access/refresh) и возвращает информацию о нем из токена UserGetterFromToken
   ```
   src/api_v1/dependencies/security_dependencies.py
   
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
   ```
   - напишем функции для валидации токена validate_token_type и получения юзера из токена get_user_by_token_sub
   ```
   src/api_v1/dependencies/security_dependencies.py

   def validate_token_type(
       payload: dict,
       token_type: str,
   ) -> bool:
       """
       Функция которая получает на вход payload и тип токена, если они совпадают, то возвращает True.
       Предназначена чтобы различать рефреш токен и эксесс
       """
       pass
   ```
   ```
   src/api_v1/dependencies/security_dependencies.py

   async def get_user_by_token_sub(
       payload: dict,
       session: AsyncSession = Depends(db_helper.get_db),
   ):
       """
       Эта функция служит для поиска юзера в БД, на вход получает payload, оттуда берем id юзера и ищем
       """
       pass
   ```
   - функция для получения payload из токена
   ```
   src/api_v1/dependencies/security_dependencies.py
   
   def get_current_token_payload(
       token: str = Depends(oauth2_scheme),
   ):
       """Берем из заголовка JWT, декодируем и возвращаем payload"""
   ```

9. Напишем эндпоинт для получения информации о себе
   ```
   src/api_v1/routers/user_router.py
   
   @router.get("/users/me/")
   async def read_users_me(
       payload: dict = Depends(get_current_token_payload),
       user: UserSchema = Depends(get_current_active_auth_user(ACCESS_TOKEN_TYPE)),
   ):
      pass
   ```
     

