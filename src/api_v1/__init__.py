from fastapi import APIRouter

from src.api_v1.routers.demo_jwt_auth import router as auth_router
from src.api_v1.routers.user_router import router as user_router
from src.api_v1.routers.views_for_auth import router as views_for_auth_router
from ..core.config import settings

router = APIRouter(
    prefix=settings.api_vi_prefix,
)

router.include_router(auth_router)
router.include_router(user_router)
router.include_router(views_for_auth_router)
