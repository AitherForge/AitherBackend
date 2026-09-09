from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.admin import router as admin_router
from app.api.ai import router as ai_router
from app.api.apps import router as apps_router
from app.api.auth import router as auth_router
from app.api.config import router as config_router
from app.api.data import router as data_router
from app.api.firebase_auth import router as firebase_auth_router
from app.api.google_auth import router as google_auth_router
from app.api.health import router as health_router
from app.api.healthz import router as healthz_router
from app.api.mail import router as mail_router
from app.api.notifications import router as notifications_router
from app.api.password_reset import router as password_reset_router
from app.api.status import router as status_router
from app.api.updates import router as updates_router
from app.api.users import router as users_router
from app.api.weather import router as weather_router
from app.config import settings
from app.db import init_db

@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield

app = FastAPI(title=settings.app_name,description="Central API backend for Aither Tech applications.",version=settings.app_version,lifespan=lifespan)
app.add_middleware(CORSMiddleware,allow_origins=settings.cors_origin_list,allow_origin_regex=r"^https://[a-zA-Z0-9-]+\.github\.io$|^https?://(localhost|127\.0\.0\.1)(:\d+)?$",allow_credentials=True,allow_methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS"],allow_headers=["Accept","Content-Type","Authorization","X-Requested-With"],expose_headers=["Content-Type"],max_age=86400)

app.include_router(status_router)
app.include_router(auth_router)
app.include_router(password_reset_router)
app.include_router(firebase_auth_router)
app.include_router(google_auth_router)
app.include_router(admin_router)
app.include_router(ai_router)
app.include_router(apps_router)
app.include_router(data_router)
app.include_router(mail_router)
app.include_router(updates_router)
app.include_router(health_router)
app.include_router(healthz_router)
app.include_router(users_router)
app.include_router(notifications_router)
app.include_router(config_router)
app.include_router(weather_router)

@app.get("/")
async def root() -> dict[str,str]:
    return {"name":settings.app_name,"status":"online","version":settings.app_version,"environment":settings.environment,"docs":"/docs"}

@app.get("/api/health")
async def health() -> dict[str,object]:
    return {"status":"healthy","service":settings.app_name,"timestamp":datetime.now(timezone.utc).isoformat()}

@app.get("/api/version")
async def version() -> dict[str,str]:
    return {"version":settings.app_version}
