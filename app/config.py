from pathlib import Path
import os

from pydantic_settings import BaseSettings, SettingsConfigDict


GEMINI_SECRET_FILE = Path("/etc/secrets/GEMINI_API_KEY")
RESEND_SECRET_FILES = (
    Path("/etc/secrets/RESEND_API_KEY"),
    Path("/etc/secrets/resend_api_key"),
    Path("/etc/secrets/resend-api-key"),
)
SERPSTACK_SECRET_FILES = (
    Path("/etc/secrets/SERPSTACK_API_KEY"),
    Path("/etc/secrets/serpstack_api_key"),
    Path("/etc/secrets/serpstack-api-key"),
)


class Settings(BaseSettings):
    app_name: str = "AitherBackend"
    app_version: str = "2.7.1"
    environment: str = "development"
    cors_origins: str = "http://localhost:3000,http://localhost:5173,https://aitherforge.github.io"
    database_url: str = "sqlite:///./aither.db"
    session_ttl_hours: int = 720
    secure_cookies: bool = True
    cookie_samesite: str = "none"
    app_url: str = "https://aitherforge.github.io"
    verification_base_url: str = "https://aitherbackendnew.onrender.com"
    smtp_host: str = "smtp.resend.com"
    smtp_port: int = 587
    smtp_username: str = "resend"
    smtp_password: str = ""
    smtp_from_email: str = "onboarding@resend.dev"
    smtp_from_name: str = "Aither"
    verification_token_hours: int = 24
    google_client_id: str = "430217545519-mcir19njrosrpd5hstamro55qq6f716b.apps.googleusercontent.com"
    openrouter_api_key: str = ""
    openrouter_url: str = "https://openrouter.ai/api/v1/chat/completions"
    ai_model: str = "openai/gpt-oss-120b"
    ai_temperature: float = 0.7
    ai_timeout_seconds: float = 90.0
    gemini_api_key: str = ""
    gemini_model: str = "gemini-3.8-flash"
    firebase_api_key: str = ""
    firebase_project_id: str = "aither-66da8"
    admin_emails: str = ""
    serpstack_api_key: str = ""
    serpstack_url: str = "https://api.serpstack.com/search"
    serpstack_timeout_seconds: float = 30.0

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def cors_origin_list(self) -> list[str]:
        origins = [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]
        required_origins = {"https://aitherforge.github.io", "http://localhost:3000", "http://localhost:5173"}
        for origin in required_origins:
            if origin not in origins:
                origins.append(origin)
        return origins

    @property
    def session_cookie_samesite(self) -> str:
        value = self.cookie_samesite.strip().lower()
        if value not in {"lax", "strict", "none"}:
            return "lax"
        if value == "none" and not self.secure_cookies:
            return "lax"
        return value

    @property
    def admin_email_list(self) -> set[str]:
        return {email.strip().lower() for email in self.admin_emails.split(",") if email.strip()}


def _load_gemini_secret_file() -> str:
    """Load the Gemini key from Render's mounted Secret File without logging it."""
    try:
        return GEMINI_SECRET_FILE.read_text(encoding="utf-8").strip()
    except (FileNotFoundError, OSError):
        return ""


def _load_resend_secret_file() -> str:
    """Load the Resend key from Render Secret Files without logging it."""
    for path in RESEND_SECRET_FILES:
        try:
            value = path.read_text(encoding="utf-8").strip()
        except (FileNotFoundError, OSError):
            continue
        if value:
            return value
    return ""


def _load_serpstack_secret_file() -> str:
    """Load the Serpstack key from a Render Secret File without logging it."""
    for path in SERPSTACK_SECRET_FILES:
        try:
            value = path.read_text(encoding="utf-8").strip()
        except (FileNotFoundError, OSError):
            continue
        if value:
            return value
    return ""


settings = Settings()
if not settings.gemini_api_key:
    secret_from_file = _load_gemini_secret_file()
    if secret_from_file:
        settings.gemini_api_key = secret_from_file

if not settings.serpstack_api_key:
    serpstack_secret = _load_serpstack_secret_file()
    if serpstack_secret:
        settings.serpstack_api_key = serpstack_secret

# The auth module historically reads RESEND_API_KEY from the environment.
# Bridge Render's mounted Secret File into that runtime environment without
# ever committing the credential to GitHub or exposing it to the frontend.
if not os.getenv("RESEND_API_KEY", "").strip():
    resend_secret = _load_resend_secret_file()
    if resend_secret:
        os.environ["RESEND_API_KEY"] = resend_secret
