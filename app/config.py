from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


GEMINI_SECRET_FILE = Path("/etc/secrets/GEMINI_API_KEY")


class Settings(BaseSettings):
    app_name: str = "AitherBackend"
    app_version: str = "2.7.1"
    environment: str = "development"
    cors_origins: str = "http://localhost:3000,http://localhost:5173,https://aitherforge.github.io"
    database_url: str = "sqlite:///./aither.db"
    # Keep users signed in across browser/app sessions for 30 days.
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


settings = Settings()
if not settings.gemini_api_key:
    secret_from_file = _load_gemini_secret_file()
    if secret_from_file:
        settings.gemini_api_key = secret_from_file
