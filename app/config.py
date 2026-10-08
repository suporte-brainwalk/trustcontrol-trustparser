"""Configuração lida do ambiente (.env fora do Git)."""
import os
from datetime import timedelta


def _bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    return default if v is None else v.strip().lower() in ("1", "true", "yes", "on", "sim")


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "")
    DATABASE_URL = os.environ.get("DATABASE_URL", "")
    APP_BASE_URL = os.getenv("APP_BASE_URL", "https://trustparser.trustcontrol.nuvem.tec.br").rstrip("/")
    TESTING = False

    # Sessão / cookies
    SESSION_COOKIE_NAME = "tparser_session"
    SESSION_COOKIE_SECURE = _bool("SESSION_COOKIE_SECURE", True)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=12)
    SESSION_IDLE_MINUTES = int(os.getenv("SESSION_IDLE_MINUTES", "30"))
    WTF_CSRF_TIME_LIMIT = None
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024
    UPLOAD_MAX_MB = int(os.getenv("UPLOAD_MAX_MB", "50"))

    # Magic link
    MAGIC_LINK_MINUTES = int(os.getenv("MAGIC_LINK_MINUTES", "15"))
    INVITE_HOURS = int(os.getenv("INVITE_HOURS", "24"))

    # E-mail
    SMTP_HOST = os.getenv("SMTP_HOST", "postfix-mail")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "25"))
    MAIL_FROM = os.getenv("MAIL_FROM", "trustparser@trustcontrol.nuvem.tec.br")
    MAIL_FROM_NAME = os.getenv("MAIL_FROM_NAME", "Trust Parser")
    TEST_MAILBOX = os.getenv("TEST_MAILBOX", "jarbas@trustcontrol.nuvem.tec.br")

    # IA (OpenRouter)
    OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
    AI_PRIMARY_MODEL = os.getenv("OPENROUTER_MODEL", "xiaomi/mimo-v2.6-pro")
    AI_FALLBACK_MODEL = os.getenv("AI_FALLBACK_MODEL", "")
    AI_TIMEOUT = int(os.getenv("AI_TIMEOUT", "300"))
    AI_ENABLED = _bool("AI_ENABLED", True)
    AI_BUDGET_USD = float(os.getenv("AI_BUDGET_USD", "10.0"))  # teto acumulado (defesa local, além do limite no OpenRouter)

    # Segredos de destinos/conectores (AES-256-GCM). 32 bytes em base64. Trocar invalida os segredos gravados.
    SECRETS_KEY = os.getenv("SECRETS_KEY", "")
    HTTP_USER_AGENT = os.getenv("HTTP_USER_AGENT", "TrustParser/1.0 (+https://trustparser.trustcontrol.nuvem.tec.br)")

    # Syslog (endereço público mostrado na tela para quem configura o equipamento)
    SYSLOG_PUBLIC_HOST = os.getenv("SYSLOG_PUBLIC_HOST", "trustparser.trustcontrol.nuvem.tec.br")
    SYSLOG_PUBLIC_IP = os.getenv("SYSLOG_PUBLIC_IP", "46.224.130.58")
    SYSLOG_TLS_PORT = int(os.getenv("SYSLOG_TLS_PORT", "6514"))
    SYSLOG_TCP_PORT = int(os.getenv("SYSLOG_TCP_PORT", "514"))
    SYSLOG_UDP_PORT = int(os.getenv("SYSLOG_UDP_PORT", "514"))

    # Worker
    SCHEDULER_ENABLED = _bool("SCHEDULER_ENABLED", True)
    TIMEZONE = os.getenv("TZ_APP", "America/Sao_Paulo")

    # API v1: pepper do HMAC das chaves (portal.env). Vazio = derivado do SECRET_KEY (trocar qualquer um invalida as chaves).
    API_KEY_PEPPER = os.getenv("API_KEY_PEPPER", "")

    RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_HEADERS_ENABLED = True


class TestConfig(Config):
    TESTING = True
    SESSION_COOKIE_SECURE = False
    WTF_CSRF_ENABLED = True
    SCHEDULER_ENABLED = False
    RATELIMIT_ENABLED = True
