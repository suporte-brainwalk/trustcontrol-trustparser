"""Magic link, TOTP, códigos de recuperação e regra anti-lockout."""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import timedelta

import pyotp
from sqlalchemy import func, select, text

from ..db import Session, utcnow
from ..models import MagicLink, User


class LockoutError(Exception):
    """Operação deixaria o portal sem administrador ativo."""


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_magic_link(user: User, purpose: str, minutes: int, ip: str = "", session=None) -> str:
    s = session or Session()
    token = secrets.token_urlsafe(32)
    s.add(MagicLink(user_id=user.id, token_hash=_hash(token), purpose=purpose,
                    expires_at=utcnow() + timedelta(minutes=minutes), ip=ip[:64]))
    s.flush()
    return token


def consume_magic_link(token: str, session=None) -> User | None:
    """Valida e consome (uso único, atômico). Retorna o usuário ou None."""
    if not token or len(token) > 100:
        return None
    s = session or Session()
    row = s.execute(select(MagicLink).where(MagicLink.token_hash == _hash(token)).with_for_update()).scalar_one_or_none()
    if row is None or row.used_at is not None or row.expires_at < utcnow():
        return None
    user = s.get(User, row.user_id)
    if user is None or user.status == "suspended":
        return None
    row.used_at = utcnow()
    # um link novo invalida os anteriores ainda não usados do mesmo usuário
    s.execute(text("update magic_links set used_at = now() where user_id = :u and used_at is null"), {"u": user.id})
    return user


# ---------------- TOTP ----------------
def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(user: User, secret: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="Trust Parser")


def verify_totp(secret: str | None, code: str) -> bool:
    if not secret or not code:
        return False
    code = "".join(ch for ch in code if ch.isdigit())
    return len(code) == 6 and pyotp.TOTP(secret).verify(code, valid_window=1)


def new_recovery_codes(n: int = 10) -> tuple[list[str], list[str]]:
    plain = [f"{secrets.token_hex(3)}-{secrets.token_hex(3)}" for _ in range(n)]
    return plain, [_hash(c) for c in plain]


def use_recovery_code(user: User, code: str) -> bool:
    h = _hash(code.strip().lower())
    for stored in list(user.recovery_codes or []):
        if hmac.compare_digest(stored, h):
            user.recovery_codes = [c for c in user.recovery_codes if c != stored]
            return True
    return False


# ---------------- Anti-lockout ----------------
def assert_not_last_admin(target: User, session=None):
    """Bloqueia remoção/suspensão/rebaixamento do último administrador ATIVO.
    Usa lock transacional para evitar corrida entre duas remoções simultâneas."""
    s = session or Session()
    s.execute(text("select pg_advisory_xact_lock(424242)"))
    if target.role != "admin" or target.status != "active":
        return
    active = s.execute(select(func.count()).select_from(User).where(User.role == "admin", User.status == "active",
                                                                  User.id != target.id)).scalar_one()
    if active < 1:
        raise LockoutError("Último administrador ativo — adicione e ative outro administrador antes.")
