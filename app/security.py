"""Autenticação, autorização, isolamento de tenant e cabeçalhos de segurança."""
from __future__ import annotations

from datetime import datetime, timezone
from functools import wraps

from flask import abort, current_app, g, redirect, request, session, url_for
from flask_login import LoginManager, current_user, logout_user

from .db import Session
from .models import User
from .services import settings

login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message = None


@login_manager.user_loader
def _load(uid):
    try:
        u = Session.get(User, int(uid))
    except (TypeError, ValueError):
        return None
    return u if u is not None and u.status == "active" else None


def client_ip() -> str:
    return (request.headers.get("X-Real-IP") or request.headers.get("X-Forwarded-For", "").split(",")[0]
            or request.remote_addr or "")[:64]


def init_security(app):
    login_manager.init_app(app)

    @app.before_request
    def _idle_timeout_and_mfa():
        if request.endpoint in (None, "static", "healthz"):
            return
        if current_user.is_authenticated:
            now = datetime.now(timezone.utc).timestamp()
            idle = int(settings.get("session_idle_minutes") or current_app.config["SESSION_IDLE_MINUTES"]) * 60
            last = session.get("last_seen", now)
            revoked = (settings.get("sessions_revoked") or {}).get(str(current_user.id))
            if revoked and session.get("login_at", 0) < revoked:  # sessões encerradas pelo administrador (CLI revoke-sessions)
                logout_user()
                session.clear()
                return redirect(url_for("auth.login", expired=1))
            if now - last > idle:
                logout_user()
                session.clear()
                return redirect(url_for("auth.login", expired=1))
            session["last_seen"] = now
            # MFA pendente: só pode acessar as telas de MFA/sair
            if session.get("mfa_pending") and not (request.endpoint or "").startswith("auth."):
                return redirect(url_for("auth.mfa"))

    @app.after_request
    def _headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; script-src 'self'; frame-ancestors 'none'; base-uri 'self'; "
            "form-action 'self'")
        if request.endpoint not in ("static",):
            resp.headers.setdefault("Cache-Control", "no-store")
        return resp


def admin_required(f):
    @wraps(f)
    def w(*a, **kw):
        if not current_user.is_authenticated:
            return login_manager.unauthorized()
        if current_user.role != "admin":
            abort(403)
        return f(*a, **kw)
    return w


def tenant_user_required(f):
    """Usuário de cliente (gestor ou leitor). Define g.tenant_id = tenant da sessão — único tenant acessível."""
    @wraps(f)
    def w(*a, **kw):
        if not current_user.is_authenticated:
            return login_manager.unauthorized()
        if current_user.role not in ("manager", "reader") or not current_user.tenant_id:
            abort(403)
        if current_user.tenant is None or current_user.tenant.status != "active":
            abort(403)
        g.tenant_id = current_user.tenant_id
        return f(*a, **kw)
    return w


def manager_required(f):
    @wraps(f)
    def w(*a, **kw):
        if current_user.role != "manager":
            abort(403)
        return f(*a, **kw)
    return tenant_user_required(w)


def scoped(query_obj, model, tenant_id: int):
    """Filtro obrigatório de tenant para qualquer consulta de dados de cliente."""
    return query_obj.where(model.tenant_id == tenant_id)
