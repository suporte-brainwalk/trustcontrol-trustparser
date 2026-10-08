"""Login por magic link (somente convite), MFA TOTP, conta e saída."""
from __future__ import annotations

import base64
import io

import qrcode
from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import select

from ..db import Session, utcnow
from ..models import MagicLink, User
from ..security import client_ip
from ..services import audit, auth as authsvc, emails, settings
from .limiter import limiter

bp = Blueprint("auth", __name__, url_prefix="/auth")


def _normalize_email(v: str) -> str:
    return (v or "").strip().lower()[:254]


def _login_email_key():
    return "login:" + _normalize_email(request.form.get("email", ""))


@bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute; 40 per hour", methods=["POST"])
@limiter.limit("3 per 10 minutes", methods=["POST"], key_func=_login_email_key)
def login():
    minutes = current_app.config["MAGIC_LINK_MINUTES"]
    if request.method == "GET":
        if current_user.is_authenticated and not session.get("mfa_pending"):
            return redirect(url_for("index"))
        return render_template("auth/login.html", minutes=minutes, expired=request.args.get("expired"))
    email = _normalize_email(request.form.get("email"))
    if "@" in email and "." in email.split("@")[-1]:
        user = Session.execute(select(User).where(User.email == email)).scalar_one_or_none()
        if user is not None and user.status in ("active", "invited") and (user.tenant is None or user.tenant.status == "active"):
            purpose = "login" if user.status == "active" else "invite"
            token = authsvc.create_magic_link(user, purpose, minutes if purpose == "login" else current_app.config["INVITE_HOURS"] * 60, client_ip())
            audit.log("auth.magic_link_requested", user.email, actor=user, tenant_id=user.tenant_id, ip=client_ip())
            Session.commit()
            emails.send_magic_link(user, token, purpose)
            Session.commit()
        else:
            audit.log("auth.login_unknown_or_blocked", email, actor_label=email, ip=client_ip())
            Session.commit()
    return render_template("auth/login.html", sent=True, email=email, minutes=minutes)


@bp.route("/l/<token>", methods=["GET", "POST"])
@limiter.limit("30 per minute")
def magic(token):
    from ..services.auth import _hash
    row = Session.execute(select(MagicLink).where(MagicLink.token_hash == _hash(token))).scalar_one_or_none() if len(token) <= 100 else None
    valid = row is not None and row.used_at is None and row.expires_at > utcnow()
    if request.method == "GET":
        return render_template("auth/link.html", valid=valid, token=token, purpose=row.purpose if row else "")
    user = authsvc.consume_magic_link(token)
    if user is None:
        Session.rollback()
        return render_template("auth/link.html", valid=False, token=""), 400
    was_invite = user.status == "invited"
    if was_invite:
        user.status = "active"
    user.last_login_at = utcnow()
    audit.log("auth.invite_accepted" if was_invite else "auth.login", user.email, actor=user, tenant_id=user.tenant_id, ip=client_ip())
    Session.commit()
    session.clear()
    login_user(user)
    session["last_seen"] = session["login_at"] = utcnow().timestamp()
    if user.totp_enabled:
        session["mfa_pending"] = True
        return redirect(url_for("auth.mfa"))
    if user.role == "admin" and settings.get("require_mfa_admin"):
        session["mfa_pending"] = True
        return redirect(url_for("auth.mfa_setup"))
    return redirect(url_for("index"))


@bp.route("/mfa", methods=["GET", "POST"])
@login_required
@limiter.limit("5 per minute; 20 per hour", methods=["POST"])
def mfa():
    if not session.get("mfa_pending"):
        return redirect(url_for("index"))
    if not current_user.totp_enabled:
        return redirect(url_for("auth.mfa_setup"))
    if request.method == "POST":
        code = (request.form.get("code") or "").strip()
        user = Session.get(User, current_user.id)
        ok = authsvc.verify_totp(user.totp_secret, code) or ("-" in code and authsvc.use_recovery_code(user, code))
        if ok:
            session.pop("mfa_pending", None)
            audit.log("auth.mfa_ok", user.email, actor=user, tenant_id=user.tenant_id, ip=client_ip())
            Session.commit()
            return redirect(url_for("index"))
        audit.log("auth.mfa_failed", user.email, actor=user, tenant_id=user.tenant_id, ip=client_ip())
        Session.commit()
        flash("Código inválido. Tente novamente.", "error")
    return render_template("auth/mfa.html")


def _qr_b64(uri: str) -> str:
    img = qrcode.make(uri, box_size=6, border=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


@bp.route("/mfa/setup", methods=["GET", "POST"])
@login_required
@limiter.limit("10 per minute", methods=["POST"])
def mfa_setup():
    user = Session.get(User, current_user.id)
    if user.totp_enabled and not session.get("mfa_pending"):
        return redirect(url_for("auth.account"))
    if user.totp_enabled and session.get("mfa_pending"):
        return redirect(url_for("auth.mfa"))
    required = user.role == "admin" and bool(settings.get("require_mfa_admin"))
    secret = session.get("totp_setup_secret") or authsvc.new_totp_secret()
    session["totp_setup_secret"] = secret
    if request.method == "POST":
        if authsvc.verify_totp(secret, request.form.get("code", "")):
            plain, hashes = authsvc.new_recovery_codes()
            user.totp_secret, user.totp_enabled, user.recovery_codes = secret, True, hashes
            session.pop("totp_setup_secret", None)
            session.pop("mfa_pending", None)
            audit.log("auth.mfa_enabled", user.email, actor=user, tenant_id=user.tenant_id, ip=client_ip())
            Session.commit()
            return render_template("auth/mfa_setup.html", codes=plain)
        flash("Código inválido. Confira o horário do celular e tente novamente.", "error")
    return render_template("auth/mfa_setup.html", qr=_qr_b64(authsvc.totp_uri(user, secret)), secret=secret, required=required)


@bp.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if session.get("mfa_pending"):
        return redirect(url_for("auth.mfa"))
    user = Session.get(User, current_user.id)
    if request.method == "POST":
        action = request.form.get("action")
        if action == "disable_mfa":
            if user.role == "admin" and settings.get("require_mfa_admin"):
                abort(403)
            if not authsvc.verify_totp(user.totp_secret, request.form.get("code", "")):
                flash("Código inválido.", "error")
            else:
                user.totp_enabled, user.totp_secret, user.recovery_codes = False, None, []
                audit.log("auth.mfa_disabled", user.email, actor=user, tenant_id=user.tenant_id, ip=client_ip())
                Session.commit()
                flash("Verificação em duas etapas desativada.")
        elif action == "regen_codes":
            if not authsvc.verify_totp(user.totp_secret, request.form.get("code", "")):
                flash("Código inválido.", "error")
            else:
                plain, hashes = authsvc.new_recovery_codes()
                user.recovery_codes = hashes
                audit.log("auth.recovery_codes_regenerated", user.email, actor=user, tenant_id=user.tenant_id, ip=client_ip())
                Session.commit()
                return render_template("auth/mfa_setup.html", codes=plain)
        return redirect(url_for("auth.account"))
    return render_template("account.html", nav="account", user=user,
                           mfa_required=user.role == "admin" and settings.get("require_mfa_admin"))


@bp.post("/logout")
def logout():
    if current_user.is_authenticated:
        audit.log("auth.logout", current_user.email, actor=current_user, tenant_id=current_user.tenant_id, ip=client_ip())
        Session.commit()
    logout_user()
    session.clear()
    return redirect(url_for("auth.login"))
