"""Montagem e envio dos e-mails do portal (HTML com banner embutido)."""
from __future__ import annotations

import html as _html
import os
import re

from flask import current_app, render_template, url_for

from ..db import Session
from ..models import User
from . import mailer

BANNER_CID = "tplogo"


def _banner():
    path = os.path.join(current_app.static_folder, "brand", "trust-logo.png")
    with open(path, "rb") as f:
        return {BANNER_CID: (f.read(), "image/png")}


def html_to_text(h: str) -> str:
    t = re.sub(r"(?is)<(script|style).*?</\1>", "", h)
    t = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</tr>|</li>|</h\d>", "\n", t)
    t = re.sub(r"<[^>]+>", " ", t)
    t = _html.unescape(t)
    return re.sub(r"[ \t]+", " ", re.sub(r"\n\s*\n+", "\n\n", t)).strip()


def base_url() -> str:
    return current_app.config["APP_BASE_URL"]


def send_magic_link(user: User, token: str, purpose: str) -> bool:
    link = base_url() + url_for("auth.magic", token=token)
    minutes = current_app.config["MAGIC_LINK_MINUTES"] if purpose == "login" else current_app.config["INVITE_HOURS"] * 60
    subject = "Convite: acesso ao Trust Parser" if purpose == "invite" else "Seu acesso ao Trust Parser"
    body = render_template("email/magic_link.html", user=user, link=link, purpose=purpose, minutes=minutes)
    d = mailer.queue("auth", f"auth:{token[:24]}", user.email, subject, tenant_id=user.tenant_id)
    Session.flush()
    return mailer.deliver(d, body, html_to_text(body), inline=_banner())


def send_system(to_list: list[str], subject: str, template: str, dedupe: str, **ctx) -> int:
    body = render_template(template, **ctx)
    sent = 0
    for to in to_list:
        d = mailer.queue("system", f"{dedupe}:{to}", to, subject)
        if d is None:
            continue
        if mailer.deliver(d, body, html_to_text(body), inline=_banner()):
            sent += 1
    return sent


def redirect_alert(addr: str) -> str:
    """Destino efetivo de um alerta operacional (setting alert_redirects; ex.: Rogério -> caixa de suporte)."""
    from . import settings
    return ((settings.get("alert_redirects") or {}).get(addr.lower()) or addr).lower()


def admin_emails() -> list[str]:
    from sqlalchemy import select
    # contas técnicas de verificação automática não recebem avisos operacionais
    out = []
    for (e,) in Session.execute(select(User.email).where(User.role == "admin", User.status == "active")):
        if e.startswith("e2e."):
            continue
        dest = redirect_alert(e)
        if dest not in out:
            out.append(dest)
    return out
