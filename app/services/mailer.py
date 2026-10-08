"""Envio de e-mail via Postfix, com modo teste (redirecionamento) e registro em deliveries."""
from __future__ import annotations

import logging
import smtplib
import uuid
from datetime import timedelta
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid

from sqlalchemy import select

from ..db import Session, utcnow
from ..models import Delivery
from . import settings

log = logging.getLogger(__name__)
_CONF = {}


def configure(conf: dict):
    _CONF.update({k: conf[k] for k in ("SMTP_HOST", "SMTP_PORT", "MAIL_FROM", "MAIL_FROM_NAME", "TEST_MAILBOX")})


def effective_recipient(email: str, session=None) -> str:
    """Em modo teste, só a allowlist recebe de verdade; o resto vai para a caixa de testes."""
    email = email.strip().lower()
    if not settings.get("test_mode", session):
        return email
    allow = [a.lower() for a in (settings.get("test_allowlist", session) or [])]
    return email if email in allow else _CONF.get("TEST_MAILBOX", "jarbas@trustcontrol.nuvem.tec.br")


def build_message(to: str, subject: str, html: str, text: str, *, original_to: str | None = None,
                  inline: dict[str, tuple[bytes, str]] | None = None, headers: dict | None = None) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = formataddr((_CONF.get("MAIL_FROM_NAME", "Trust Parser"), _CONF.get("MAIL_FROM")))
    msg["To"] = to
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    domain = (_CONF.get("MAIL_FROM") or "trustcontrol.com.br").split("@")[-1]
    msg["Message-ID"] = make_msgid(idstring=uuid.uuid4().hex[:12], domain=domain)
    if original_to and original_to != to:
        msg["X-TrustParser-Original-To"] = original_to
    for k, v in (headers or {}).items():
        msg[k] = v
    msg.set_content(text or "Este e-mail requer um cliente com suporte a HTML.")
    msg.add_alternative(html, subtype="html")
    if inline:
        html_part = msg.get_payload()[1]
        for cid, (data, mime) in inline.items():
            maintype, subtype = mime.split("/", 1)
            html_part.add_related(data, maintype=maintype, subtype=subtype, cid=f"<{cid}>", filename=f"{cid}.{subtype}")
    return msg


def send_now(msg: EmailMessage) -> str:
    with smtplib.SMTP(_CONF.get("SMTP_HOST", "postfix-mail"), int(_CONF.get("SMTP_PORT", 25)), timeout=30) as s:
        s.ehlo("portal-app")
        refused = s.send_message(msg)
        if refused:
            raise smtplib.SMTPRecipientsRefused(refused)
    return "250 OK"


def queue(kind: str, dedupe_key: str, recipient: str, subject: str, *, ref_id=None, tenant_id=None, session=None) -> Delivery | None:
    """Cria o registro de entrega (idempotente pela dedupe_key). Retorna None se já existia."""
    s = session or Session()
    if s.execute(select(Delivery.id).where(Delivery.dedupe_key == dedupe_key)).first():
        return None
    d = Delivery(kind=kind, dedupe_key=dedupe_key[:200], recipient=recipient.lower(),
                 effective_recipient=effective_recipient(recipient, s), subject=subject, ref_id=ref_id,
                 tenant_id=tenant_id, status="pending")
    s.add(d)
    s.flush()
    return d


def deliver(d: Delivery, html: str, text: str, inline=None, session=None) -> bool:
    """Envia uma entrega pendente; registra resultado e agenda retentativa exponencial (máx. 5)."""
    d.attempts += 1
    try:
        msg = build_message(d.effective_recipient, d.subject, html, text, original_to=d.recipient, inline=inline)
        d.smtp_response = send_now(msg)
        d.message_id = msg["Message-ID"]
        d.status, d.sent_at, d.next_attempt_at = "sent", utcnow(), None
        return True
    except Exception as e:  # noqa: BLE001 — registra qualquer falha de SMTP
        log.warning("falha de envio delivery=%s: %s", d.id, e)
        d.smtp_response = str(e)[:500]
        if d.attempts >= 5:
            d.status = "failed"
        else:
            d.next_attempt_at = utcnow() + timedelta(minutes=2 ** d.attempts)
        return False
