"""Montagem e envio das respostas da EVA (HTML leve + texto, capturas embutidas, Rogério sempre em cópia)."""
from __future__ import annotations

import html
import re
import smtplib
import threading
import uuid
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid

from . import config

STATUS_STYLE = {
    "publicado": ("#e8f4d4", "#3f7a1c", "✅"),
    "sem_mudanca": ("#eef3f8", "#1f4c81", "💬"),
    "nao_publicado": ("#fff4e5", "#9a5b00", "⚠️"),
    "desfeito": ("#e8f4d4", "#3f7a1c", "↩️"),
}


def _esc(t: str) -> str:
    """Escapa o texto da IA e converte apenas **negrito** (sem outro HTML)."""
    return re.sub(r"\*\*([^*\n]{1,200})\*\*", r"<b>\1</b>", html.escape(t or ""))


def _li(items):
    return "".join(f"<li style=\"margin:0 0 6px 0;\">{_esc(i)}</li>" for i in items if i)


# Conversa em andamento na thread atual (fila e lembretes rodam em threads separadas): cada resposta enviada é gravada
# em eva_messages. deliver=False (pedido da API sem cópia por e-mail): a resposta fica só na conversa, nenhum e-mail sai.
_TL = threading.local()


def capture(cap: dict | None):
    _TL.cap = cap


def current() -> dict | None:
    return getattr(_TL, "cap", None)


def render(reply: dict, *, status_key: str, status_text: str, shots: list[dict], version: str, original: dict | None) -> tuple[str, str, list]:
    """Retorna (html, texto, inline[(cid, bytes)]). Todo texto vindo da IA é escapado."""
    cap = current()
    if cap is not None:
        cap.update(reply=dict(reply), status_key=status_key, status_text=status_text)
    bg, fg, icon = STATUS_STYLE.get(status_key, STATUS_STYLE["sem_mudanca"])
    inline = []
    parts = [f'<p style="margin:0 0 14px 0;">{html.escape(reply.get("saudacao", "Olá!"))}</p>']
    parts += [f'<p style="margin:0 0 12px 0;">{_esc(p)}</p>' for p in reply.get("paragrafos", []) if p]
    parts.append(f'<div style="background:{bg};color:{fg};border-radius:8px;padding:10px 14px;margin:14px 0;font-weight:600;">{icon} {html.escape(status_text)}</div>')
    if reply.get("passo_a_passo"):
        rows = "".join(f'<tr><td valign="top" style="padding:8px 10px 8px 0;width:28px;"><div style="width:24px;height:24px;border-radius:12px;background:#7BBA37;color:#10200a;font-weight:700;font-size:12px;line-height:24px;text-align:center;">{n}</div></td>'
                       f'<td style="padding:8px 0;border-bottom:1px solid #eef2f5;">{_esc(step)}</td></tr>'
                       for n, step in enumerate([x for x in reply["passo_a_passo"] if x][:12], 1))
        parts.append(f'<div style="margin:16px 0;padding:12px 16px;background:#f7faf3;border:1px solid #dfeccd;border-radius:8px;">'
                     f'<p style="margin:0 0 6px 0;font-weight:700;">Passo a passo</p><table role="presentation" cellpadding="0" cellspacing="0" width="100%">{rows}</table></div>')
    if reply.get("o_que_fiz"):
        parts.append(f'<p style="margin:16px 0 6px 0;font-weight:700;">O que eu fiz</p><ul style="margin:0 0 0 18px;padding:0;">{_li(reply["o_que_fiz"])}</ul>')
    for i, s in enumerate(shots):
        blocks = []
        if s.get("tela_png"):
            cid = f"tela{i}-{uuid.uuid4().hex[:8]}"
            inline.append((cid, s["tela_png"]))
            blocks.append(f'<img src="cid:{cid}" width="600" style="max-width:100%;border:1px solid #d7e0ea;border-radius:6px;display:block;margin-top:6px;" alt="tela">')
        for label in ("antes", "depois"):
            if s.get(f"{label}_png"):
                cid = f"captura{i}{label}-{uuid.uuid4().hex[:8]}"
                inline.append((cid, s[f"{label}_png"]))
                blocks.append(f'<p style="margin:10px 0 4px 0;font-size:12px;color:#566573;font-weight:700;text-transform:uppercase;">{"Antes" if label == "antes" else "Depois"}</p>'
                              f'<img src="cid:{cid}" width="600" style="max-width:100%;border:1px solid #d7e0ea;border-radius:6px;display:block;" alt="{label}">')
        if blocks:
            parts.append(f'<div style="margin:16px 0;"><p style="margin:0;font-weight:700;">{html.escape(s.get("legenda", "Tela"))}</p>{"".join(blocks)}</div>')
    steps = [("Próximos passos · time Trust Control", reply.get("proximos_passos_trust")),
             ("Próximos passos · Rogério / Brainwalk", reply.get("proximos_passos_rogerio")),
             ("O que eu faço em seguida", reply.get("proximos_passos_eva"))]
    for title, items in steps:
        if items:
            parts.append(f'<p style="margin:16px 0 6px 0;font-weight:700;">{html.escape(title)}</p><ul style="margin:0 0 0 18px;padding:0;">{_li(items)}</ul>')
    import re as _re
    reply["fechamento"] = _re.sub(r"(?is)\s*((um|grande)\s+)?(abra[cç]os?|abs|att|atenciosamente)[,!.]?\s*(eva)?[.!]?\s*$", "", reply.get("fechamento", "") or "").strip()
    if reply.get("fechamento"):
        parts.append(f'<p style="margin:18px 0 0 0;">{_esc(reply["fechamento"])}</p>')
    parts.append('<p style="margin:14px 0 0 0;">Abraço,<br><b>EVA</b><br><span style="color:#566573;font-size:12px;">Suporte e Manutenção por IA · Trust Parser</span></p>')
    quoted = ""
    if original:
        quoted = (f'<div style="margin-top:22px;padding-top:12px;border-top:1px solid #e3e8ee;color:#566573;font-size:12px;">'
                  f'<p style="margin:0 0 6px 0;">Pedido original de {html.escape(original["de"])}:</p>'
                  f'<blockquote style="margin:0;padding-left:10px;border-left:3px solid #d7e0ea;white-space:pre-wrap;">{html.escape(original["texto"][:3000])}</blockquote></div>')
    footer = f'<p style="margin:16px 0 0 0;color:#98a4b3;font-size:11px;">Versão {html.escape(version)}</p>' if version else ""
    body = ('<!doctype html><html lang="pt-BR"><body style="margin:0;background:#f4f6f8;">'
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:18px 10px;">'
            '<table role="presentation" width="640" cellpadding="0" cellspacing="0" style="max-width:640px;background:#ffffff;border-radius:10px;border-top:4px solid #7BBA37;">'
            '<tr><td style="padding:22px 24px;font-family:Roboto,Arial,sans-serif;font-size:14px;line-height:1.6;color:#1f2d3d;">'
            + "".join(parts) + quoted + footer + "</td></tr></table></td></tr></table></body></html>")
    text_lines = [reply.get("saudacao", "Olá!"), ""] + reply.get("paragrafos", []) + ["", f"{icon} {status_text}", ""]
    if reply.get("passo_a_passo"):
        text_lines += ["Passo a passo:"] + [f"{n}. {x}" for n, x in enumerate([x for x in reply["passo_a_passo"] if x][:12], 1)] + [""]
    if reply.get("o_que_fiz"):
        text_lines += ["O que eu fiz:"] + [f"- {i}" for i in reply["o_que_fiz"]] + [""]
    for title, items in steps:
        if items:
            text_lines += [f"{title}:"] + [f"- {i}" for i in items] + [""]
    text_lines += [reply.get("fechamento", ""), "", "Abraço,", config.SIGNATURE]
    if version:
        text_lines.append(f"Versão {version}")
    return body, re.sub(r"\*\*([^*\n]{1,200})\*\*", r"\1", "\n".join(text_lines)), inline


def build(*, to: list[str], cc: list[str], subject: str, html_body: str, text_body: str, inline: list, in_reply_to: str | None,
          references: list[str], request_id: int | None) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = formataddr((config.FROM_NAME, config.MAILBOX))
    if config.OUTBOUND_REDIRECT:
        msg["X-Eva-Original-To"] = ", ".join(to)
        msg["X-Eva-Original-Cc"] = ", ".join(cc)
        to, cc = [config.OUTBOUND_REDIRECT], []
    msg["To"] = ", ".join(to)
    if cc:
        msg["Cc"] = ", ".join(cc)
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(idstring=uuid.uuid4().hex[:12], domain=config.MAILBOX.split("@")[1])
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
        msg["References"] = " ".join(list(dict.fromkeys([*references, in_reply_to]))[-20:])
    msg["Auto-Submitted"] = "auto-replied"
    msg["X-Eva"] = f"solicitacao-{request_id}" if request_id else "eva"
    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype="html")
    if inline:
        html_part = msg.get_payload()[1]
        for cid, data in inline:
            html_part.add_related(data, maintype="image", subtype="png", cid=f"<{cid}>", filename=f"{cid}.png")
    return msg


def _parts(msg: EmailMessage) -> tuple[str, str, list]:
    text_body, html_body, images = "", "", []
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype == "text/plain" and not text_body:
            text_body = part.get_content()
        elif ctype == "text/html" and not html_body:
            html_body = part.get_content()
        elif ctype.startswith("image/"):
            images.append((part.get_filename() or "tela.png", ctype, part.get_payload(decode=True) or b""))
    return text_body, html_body, images


def record(msg: EmailMessage, emailed: bool):
    """Grava a resposta na conversa (dos dois canais), com a versão estruturada capturada no render."""
    cap = current()
    if cap is None or not cap.get("thread_id"):
        return
    from . import store
    text_body, html_body, images = _parts(msg)
    try:
        store.add_message(cap["thread_id"], cap.get("request_id"), "out", cap.get("channel", "email"), "eva", str(msg["Subject"] or ""),
                          text_body, html=html_body, reply=cap.get("reply") or {}, status_key=cap.get("status_key", ""),
                          status_text=cap.get("status_text", ""), emailed=emailed, attachments=images)
    except Exception:  # noqa: BLE001 — gravar a conversa nunca impede a resposta
        import logging
        logging.getLogger("eva.outbox").exception("não consegui gravar a resposta na conversa")
        if not emailed:
            raise


def send(msg: EmailMessage) -> str:
    cap = current()
    if cap is not None and cap.get("deliver") is False:
        record(msg, emailed=False)
        return msg["Message-ID"]
    mid = smtp_send(msg)
    record(msg, emailed=True)
    return mid


def smtp_send(msg: EmailMessage) -> str:
    with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=60) as s:
        s.ehlo("eva-orchestrator")
        refused = s.send_message(msg)
        if refused:
            raise smtplib.SMTPRecipientsRefused(refused)
    return msg["Message-ID"]


def smtp_ok() -> bool:
    try:
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=15) as s:
            return s.noop()[0] == 250
    except Exception:  # noqa: BLE001
        return False
