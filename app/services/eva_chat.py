"""Conversa com a EVA pela API: a mesma EVA do e-mail, outro canal.

O Trust Parser só grava o pedido na mesma fila do e-mail (eva_requests, com channel=api) e a mensagem em eva_messages;
o orquestrador processa na ordem de chegada, com as mesmas regras, proibições e volta automática, e grava a resposta em
eva_messages (e manda o e-mail de sempre quando há destinatários). A EVA continua sem acesso de rede ao Trust Parser.
"""
from __future__ import annotations

import base64
import binascii
import uuid

from sqlalchemy import exists, func, or_, select

from ..db import Session, utcnow
from ..models import EvaAttachment, EvaMessage, EvaRequest, EvaThread, EvaWhitelist
from . import settings
from .changes import Outcome, ServiceError, clean
from .people import norm_email

ROGERIO = "rogerio.crispim@brainwalk.com.br"
MAX_TEXT = 20000
MAX_IMAGES = 4
MAX_IMAGE_BYTES = 5 * 1024 * 1024  # total por mensagem
MAX_CC = 10
MAX_PENDING_PER_KEY = 3
MAX_MESSAGES_PER_HOUR = 30
IMAGE_TYPES = {"image/png": (b"\x89PNG", ".png"), "image/jpeg": (b"\xff\xd8\xff", ".jpg"), "image/webp": (b"RIFF", ".webp")}
MSG_DOMAIN = "trustparser.trustcontrol.nuvem.tec.br"


def whitelist_entry(email: str) -> EvaWhitelist | None:
    w = Session.get(EvaWhitelist, (email or "").strip().lower())
    return w if w is not None and w.active else None


def visible_threads(email: str, role: str):
    """Donos veem todas as conversas (como na tela); membros, as que abriram ou de que participaram."""
    q = select(EvaThread)
    if role != "owner":
        q = q.where(or_(EvaThread.requester == email,
                        exists().where(EvaRequest.thread_id == EvaThread.id, EvaRequest.sender == email)))
    return q


def can_see(t: EvaThread, email: str, role: str) -> bool:
    if role == "owner" or t.requester == email:
        return True
    return Session.execute(select(EvaRequest.id).where(EvaRequest.thread_id == t.id, EvaRequest.sender == email).limit(1)).first() is not None


def pending_for_key(key_id: int) -> int:
    return Session.execute(select(func.count()).select_from(EvaRequest).where(
        EvaRequest.status.in_(("queued", "processing")), EvaRequest.details["key_id"].astext == str(key_id))).scalar_one()


def _images(images) -> list[tuple[str, str, bytes]]:
    if len(images or []) > MAX_IMAGES:
        raise ServiceError(f"Envie no máximo {MAX_IMAGES} imagens por mensagem.")
    out, total = [], 0
    for n, img in enumerate(images or [], 1):
        ctype = (img.get("content_type") or "").lower()
        if ctype not in IMAGE_TYPES:
            raise ServiceError(f"Imagem {n}: formato não aceito (use PNG, JPEG ou WebP).")
        try:
            data = base64.b64decode(img.get("data") or "", validate=True)
        except (binascii.Error, ValueError) as e:
            raise ServiceError(f"Imagem {n}: conteúdo base64 inválido.") from e
        magic, ext = IMAGE_TYPES[ctype]
        if not data.startswith(magic) or (ctype == "image/webp" and data[8:12] != b"WEBP"):
            raise ServiceError(f"Imagem {n}: o conteúdo não é um {ctype.split('/')[1].upper()} válido.")
        total += len(data)
        if total > MAX_IMAGE_BYTES:
            raise ServiceError("As imagens somam mais de 5 MB.")
        name = clean(img.get("name"), 120) or f"imagem-{n}{ext}"
        out.append((name, ctype, data))
    return out


def _cc(values, owner: str) -> list[str]:
    if len(values or []) > MAX_CC:
        raise ServiceError(f"No máximo {MAX_CC} pessoas em cópia.")
    out = []
    for v in values or []:
        e = norm_email(v)
        if not e:
            raise ServiceError(f"E-mail em cópia inválido: {v}")
        if e != owner and e not in out:
            out.append(e)
    return out


def submit(*, key, owner: str, text: str, subject: str = "", thread: EvaThread | None = None, images=(), cc=(),
           email_copy: bool = True, ip: str = "") -> Outcome:
    """Coloca a mensagem na fila da EVA. Valida as mesmas condições do e-mail (lista de autorizados, modo) e os limites da API."""
    w = whitelist_entry(owner)
    if w is None:
        raise ServiceError(f"{owner or 'O responsável pela chave'} não está ativo na lista de autorizados da EVA.", 403)
    if (settings.get("eva_mode") or "demo") != "ativo" and owner != ROGERIO:
        raise ServiceError("A EVA está em modo demonstração: só o Rogério é atendido no momento (vale para e-mail e API).", 403)
    text = (text or "").strip()
    if not text:
        raise ServiceError("Escreva a mensagem.")
    if len(text) > MAX_TEXT:
        raise ServiceError(f"A mensagem passa de {MAX_TEXT} caracteres.")
    imgs, cc = _images(images), _cc(cc, owner)
    if pending_for_key(key.id) >= MAX_PENDING_PER_KEY:
        raise ServiceError(f"Esta chave já tem {MAX_PENDING_PER_KEY} pedidos na fila da EVA. Aguarde a resposta de um deles.", 429)
    mid = f"<api-{uuid.uuid4().hex}@{MSG_DOMAIN}>"
    if thread is None:
        subject = clean(subject, 300)
        if not subject:
            raise ServiceError("Informe o assunto da conversa.")
        thread = EvaThread(subject=subject, requester=owner, state="em_andamento", message_ids=[mid], pending=[], reminders_sent=0)
        Session.add(thread)
        Session.flush()
        previous: list[str] = []
    else:
        previous = [m for m in (thread.message_ids or []) if m]
        subject = clean(subject, 300) or ("Re: " + thread.subject)[:300]
        thread.message_ids = list(dict.fromkeys(previous + [mid]))
        thread.state, thread.reminders_sent, thread.updated_at = "em_andamento", 0, utcnow()
    req = EvaRequest(thread_id=thread.id, message_id=mid, sender=owner, subject=subject, status="queued",
                        details={"channel": "api", "key_id": key.id, "chave": f"tpk_live_{key.prefix}…", "email_copy": bool(email_copy),
                                 "cc": cc, "nome": w.name or "", "ip": ip, "in_reply_to": previous[-1] if previous else "",
                                 "references": previous[-10:]})
    Session.add(req)
    Session.flush()
    msg = EvaMessage(thread_id=thread.id, request_id=req.id, direction="in", channel="api", author=owner, subject=subject, body_text=text)
    Session.add(msg)
    Session.flush()
    for name, ctype, data in imgs:
        Session.add(EvaAttachment(message_id=msg.id, name=name, content_type=ctype, size=len(data), data=data))
    Session.flush()
    return Outcome(message="Mensagem na fila da EVA.", obj=(thread, req, msg),
                   audit=[("eva.pedido_api", owner, {"pedido": req.id, "conversa": thread.id, "assunto": subject[:200],
                                                        "chave": f"tpk_live_{key.prefix}…", "imagens": len(imgs), "copia_email": bool(email_copy)})])


def queue_position(request_id: int) -> int:
    return Session.execute(select(func.count()).select_from(EvaRequest).where(
        EvaRequest.status.in_(("queued", "processing")), EvaRequest.id <= request_id)).scalar_one()
