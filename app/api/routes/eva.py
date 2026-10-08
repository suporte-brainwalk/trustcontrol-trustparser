"""EVA: situação, conversas e lista de autorizados (leitura e gestão de membros) + conversa (pedidos como por e-mail).

Mesmas regras do e-mail: só chave cujo responsável é dono ativo da lista gerencia; donos são geridos só na tela EVA do
Trust Parser; toda mudança na lista avisa os donos. O papel é conferido a cada chamada (saiu da lista, a chave para na hora).
"""
from __future__ import annotations

import threading
import time

from flask import Response, g
from limits import RateLimitItemPerHour
from sqlalchemy import select

from ...db import Session
from ...models import EvaAttachment, EvaMessage, EvaRequest, EvaThread, EvaWhitelist
from ...security import client_ip
from ...services import api_keys, eva_admin as svc, eva_chat as chat
from ..errors import ApiError
from ..pagination import page
from ..registry import Page, Written, actor_label, api_get, api_write
from ..schemas_eva import (EvaAttachmentOut as AttachmentOut, EvaConversationAccepted as ConversationAccepted,
                           EvaConversationCreate as ConversationCreate, EvaConversationDetail as ConversationDetail,
                           EvaMessageCreate as MessageCreate, EvaMessageOut as MessageOut, EvaMessagesQuery as MessagesQuery,
                           EvaRequestOut, EvaStatus, EvaThreadDetail, EvaThreadOut, EvaThreadQuery, EvaThreadUpdate as ThreadUpdate,
                           EvaWhitelistAdd as WhitelistAdd, EvaWhitelistEntry)

TAG = ["EVA"]


def require_whitelist(owner: bool = False) -> str:
    """Papel atual do responsável pela chave na lista de autorizados da EVA (conferido a cada chamada)."""
    role = api_keys.eva_role(g.api_key.owner_email)
    if role is None or (owner and role != "owner"):
        need = "dono ativo" if owner else "ativo"
        raise ApiError(403, f"O responsável por esta chave ({g.api_key.owner_email or 'não informado'}) precisa estar {need} na lista de autorizados da EVA.")
    return role


def request_out(r: EvaRequest) -> EvaRequestOut:
    return EvaRequestOut(id=r.id, channel="api" if (r.details or {}).get("channel") == "api" else "email", sender=r.sender,
                            subject=r.subject, received_at=r.received_at, status=r.status if r.status in ("queued", "processing", "done", "failed") else "failed",
                            intent=r.intent or "", summary=r.summary or "", commit=r.commit_sha or None, deployed=bool(r.deployed),
                            rolled_back=bool(r.rolled_back), finished_at=r.finished_at)


def thread_fields(t: EvaThread) -> dict:
    return dict(id=t.id, subject=t.subject, requester=t.requester, state=t.state, pending=[str(x) for x in (t.pending or [])],
                created_at=t.created_at, updated_at=t.updated_at, last_eva_at=t.last_eva_at)


def thread_detail(t: EvaThread) -> EvaThreadDetail:
    reqs = Session.execute(select(EvaRequest).where(EvaRequest.thread_id == t.id).order_by(EvaRequest.id)).scalars().all()
    return EvaThreadDetail(**thread_fields(t), requests=[request_out(r) for r in reqs])


@api_get("/eva/status", summary="Situação da EVA", response=EvaStatus, permission="eva:ler", tags=TAG)
def eva_status():
    """No ar ou não, modo (ativo/demo), fila e saúde dos acessos (IA, caixa de entrada e envio)."""
    return EvaStatus(**svc.status())


@api_get("/eva/threads", summary="Conversas com a EVA", response=EvaThreadOut, many=True, query=EvaThreadQuery,
         permission="eva:ler", tags=TAG)
def eva_threads(q: EvaThreadQuery):
    """Todas as conversas (e-mail e API), da mais recente para a mais antiga. Sem o conteúdo das mensagens."""
    stmt = select(EvaThread)
    if q.state:
        stmt = stmt.where(EvaThread.state == q.state)
    rows, nxt = page(Session, stmt, EvaThread.id, EvaThread.id, q.limit, q.cursor, desc=True)
    return Page([EvaThreadOut(**thread_fields(t)) for t in rows], nxt)


@api_get("/eva/threads/{thread_id}", summary="Detalhe de uma conversa", response=EvaThreadDetail, permission="eva:ler", tags=TAG)
def eva_thread(thread_id: int):
    """Situação, pendências e os pedidos da conversa (resumo, commit e publicação), sem o corpo dos e-mails nem anexos."""
    t = Session.get(EvaThread, thread_id)
    if t is None:
        raise ApiError(404, "Conversa não encontrada.")
    return thread_detail(t)


@api_get("/eva/whitelist", summary="Pessoas autorizadas a falar com a EVA", response=EvaWhitelistEntry, many=True, permission="eva:ler", tags=TAG)
def eva_whitelist():
    """Quem pode acionar a EVA (por e-mail e pela API). Lista completa."""
    rows = Session.execute(select(EvaWhitelist).order_by(EvaWhitelist.role.desc(), EvaWhitelist.email)).scalars().all()
    return Page([EvaWhitelistEntry(email=w.email, name=w.name, role=w.role, active=w.active, added_by=w.added_by, added_at=w.added_at)
                 for w in rows], None)


def _entry(email: str) -> EvaWhitelistEntry:
    w = Session.get(EvaWhitelist, email)
    return EvaWhitelistEntry(email=w.email, name=w.name, role=w.role, active=w.active, added_by=w.added_by, added_at=w.added_at)


@api_write("POST", "/eva/whitelist", summary="Incluir membro na lista de autorizados da EVA", permission="eva:gerenciar", body=WhitelistAdd,
           response=EvaWhitelistEntry, status=201, tags=TAG)
def eva_whitelist_add(body: WhitelistAdd):
    """Só chave de dono. Inclui (ou reativa) um **membro**; donos são geridos só na tela EVA. Os donos recebem um aviso por e-mail."""
    require_whitelist(owner=True)
    out = svc.whitelist_add(body.email, body.name, by=actor_label(g.api_key), ip=client_ip())
    e = out.obj.email
    return Written(out, build=lambda: _entry(e), location="/api/v1/eva/whitelist")


@api_write("DELETE", "/eva/whitelist/{email}", summary="Remover membro da lista de autorizados da EVA", permission="eva:gerenciar",
           status=204, tags=TAG, path_types={"email": "string"})
def eva_whitelist_remove(email: str):
    """Só chave de dono. Donos não podem ser removidos por aqui (só na tela EVA). Os donos recebem um aviso por e-mail."""
    require_whitelist(owner=True)
    return Written(svc.whitelist_remove(email, by=actor_label(g.api_key), ip=client_ip()))


@api_write("PATCH", "/eva/threads/{thread_id}", summary="Mudar a situação de uma conversa", permission="eva:gerenciar",
           body=ThreadUpdate, response=EvaThreadDetail, current=eva_thread, tags=TAG)
def eva_thread_update(body: ThreadUpdate, thread_id: int):
    """Encerrar (concluido), parar os lembretes (parado) ou reabrir (em_andamento). Só chave de dono."""
    require_whitelist(owner=True)
    t = Session.get(EvaThread, thread_id)
    if t is None:
        raise ApiError(404, "Conversa não encontrada.")
    return Written(svc.set_thread_state(t, body.state), build=lambda: eva_thread(thread_id))



# ------------------------------------------------------------------------------------------------ conversa (eva:conversar)
CHAT = ["EVA · conversa"]
_WAITERS = threading.BoundedSemaphore(2)
CHAT_MAX_BODY = 8 * 1024 * 1024  # 5 MB de imagens em base64 + texto  # long polling segura uma thread do servidor: no máximo 2 esperas ao mesmo tempo


def _me() -> tuple[str, str]:
    role = require_whitelist()
    return (g.api_key.owner_email or "").strip().lower(), role


def _conversation(thread_id: int) -> EvaThread:
    me, role = _me()
    t = Session.get(EvaThread, thread_id)
    if t is None or not chat.can_see(t, me, role):
        raise ApiError(404, "Conversa não encontrada.")
    return t


def _message_out(m: EvaMessage) -> MessageOut:
    out = m.direction == "out"
    return MessageOut(id=m.id, direction=m.direction, channel=m.channel, author=m.author, created_at=m.created_at, subject=m.subject,
                      text=m.body_text, html=m.body_html or None if out else None, status=m.status_key or None if out else None,
                      status_text=m.status_text or None if out else None, reply=(m.reply or None) if out else None, request_id=m.request_id,
                      attachments=[AttachmentOut(id=a.id, name=a.name, content_type=a.content_type, size=a.size,
                                                 url=f"/api/v1/eva/conversations/{m.thread_id}/attachments/{a.id}") for a in m.attachments])


def _messages(thread_id: int, after: int = 0) -> list[MessageOut]:
    rows = Session.execute(select(EvaMessage).where(EvaMessage.thread_id == thread_id, EvaMessage.id > after)
                           .order_by(EvaMessage.id)).scalars().all()
    return [_message_out(m) for m in rows]


def _message_limit():
    from ...web.limiter import limiter
    item = RateLimitItemPerHour(chat.MAX_MESSAGES_PER_HOUR)
    if not limiter.limiter.hit(item, "eva-msg", str(g.api_key.id)):
        stats = limiter.limiter.get_window_stats(item, "eva-msg", str(g.api_key.id))
        raise ApiError(429, f"Limite de {chat.MAX_MESSAGES_PER_HOUR} mensagens por hora à EVA desta chave excedido.",
                       {"Retry-After": str(max(1, int(stats.reset_time - time.time())))})


def _submit(body, thread: EvaThread | None):
    me, _ = _me()
    if not g.get("dry_run"):
        _message_limit()
    try:
        out = chat.submit(key=g.api_key, owner=me, text=body.message, subject=getattr(body, "subject", ""), thread=thread,
                          images=[i.model_dump() for i in body.images], cc=body.cc, email_copy=body.email_copy, ip=client_ip())
    except chat.ServiceError as e:
        if e.status == 429:
            raise ApiError(429, str(e), {"Retry-After": "60"}) from e
        raise
    t, req, msg = out.obj
    tid, rid, mid = t.id, req.id, msg.id

    def build():
        return ConversationAccepted(conversation_id=tid, request_id=rid, message_id=mid, queue_position=chat.queue_position(rid),
                                    poll=f"/api/v1/eva/conversations/{tid}/messages?after={mid}&wait=25")
    return Written(out, build=build, status=202, location=f"/api/v1/eva/conversations/{tid}")


@api_write("POST", "/eva/conversations", summary="Abrir conversa com a EVA", permission="eva:conversar", body=ConversationCreate,
           response=ConversationAccepted, status=202, tags=CHAT, max_body=CHAT_MAX_BODY)
def eva_conversation_create(body: ConversationCreate):
    """A mesma EVA do e-mail: suporte, dúvidas sobre as telas, consultas aos dados e manutenções, com as mesmas regras e
    proibições. Quem fala é o responsável pela chave (precisa estar ativo na lista de autorizados; dono tem direitos de dono).

    A resposta não é imediata (de segundos a vários minutos): o pedido entra na fila e a resposta aparece em
    `GET /eva/conversations/{id}/messages`. Limites: 3 pedidos na fila e 30 mensagens por hora por chave."""
    return _submit(body, None)


@api_write("POST", "/eva/conversations/{thread_id}/messages", summary="Continuar a conversa", permission="eva:conversar",
           body=MessageCreate, response=ConversationAccepted, status=202, tags=CHAT, max_body=CHAT_MAX_BODY)
def eva_conversation_reply(body: MessageCreate, thread_id: int):
    """Continua a conversa (inclusive uma aberta por e-mail), com a mesma sessão da EVA — como responder ao e-mail.
    Serve também para responder a uma confirmação pedida por ela (ex.: "pode aplicar?")."""
    return _submit(body, _conversation(thread_id))


@api_get("/eva/conversations", summary="Minhas conversas com a EVA", response=EvaThreadOut, many=True, query=EvaThreadQuery,
         permission="eva:conversar", tags=CHAT)
def eva_conversations(q: EvaThreadQuery):
    """Membros veem as conversas que abriram ou de que participaram (e-mail ou API); donos veem todas."""
    me, role = _me()
    stmt = chat.visible_threads(me, role)
    if q.state:
        stmt = stmt.where(EvaThread.state == q.state)
    rows, nxt = page(Session, stmt, EvaThread.id, EvaThread.id, q.limit, q.cursor, desc=True)
    return Page([EvaThreadOut(**thread_fields(t)) for t in rows], nxt)


@api_get("/eva/conversations/{thread_id}", summary="Conversa completa", response=ConversationDetail, permission="eva:conversar", tags=CHAT)
def eva_conversation(thread_id: int):
    """Situação, pendências, mensagens (das duas direções e dos dois canais) e o estado de cada pedido."""
    t = _conversation(thread_id)
    reqs = Session.execute(select(EvaRequest).where(EvaRequest.thread_id == t.id).order_by(EvaRequest.id)).scalars().all()
    return ConversationDetail(**thread_fields(t), messages=_messages(t.id), requests=[request_out(r) for r in reqs])


@api_get("/eva/conversations/{thread_id}/messages", summary="Mensagens novas (long polling)", response=MessageOut, many=True,
         query=MessagesQuery, permission="eva:conversar", tags=CHAT)
def eva_conversation_messages(q: MessagesQuery, thread_id: int):
    """Mensagens com id maior que `after`. Com `wait` (até 25 s), a conexão espera a resposta da EVA chegar.
    Sem novidade: `204` com `Retry-After` — chame de novo com o mesmo `after`."""
    t = _conversation(thread_id)
    msgs = _messages(t.id, q.after)
    if not msgs and q.wait and _WAITERS.acquire(blocking=False):
        try:
            deadline = time.monotonic() + q.wait
            while not msgs and time.monotonic() < deadline:
                time.sleep(1)
                Session.rollback()  # nova leitura do banco a cada volta
                msgs = _messages(t.id, q.after)
        finally:
            _WAITERS.release()
    if not msgs:
        return Response(status=204, headers={"Retry-After": "10"})
    return Page(msgs, None)


@api_get("/eva/conversations/{thread_id}/attachments/{attachment_id}", summary="Baixar imagem da conversa", permission="eva:conversar",
         tags=CHAT)
def eva_conversation_attachment(thread_id: int, attachment_id: int):
    """Imagem enviada na conversa ou tela anexada pela EVA na resposta (PNG, JPEG ou WebP)."""
    t = _conversation(thread_id)
    a = Session.get(EvaAttachment, attachment_id)
    if a is None or Session.get(EvaMessage, a.message_id).thread_id != t.id:
        raise ApiError(404, "Imagem não encontrada.")
    return Response(a.data, mimetype=a.content_type, headers={"Content-Disposition": f'inline; filename="{a.name}"',
                                                              "X-Content-Type-Options": "nosniff"})


@api_get("/eva/requests/{request_id}", summary="Estado de um pedido à EVA", response=EvaRequestOut, permission="eva:conversar",
         tags=CHAT)
def eva_request(request_id: int):
    """queued → processing → done (ou failed), com o commit e a publicação quando houve alteração do Trust Parser."""
    r = Session.get(EvaRequest, request_id)
    if r is None:
        raise ApiError(404, "Pedido não encontrado.")
    _conversation(r.thread_id)
    return request_out(r)
