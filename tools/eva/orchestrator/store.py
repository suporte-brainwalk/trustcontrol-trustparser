"""Persistência no banco do Trust Parser (tabelas eva_*, settings e audit_log) — SQLAlchemy Core, transações curtas."""
from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import datetime, timezone

from sqlalchemy import MetaData, Table, create_engine, func, select, text
from sqlalchemy.exc import NoSuchTableError

from . import config

ACTOR = "EVA (agente por e-mail)"

_engine = None
_md = MetaData()
T: dict[str, Table] = {}


def utcnow():
    return datetime.now(timezone.utc)


def init(url: str | None = None):
    global _engine
    _engine = create_engine(url or config.DATABASE_URL, pool_pre_ping=True, pool_size=4, max_overflow=4, future=True)
    for name in ("eva_whitelist", "eva_threads", "eva_requests", "settings", "audit_log"):
        T[name] = Table(name, _md, autoload_with=_engine)
    for name in ("eva_messages", "eva_attachments"):  # conversa gravada (e-mail e API); ausentes antes da migração
        try:
            T[name] = Table(name, _md, autoload_with=_engine)
        except NoSuchTableError:
            pass
    return _engine


def engine():
    return _engine


@contextmanager
def tx():
    with _engine.begin() as c:
        yield c


# ---------------- settings / auditoria
def get_setting(key, default=None):
    with tx() as c:
        v = c.execute(select(T["settings"].c.value).where(T["settings"].c.key == key)).scalar()
    return (v or {}).get("v", default) if v is not None else default


def set_setting(key, value):
    with tx() as c:
        c.execute(text("""insert into settings (key, value, updated_at) values (:k, CAST(:v AS jsonb), now())
                          on conflict (key) do update set value = excluded.value, updated_at = now()"""),
                  {"k": key, "v": json.dumps({"v": value})})


def audit(action: str, target: str, details: dict | None = None):
    with tx() as c:
        c.execute(T["audit_log"].insert().values(at=utcnow(), actor_label=ACTOR, action=action,
                                                 target=target[:2000], details=details or {}, ip=""))


# ---------------- whitelist
def whitelist() -> dict[str, dict]:
    w = T["eva_whitelist"]
    with tx() as c:
        return {r.email: dict(r._mapping) for r in c.execute(select(w))}


def whitelist_add(email: str, name: str, added_by: str):
    w = T["eva_whitelist"]
    with tx() as c:
        c.execute(text("""insert into eva_whitelist (email, name, role, active, added_by, added_at) values (:e, :n, 'member', true, :b, now())
                          on conflict (email) do update set active = true, name = coalesce(nullif(:n, ''), eva_whitelist.name), added_by = :b"""),
                  {"e": email, "n": name[:160], "b": added_by})
    audit("eva.whitelist_incluida", email, {"por": added_by})


def whitelist_remove(email: str, removed_by: str):
    w = T["eva_whitelist"]
    with tx() as c:
        c.execute(w.update().where(w.c.email == email, w.c.role == "member").values(active=False))
    audit("eva.whitelist_removida", email, {"por": removed_by})


# ---------------- conversas e solicitações
def find_thread(ids: list[str]):
    if not ids:
        return None
    with tx() as c:
        return c.execute(text("select * from eva_threads where message_ids ?| :ids order by id desc limit 1"),
                         {"ids": list(ids)}).mappings().first()


def create_thread(subject: str, requester: str, message_id: str) -> int:
    t = T["eva_threads"]
    with tx() as c:
        return c.execute(t.insert().values(subject=subject, requester=requester, state="em_andamento", message_ids=[message_id],
                                           pending=[], reminders_sent=0, created_at=utcnow(), updated_at=utcnow()).returning(t.c.id)).scalar_one()


def thread(tid: int):
    t = T["eva_threads"]
    with tx() as c:
        return c.execute(select(t).where(t.c.id == tid)).mappings().first()


def update_thread(tid: int, **values):
    t = T["eva_threads"]
    values["updated_at"] = utcnow()
    with tx() as c:
        c.execute(t.update().where(t.c.id == tid).values(**values))


def add_thread_message_ids(tid: int, ids: list[str]):
    with tx() as c:
        c.execute(text("""update eva_threads set message_ids = (select jsonb_agg(distinct x) from jsonb_array_elements_text(message_ids || CAST(:ids AS jsonb)) x),
                          updated_at = now() where id = :t"""), {"ids": json.dumps([i for i in ids if i]), "t": tid})


def request_exists(message_id: str) -> bool:
    r = T["eva_requests"]
    with tx() as c:
        return c.execute(select(func.count()).select_from(r).where(r.c.message_id == message_id)).scalar_one() > 0


def create_request(thread_id: int, message_id: str, sender: str, subject: str, details: dict) -> int:
    r = T["eva_requests"]
    with tx() as c:
        return c.execute(r.insert().values(thread_id=thread_id, message_id=message_id, sender=sender, subject=subject, received_at=utcnow(),
                                           status="queued", details=details).returning(r.c.id)).scalar_one()


def next_queued():
    r = T["eva_requests"]
    with tx() as c:
        row = c.execute(select(r).where(r.c.status == "queued").order_by(r.c.id).limit(1).with_for_update(skip_locked=True)).mappings().first()
        if row:
            c.execute(r.update().where(r.c.id == row["id"]).values(status="processing"))
        return row


def update_request(rid: int, **values):
    r = T["eva_requests"]
    with tx() as c:
        c.execute(r.update().where(r.c.id == rid).values(**values))


def request(rid: int):
    r = T["eva_requests"]
    with tx() as c:
        return c.execute(select(r).where(r.c.id == rid)).mappings().first()


def recent_changes(limit: int = 15) -> list[dict]:
    """Mudanças publicadas (e ainda não desfeitas) que podem ser desfeitas."""
    r = T["eva_requests"]
    with tx() as c:
        rows = c.execute(select(r).where(r.c.deployed.is_(True), r.c.rolled_back.is_(False), r.c.reverted_by.is_(None),
                                         ((r.c.commit_sha != "") & (r.c.intent == "alteracao")) | (r.c.intent == "manutencao"))
                         .order_by(r.c.id.desc()).limit(limit)).mappings().all()
    return [dict(x) for x in rows]


def requeue_stuck():
    """Após reinício: solicitações que estavam em execução voltam para a fila."""
    r = T["eva_requests"]
    with tx() as c:
        return c.execute(r.update().where(r.c.status == "processing").values(status="queued")).rowcount


def threads_waiting():
    t = T["eva_threads"]
    with tx() as c:
        return c.execute(select(t).where(t.c.state.in_(["aguardando_trust", "aguardando_rogerio"]))).mappings().all()


def queue_stats():
    r = T["eva_requests"]
    with tx() as c:
        rows = c.execute(select(r.c.status, func.count(), func.min(r.c.received_at)).where(r.c.status.in_(["queued", "processing"]))
                         .group_by(r.c.status)).all()
    return {s: {"n": n, "oldest": o} for s, n, o in rows}


def try_lock(key: int = 90311):
    """Advisory lock de sessão: garante um único orquestrador."""
    conn = _engine.connect()
    ok = conn.execute(text("select pg_try_advisory_lock(:k)"), {"k": key}).scalar()
    conn.commit()
    if not ok:
        conn.close()
        return None
    return conn



# ---------------- mensagens da conversa (e-mail e API)
def add_message(thread_id: int, request_id: int | None, direction: str, channel: str, author: str, subject: str, text_body: str, *,
                html: str = "", reply: dict | None = None, status_key: str = "", status_text: str = "", emailed: bool = False,
                attachments=()) -> int | None:
    if "eva_messages" not in T:
        return None
    m, a = T["eva_messages"], T.get("eva_attachments")
    with tx() as c:
        mid = c.execute(m.insert().values(thread_id=thread_id, request_id=request_id, direction=direction, channel=channel, author=author[:254],
                                          subject=(subject or "")[:1000], body_text=text_body or "", body_html=html or "", reply=reply or {},
                                          status_key=(status_key or "")[:20], status_text=(status_text or "")[:300], emailed=emailed,
                                          created_at=utcnow()).returning(m.c.id)).scalar_one()
        for name, ctype, data in attachments or ():
            if a is not None and data:
                c.execute(a.insert().values(message_id=mid, name=name[:200], content_type=ctype[:60], size=len(data), data=data, created_at=utcnow()))
    return mid


def api_message(request_id: int):
    """Mensagem de entrada (canal API) de um pedido, com as imagens."""
    m, a = T["eva_messages"], T["eva_attachments"]
    with tx() as c:
        row = c.execute(select(m).where(m.c.request_id == request_id, m.c.direction == "in").order_by(m.c.id).limit(1)).mappings().first()
        atts = c.execute(select(a.c.name, a.c.content_type, a.c.data).where(a.c.message_id == row["id"]).order_by(a.c.id)).all() if row else []
    return row, [(x.name, x.content_type, bytes(x.data)) for x in atts]


def last_request(thread_id: int):
    r = T["eva_requests"]
    with tx() as c:
        return c.execute(select(r).where(r.c.thread_id == thread_id).order_by(r.c.id.desc()).limit(1)).mappings().first()
