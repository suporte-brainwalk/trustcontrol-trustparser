"""EVA no Trust Parser: situação, lista de pessoas autorizadas e situação das conversas — pela tela (admin) e pela API.

Regras:
- Tela EVA (administrador do Trust Parser): inclui pessoas como dono ou membro, muda o papel e remove (desativa), com
  trava anti-bloqueio: nunca fica sem nenhum dono ativo.
- API (chave de dono, eva:gerenciar) e e-mail (dono pedindo à EVA): só incluem/removem MEMBROS; donos são geridos só na tela.
- Toda mudança na lista avisa os donos por e-mail e fica na auditoria. O orquestrador lê a lista do banco a cada mensagem:
  a mudança vale na hora.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import func, select

from ..db import Session, utcnow
from ..models import EvaRequest, EvaThread, EvaWhitelist
from . import settings
from .changes import Conflict, Outcome, ServiceError, clean
from .people import norm_email

THREAD_STATES = ("em_andamento", "concluido", "parado")
ROLES = ("owner", "member")
MODES = ("demo", "ativo")
ONLINE_SECONDS = 300
MAILBOX = "eva-trustparser@trustcontrol.nuvem.tec.br"
# implantação: quem pode falar com a EVA no primeiro dia (depois, só pela tela EVA)
INITIAL = [("rogerio.crispim@brainwalk.com.br", "Rogério Crispim", "owner"),
           ("raphael.soares@trustcontrol.com.br", "Raphael Soares", "owner"),
           ("alberto.santos@trustcontrol.com.br", "Alberto Santos", "member")]


def heartbeat() -> dict:
    return settings.get("eva_heartbeat") or {}


def status() -> dict:
    hb = heartbeat()
    at = None
    if hb.get("at"):
        try:
            at = datetime.fromisoformat(hb["at"])
        except ValueError:
            at = None
    counts = dict(Session.execute(select(EvaRequest.status, func.count()).where(EvaRequest.status.in_(("queued", "processing")))
                                  .group_by(EvaRequest.status)).all())
    busy = Session.execute(select(EvaRequest.id).where(EvaRequest.status == "processing").order_by(EvaRequest.id)).scalars().first()
    return dict(online=bool(at and (utcnow() - at).total_seconds() <= ONLINE_SECONDS), last_signal_at=at, mode=mode(),
                queued=int(counts.get("queued", 0)), processing=int(counts.get("processing", 0)), processing_request=busy,
                ai_access_ok=hb.get("auth_ok"), email_in_ok=hb.get("imap_ok"), email_out_ok=hb.get("smtp_ok"))


def mode() -> str:
    return "ativo" if (settings.get("eva_mode") or "demo") == "ativo" else "demo"


def set_mode(value: str, *, by: str) -> Outcome:
    if value not in MODES:
        raise ServiceError("Modo inválido (demo ou ativo).")
    before = mode()
    settings.set_("eva_mode", value)
    return Outcome(message="EVA liberada para todas as pessoas autorizadas." if value == "ativo" else
                   "EVA em modo demonstração: só o Rogério é atendido.",
                   audit=[("eva.modo", value, {"de": before, "para": value, "por": by})] if before != value else [])


def owners() -> list[str]:
    return list(Session.execute(select(EvaWhitelist.email).where(EvaWhitelist.role == "owner", EvaWhitelist.active.is_(True))
                                .order_by(EvaWhitelist.email)).scalars())


def entries() -> list[EvaWhitelist]:
    return list(Session.execute(select(EvaWhitelist).order_by(EvaWhitelist.active.desc(), EvaWhitelist.role.desc(),
                                                              EvaWhitelist.email)).scalars())


def ensure_initial(by: str = "implantação") -> int:
    """Cria a lista inicial se ainda não houver ninguém (idempotente; chamado pela migração/CLI de implantação)."""
    if Session.execute(select(func.count()).select_from(EvaWhitelist)).scalar_one():
        return 0
    for e, n, r in INITIAL:
        Session.add(EvaWhitelist(email=e, name=n, role=r, active=True, added_by=by))
    Session.flush()
    return len(INITIAL)


def _notify_owners(action: str, email: str, by: str, ip: str, role: str = "member", extra: str = ""):
    """Aviso de segurança aos donos (respeita o redirecionamento de alertas operacionais)."""
    from . import emails
    to = list(dict.fromkeys(emails.redirect_alert(o) for o in owners()))
    if not to:
        return
    verbs = {"incluida": "incluído(a) na", "removida": "removido(a) da", "papel": "com papel alterado na"}
    verb = verbs.get(action, action)
    emails.send_system(to, f"[Trust Parser] {email} {verb} lista de autorizados da EVA", "email/eva_whitelist.html",
                       f"evawl:{uuid.uuid4().hex}", email=email, verb=verb, by=by, ip=ip, role=role, extra=extra,
                       base_url=emails.base_url(), mailbox=MAILBOX)


def _active_owner_count(exclude: str | None = None) -> int:
    q = select(func.count()).select_from(EvaWhitelist).where(EvaWhitelist.role == "owner", EvaWhitelist.active.is_(True))
    if exclude:
        q = q.where(EvaWhitelist.email != exclude)
    return Session.execute(q).scalar_one()


# ------------------------------------------------------------------------------------------------ tela (administrador)
def gui_add(email, name, role, *, by: str, ip: str = "") -> Outcome:
    e = norm_email(email)
    if not e:
        raise ServiceError("E-mail inválido.")
    if role not in ROLES:
        raise ServiceError("Papel inválido (dono ou membro).")
    if e == MAILBOX:
        raise ServiceError("A própria caixa da EVA não pode ser autorizada.")
    w = Session.get(EvaWhitelist, e)
    if w is not None and w.active:
        raise Conflict("Essa pessoa já está autorizada. Use “mudar papel” se for o caso.")
    if w is None:
        w = EvaWhitelist(email=e, name=clean(name), role=role, active=True, added_by=by[:254])
        Session.add(w)
    else:
        w.active, w.role, w.added_by, w.added_at = True, role, by[:254], utcnow()
        if clean(name):
            w.name = clean(name)
    Session.flush()
    return Outcome(message=f"{e} autorizado(a) a falar com a EVA como {'dono' if role == 'owner' else 'membro'}.", obj=w,
                   audit=[("eva.whitelist_incluida", e, {"por": by, "papel": role, "via": "tela"})],
                   after_commit=[lambda: _notify_owners("incluida", e, by, ip, role)])


def gui_set_role(email, role, *, by: str, ip: str = "") -> Outcome:
    e = norm_email(email) or ""
    if role not in ROLES:
        raise ServiceError("Papel inválido (dono ou membro).")
    w = Session.get(EvaWhitelist, e)
    if w is None or not w.active:
        raise ServiceError("Essa pessoa não está na lista.", 404)
    if w.role == role:
        raise Conflict("A pessoa já tem esse papel.")
    if w.role == "owner" and role != "owner" and _active_owner_count(exclude=e) == 0:
        raise Conflict("Não é possível rebaixar o último dono: a lista ficaria sem ninguém para administrá-la.")
    before, w.role = w.role, role
    Session.flush()
    return Outcome(message=f"{e} agora é {'dono' if role == 'owner' else 'membro'} da lista da EVA.", obj=w,
                   audit=[("eva.whitelist_papel", e, {"por": by, "de": before, "para": role, "via": "tela"})],
                   after_commit=[lambda: _notify_owners("papel", e, by, ip, role)])


def gui_remove(email, *, by: str, ip: str = "") -> Outcome:
    e = norm_email(email) or ""
    w = Session.get(EvaWhitelist, e)
    if w is None or not w.active:
        raise ServiceError("Essa pessoa não está na lista.", 404)
    if w.role == "owner" and _active_owner_count(exclude=e) == 0:
        raise Conflict("Não é possível remover o último dono: a lista ficaria sem ninguém para administrá-la.")
    w.active = False
    Session.flush()
    return Outcome(message=f"{e} não pode mais falar com a EVA.",
                   audit=[("eva.whitelist_removida", e, {"por": by, "papel": w.role, "via": "tela"})],
                   after_commit=[lambda: _notify_owners("removida", e, by, ip, w.role)])


# ------------------------------------------------------------------------------------------------ API (chave de dono)
def whitelist_add(email, name, *, by: str, ip: str = "") -> Outcome:
    e = norm_email(email)
    if not e:
        raise ServiceError("E-mail inválido.")
    w = Session.get(EvaWhitelist, e)
    if w is not None and w.role == "owner":
        raise Conflict("Donos da lista não são alterados pela API (só pela tela EVA do Trust Parser).")
    if w is not None and w.active:
        raise Conflict("Essa pessoa já está autorizada.")
    if e == MAILBOX:
        raise ServiceError("A própria caixa da EVA não pode ser autorizada.")
    if w is None:
        w = EvaWhitelist(email=e, name=clean(name), role="member", active=True, added_by=by[:254])
        Session.add(w)
    else:
        w.active, w.added_by = True, by[:254]
        if clean(name):
            w.name = clean(name)
    Session.flush()
    return Outcome(message=f"{e} incluído(a) na lista de autorizados da EVA.", obj=w,
                   audit=[("eva.whitelist_incluida", e, {"por": by, "via": "api"})],
                   after_commit=[lambda: _notify_owners("incluida", e, by, ip, "member", "via API")])


def whitelist_remove(email, *, by: str, ip: str = "") -> Outcome:
    e = norm_email(email) or ""
    w = Session.get(EvaWhitelist, e)
    if w is None or not w.active:
        raise ServiceError("Essa pessoa não está na lista.", 404)
    if w.role == "owner":
        raise Conflict("Donos da lista não podem ser removidos pela API (só pela tela EVA do Trust Parser).")
    w.active = False
    Session.flush()
    return Outcome(message=f"{e} removido(a) da lista de autorizados da EVA.", audit=[("eva.whitelist_removida", e, {"por": by, "via": "api"})],
                   after_commit=[lambda: _notify_owners("removida", e, by, ip, "member", "via API")])


def set_thread_state(th: EvaThread, state: str) -> Outcome:
    if state not in THREAD_STATES:
        raise ServiceError("Situação inválida (use em_andamento, concluido ou parado).")
    before = th.state
    th.state = state
    if state != "em_andamento":
        th.pending = [] if state == "concluido" else th.pending
    Session.flush()
    return Outcome(message="Situação da conversa atualizada.", obj=th,
                   audit=[("eva.conversa_situacao", th.subject[:200], {"conversa": th.id, "de": before, "para": state})])
