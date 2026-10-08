"""Tenants (clientes da Trust). Regras únicas para a tela e a API."""
from __future__ import annotations

from sqlalchemy import func, select

from ..db import Session
from ..models import Tenant
from .changes import Conflict, Outcome, ServiceError, clean, diff


def _taken(name: str, exclude_id=None) -> bool:
    q = select(Tenant.id).where(func.lower(Tenant.name) == name.lower())
    if exclude_id:
        q = q.where(Tenant.id != exclude_id)
    return Session.execute(q).first() is not None


def get_tenant(tid: int) -> Tenant:
    t = Session.get(Tenant, tid)
    if t is None:
        raise ServiceError("Tenant não encontrado.", 404)
    return t


def create_tenant(*, name, segment="", internal=False) -> Outcome:
    name = clean(name)
    if not name:
        raise ServiceError("Informe o nome do tenant.")
    if _taken(name):
        raise Conflict("Já existe um tenant com esse nome.")
    t = Tenant(name=name, segment=clean(segment, 60), internal=bool(internal))
    Session.add(t)
    Session.flush()
    return Outcome(message=f"Tenant “{t.name}” criado.", obj=t, tenant_id=t.id, audit=[("tenant.created", t.name, {"internal": t.internal})])


def update_tenant(t: Tenant, *, name=None, segment=None, internal=None, status=None) -> Outcome:
    before = dict(name=t.name, segment=t.segment, internal=t.internal, status=t.status)
    if name is not None:
        name = clean(name)
        if not name:
            raise ServiceError("Informe o nome do tenant.")
        if _taken(name, t.id):
            raise Conflict("Já existe um tenant com esse nome.")
        t.name = name
    if segment is not None:
        t.segment = clean(segment, 60)
    if internal is not None:
        t.internal = bool(internal)
    if status is not None:
        if status not in ("active", "suspended"):
            raise ServiceError("Situação inválida (active ou suspended).")
        t.status = status
    ch = diff(before, dict(name=t.name, segment=t.segment, internal=t.internal, status=t.status))
    msg = f"Tenant “{t.name}” atualizado."
    if ch.get("status"):
        msg = f"Tenant “{t.name}” {'suspenso: syslog, coleta e envios param' if t.status == 'suspended' else 'reativado'}."
    return Outcome(message=msg, obj=t, tenant_id=t.id, audit=[("tenant.updated", t.name, ch)] if ch else [])
