"""Registro de auditoria."""
from ..db import Session
from ..models import AuditLog


def log(action: str, target: str = "", *, actor=None, actor_label: str | None = None, tenant_id=None,
        details: dict | None = None, ip: str = "", session=None):
    s = session or Session()
    label = actor_label or (actor.email if actor is not None else "sistema")
    s.add(AuditLog(actor_user_id=getattr(actor, "id", None), actor_label=label, tenant_id=tenant_id,
                   action=action, target=target[:2000], details=details or {}, ip=ip or ""))
