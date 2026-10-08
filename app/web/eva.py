"""Tela EVA (administradores): situação, conversas, histórico de pedidos, modo e quem pode falar com a EVA.

Registro (app/__init__.py):  from .web.eva import bp as eva_bp ; app.register_blueprint(eva_bp)
"""
from __future__ import annotations

from datetime import datetime

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user
from sqlalchemy import select

from ..db import Session, utcnow
from ..models import EvaRequest, EvaThread
from ..security import admin_required, client_ip
from ..services import audit
from ..services import eva_admin as svc
from ..services.changes import ServiceError

bp = Blueprint("eva", __name__, url_prefix="/admin/eva")

STATE_PT = {"em_andamento": "em andamento", "concluido": "concluída", "aguardando_trust": "aguardando time Trust",
            "aguardando_rogerio": "aguardando Rogério", "parado": "parada"}
INTENT_PT = {"pergunta": "dúvida", "manutencao": "manutenção", "alteracao": "alteração", "desfazer": "desfazer",
             "whitelist_incluir": "autorizar pessoa", "whitelist_remover": "remover pessoa", "esclarecimento": "esclarecimento",
             "fora_de_escopo": "fora de escopo"}


def _commit(out, ok_msg: str | None = None):
    """Auditoria com o administrador logado, commit e avisos pós-commit (mesmo padrão das outras telas)."""
    for action, target, details in out.audit or []:
        audit.log(action, target, actor=current_user, tenant_id=out.tenant_id, details=details, ip=client_ip())
    Session.commit()
    for fn in out.after_commit or []:
        try:
            fn()
        except Exception:  # noqa: BLE001 — aviso que falha não desfaz a mudança
            import logging
            logging.getLogger(__name__).exception("aviso da lista da EVA não enviado")
    Session.commit()
    flash(ok_msg or out.message)


def _run(fn, *args, **kw):
    try:
        _commit(fn(*args, **kw))
    except ServiceError as e:
        Session.rollback()
        flash(str(e), "error")
    return redirect(url_for("eva.page"))


@bp.get("")
@bp.get("/")
@admin_required
def page():
    hb = svc.heartbeat()
    age = None
    if hb.get("at"):
        try:
            age = int((utcnow() - datetime.fromisoformat(hb["at"])).total_seconds())
        except ValueError:
            age = None
    st = svc.status()
    threads = Session.execute(select(EvaThread).order_by(EvaThread.updated_at.desc()).limit(50)).scalars().all()
    reqs = Session.execute(select(EvaRequest).order_by(EvaRequest.id.desc()).limit(50)).scalars().all()
    wl = svc.entries()
    active_owners = sum(1 for w in wl if w.active and w.role == "owner")
    return render_template("admin/eva.html", nav="eva", hb=hb, age=age, st=st, mode=st["mode"], threads=threads, reqs=reqs, wl=wl,
                           active_owners=active_owners, STATE_PT=STATE_PT, INTENT_PT=INTENT_PT, mailbox=svc.MAILBOX)


@bp.post("/whitelist")
@admin_required
def whitelist_add():
    f = request.form
    return _run(svc.gui_add, f.get("email", ""), f.get("name", ""), f.get("role", "member"), by=current_user.email, ip=client_ip())


@bp.post("/whitelist/<path:email>/role")
@admin_required
def whitelist_role(email):
    return _run(svc.gui_set_role, email, request.form.get("role", ""), by=current_user.email, ip=client_ip())


@bp.post("/whitelist/<path:email>/remove")
@admin_required
def whitelist_remove(email):
    return _run(svc.gui_remove, email, by=current_user.email, ip=client_ip())


@bp.post("/mode")
@admin_required
def set_mode():
    return _run(svc.set_mode, request.form.get("mode", ""), by=current_user.email)


@bp.post("/threads/<int:tid>/state")
@admin_required
def thread_state(tid):
    th = Session.get(EvaThread, tid)
    if th is None:
        flash("Conversa não encontrada.", "error")
        return redirect(url_for("eva.page"))
    return _run(svc.set_thread_state, th, request.form.get("state", ""))
