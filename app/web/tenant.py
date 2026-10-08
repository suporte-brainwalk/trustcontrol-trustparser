"""Área do cliente (gestor e leitor): visão do próprio tenant. Gestor libera IPs do syslog, envia arquivos e gerencia pessoas."""
from __future__ import annotations

import os

from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, url_for
from flask_login import current_user
from sqlalchemy import func, select

from ..db import Session
from ..models import AllowedIP, Destination, Event, EventDelivery, Source, Tenant, Upload, User
from ..security import client_ip, tenant_user_required
from ..services import audit, catalog, emails, people, sources as ssvc
from ..services.changes import ServiceError
from . import common

bp = Blueprint("tenant", __name__, url_prefix="/t")


@bp.before_request
@tenant_user_required
def _guard():
    return None


@bp.context_processor
def _ctx():
    return {"is_manager": current_user.role == "manager"}


def _t() -> Tenant:
    return Session.get(Tenant, g.tenant_id)


def _manager():
    if current_user.role != "manager":
        abort(403)


def _done(out):
    for action, target, details in out.audit:
        audit.log(action, target, actor=current_user, tenant_id=g.tenant_id, details=details, ip=client_ip())
    Session.commit()
    for u, token in out.invites:
        emails.send_magic_link(u, token, "invite")
    if out.invites:
        Session.commit()
    if out.message:
        flash(out.message)


@bp.get("/")
def dashboard():
    return render_template("tenant/dashboard.html", nav="tdash", t=_t(), **common.dashboard_data(g.tenant_id))


@bp.get("/fontes")
def sources():
    t = _t()
    srcs = common.sources_of(t.id)
    ips = Session.execute(select(AllowedIP).where(AllowedIP.tenant_id == t.id).order_by(AllowedIP.cidr)).scalars().all()
    return render_template("tenant/sources.html", nav="tsources", t=t, sources=srcs, ips=ips, protocols=ssvc.PROTOCOLS,
                           syslog=common.syslog_info(), fw=common.fw_status())


@bp.post("/fontes/ips")
def ip_add():
    _manager()
    f = request.form
    try:
        _done(ssvc.add_allowed_ip(_t(), cidr=f.get("cidr"), protocols=f.getlist("protocols"), description=f.get("description", ""),
                                  source_id=f.get("source_id") or None, allow_wide=False, by=current_user.email))
    except ServiceError as e:
        Session.rollback()
        flash(str(e), "error")
    return redirect(url_for("tenant.sources"))


@bp.post("/fontes/ips/<int:aid>")
def ip_action(aid):
    _manager()
    a = Session.get(AllowedIP, aid)
    if a is None or a.tenant_id != g.tenant_id:
        abort(404)
    try:
        if request.form.get("action") == "delete":
            _done(ssvc.delete_allowed_ip(a))
        else:
            _done(ssvc.update_allowed_ip(a, active=not a.active))
    except ServiceError as e:
        Session.rollback()
        flash(str(e), "error")
    return redirect(url_for("tenant.sources"))


@bp.get("/destinos")
def destinations():
    t = _t()
    rows = Session.execute(select(Destination).where(Destination.tenant_id == t.id).order_by(Destination.name)).scalars().all()
    pending = dict(Session.execute(select(EventDelivery.destination_id, func.count()).where(EventDelivery.status == "pending")
                                   .group_by(EventDelivery.destination_id)).all())
    from ..engine import senders
    return render_template("tenant/destinations.html", nav="tdests", t=t, rows=rows, pending=pending, kinds=senders.KINDS)


@bp.get("/uploads")
def uploads():
    t = _t()
    rows = Session.execute(select(Upload).where(Upload.tenant_id == t.id).order_by(Upload.id.desc()).limit(50)).scalars().all()
    return render_template("tenant/uploads.html", nav="tuploads", t=t, rows=rows, sources=common.sources_of(t.id),
                           inputs=common.input_parsers(), outputs=catalog.output_choices())


@bp.post("/uploads")
def upload_new():
    _manager()
    request.max_content_length = current_app.config["UPLOAD_MAX_MB"] * 1024 * 1024 + 65536
    f = request.form
    try:
        up = common.ingest_upload(_t(), request.files.get("file"), source_id=f.get("source_id") or None, parser_id=f.get("parser_id") or None,
                                  send=f.get("send") == "1", by=current_user.email)
        audit.log("upload.created", up.filename, actor=current_user, tenant_id=g.tenant_id, details={"lines": up.lines}, ip=client_ip())
        Session.commit()
        flash(f"Arquivo recebido: {up.lines} linha(s).")
        return redirect(url_for("tenant.upload", uid=up.id))
    except ServiceError as e:
        Session.rollback()
        flash(str(e), "error")
        return redirect(url_for("tenant.uploads"))


@bp.get("/uploads/<int:uid>")
def upload(uid):
    up = Session.get(Upload, uid)
    if up is None or up.tenant_id != g.tenant_id:
        abort(404)
    sample = Session.execute(select(Event).where(Event.upload_id == uid).order_by(Event.line_no).limit(20)).scalars().all()
    return render_template("admin/upload.html", nav="tuploads", t=_t(), up=up, sample=sample, outputs=catalog.output_choices(), errors=[])


@bp.get("/uploads/<int:uid>/download")
def upload_download(uid):
    up = Session.get(Upload, uid)
    if up is None or up.tenant_id != g.tenant_id:
        abort(404)
    audit.log("upload.downloaded", up.filename, actor=current_user, tenant_id=g.tenant_id, details={"format": request.args.get("fmt")}, ip=client_ip())
    Session.commit()
    return common.download_response(select(Event).where(Event.upload_id == uid).order_by(Event.line_no), request.args.get("fmt", "ocsf_json"),
                                    os.path.splitext(up.filename)[0], request.args.get("unparsed") == "1")


@bp.get("/eventos")
def events():
    q, filt = common.events_query(request.args, g.tenant_id)
    rows = Session.execute(q.order_by(Event.id.desc()).limit(100)).scalars().all()
    return render_template("tenant/events.html", nav="tevents", t=_t(), rows=rows, filt=filt, sources=common.sources_of(g.tenant_id),
                           outputs=catalog.output_choices())


@bp.get("/eventos/download")
def events_download():
    q, filt = common.events_query(request.args, g.tenant_id)
    audit.log("events.downloaded", str(filt)[:300], actor=current_user, tenant_id=g.tenant_id, ip=client_ip())
    Session.commit()
    return common.download_response(q.order_by(Event.id), request.args.get("fmt", "ocsf_json"), "eventos", request.args.get("unparsed") == "1")


@bp.get("/pessoas")
def team():
    return render_template("tenant/team.html", nav="tteam", t=_t(), users=people.list_people(_t()))


@bp.post("/pessoas")
def team_action():
    _manager()
    t, f = _t(), request.form
    try:
        act = f.get("action", "add")
        if act == "add":
            _done(people.add(t, name=f.get("name"), email=f.get("email"), role=f.get("role")))
        elif act == "remove":
            _done(people.remove(t, f.get("email"), actor=current_user))
        elif act == "update":
            _done(people.update(t, f.get("email"), role=f.get("role"), actor=current_user))
        elif act == "resend":
            u = Session.execute(select(User).where(User.tenant_id == t.id, User.email == (f.get("email") or "").lower())).scalar_one_or_none() or abort(404)
            _done(people.resend_invite(u))
    except ServiceError as e:
        Session.rollback()
        flash(str(e), "error")
    return redirect(url_for("tenant.team"))
