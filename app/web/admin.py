"""Área do administrador (Trust Control): painel, tenants, fontes, firewall, destinos, parsers, uploads, eventos,
não reconhecidos, Estúdio IA, configurações, auditoria e chaves de API."""
from __future__ import annotations

import gzip
import io
import json
import os
from datetime import timedelta

from flask import (Blueprint, Response, abort, current_app, flash, g, redirect, render_template, request, send_file,
                   stream_with_context, url_for)
from flask_login import current_user
import re

from sqlalchemy import func, insert, select, text
from sqlalchemy.orm import joinedload

from ..db import Session, utcnow
from ..engine import connectors as connectors_pkg
from ..engine import formats, senders
from ..models import (AllowedIP, ApiKey, AuditLog, Destination, Event, EventDelivery, Parser, ParserVersion, Source, StudioJob,
                      Tenant, Upload, User)
from ..security import admin_required, client_ip
from ..services import api_keys, audit, auth as authsvc, catalog, destinations as dsvc, emails, people, settings, sources as ssvc, tenants as tsvc
from ..services.changes import ServiceError
from . import common

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.before_request
@admin_required
def _guard():
    return None


@bp.context_processor
def _ctx():
    return common.nav_counts()


def _done(out, tenant_id=None, flash_message=True):
    for action, target, details in out.audit:
        audit.log(action, target, actor=current_user, tenant_id=tenant_id if tenant_id is not None else out.tenant_id, details=details, ip=client_ip())
    Session.commit()
    for u, token in out.invites:
        emails.send_magic_link(u, token, "invite")
    for cb in out.after_commit:
        cb()
    if out.invites or out.after_commit:
        Session.commit()
    if flash_message and out.message:
        flash(out.message)
    if out.warning:
        flash(out.warning, "warn")
    return out


def _fail(e):
    Session.rollback()
    flash(str(e), "error")


def _form_bool(name):
    return request.form.get(name) in ("1", "on", "true", "sim")


# ------------------------------------------------------------------------------------------------ painel
@bp.get("/")
def dashboard():
    return render_template("admin/dashboard.html", nav="dash", **common.dashboard_data(None))


# ------------------------------------------------------------------------------------------------ tenants
@bp.get("/tenants")
def tenants():
    rows = Session.execute(select(Tenant).order_by(Tenant.status, Tenant.name)).scalars().all()
    stats = common.tenant_stats([t.id for t in rows])
    return render_template("admin/tenants.html", nav="tenants", rows=rows, stats=stats)


@bp.post("/tenants/new")
def tenant_new():
    try:
        out = _done(tsvc.create_tenant(name=request.form.get("name"), segment=request.form.get("segment"), internal=_form_bool("internal")))
        return redirect(url_for("admin.tenant", tid=out.obj.id))
    except ServiceError as e:
        _fail(e)
        return redirect(url_for("admin.tenants"))


@bp.get("/tenants/<int:tid>")
def tenant(tid):
    t = Session.get(Tenant, tid) or abort(404)
    srcs = Session.execute(select(Source).where(Source.tenant_id == tid).order_by(Source.name)).scalars().all()
    dsts = Session.execute(select(Destination).where(Destination.tenant_id == tid).order_by(Destination.name)).scalars().all()
    ips = Session.execute(select(AllowedIP).where(AllowedIP.tenant_id == tid).order_by(AllowedIP.cidr)).scalars().all()
    return render_template("admin/tenant.html", nav="tenants", t=t, sources=srcs, dests=dsts, ips=ips, users=people.list_people(t),
                           tab=request.args.get("tab", "fontes"), syslog=common.syslog_info())


@bp.post("/tenants/<int:tid>/update")
def tenant_update(tid):
    t = Session.get(Tenant, tid) or abort(404)
    f = request.form
    try:
        _done(tsvc.update_tenant(t, name=f.get("name"), segment=f.get("segment"), status=f.get("status"),
                                 internal=(_form_bool("internal") if "internal_present" in f else None)))
    except ServiceError as e:
        _fail(e)
    return redirect(url_for("admin.tenant", tid=tid, tab=f.get("tab", "fontes")))


@bp.post("/tenants/<int:tid>/pessoas")
def tenant_person(tid):
    t = Session.get(Tenant, tid) or abort(404)
    f = request.form
    try:
        act = f.get("action", "add")
        if act == "add":
            _done(people.add(t, name=f.get("name"), email=f.get("email"), role=f.get("role")))
        elif act == "update":
            _done(people.update(t, f.get("email"), role=f.get("role"), name=f.get("name"), actor=current_user))
        elif act == "remove":
            _done(people.remove(t, f.get("email"), actor=current_user))
        elif act == "resend":
            u = Session.execute(select(User).where(User.tenant_id == tid, User.email == (f.get("email") or "").lower())).scalar_one_or_none() or abort(404)
            _done(people.resend_invite(u))
    except ServiceError as e:
        _fail(e)
    return redirect(url_for("admin.tenant", tid=tid, tab="pessoas"))


# ------------------------------------------------------------------------------------------------ fontes
@bp.get("/fontes")
def sources():
    q = select(Source).join(Tenant, Tenant.id == Source.tenant_id).order_by(Tenant.name, Source.name)
    if request.args.get("tenant_id"):
        q = q.where(Source.tenant_id == int(request.args["tenant_id"]))
    rows = Session.execute(q).scalars().all()
    return render_template("admin/sources.html", nav="sources", rows=rows, tenants=common.tenants(), inputs=common.input_parsers(),
                           connectors=connectors_pkg.REGISTRY, syslog=common.syslog_info(), ingest=settings.get("ingest_status") or {})


def _connector_form(slug: str | None = None):
    """Campos do conector escolhido: c_<slug>__<campo> (configuração) e s_<slug>__<campo> (segredos)."""
    slug = slug or request.form.get("connector") or ""
    cp, sp = f"c_{slug}__", f"s_{slug}__"
    cfg = {k[len(cp):]: v for k, v in request.form.items() if k.startswith(cp)}
    sec = {k[len(sp):]: v for k, v in request.form.items() if k.startswith(sp) and v}
    return cfg, sec


@bp.post("/fontes/nova")
def source_new():
    f = request.form
    t = Session.get(Tenant, int(f.get("tenant_id") or 0)) or abort(404)
    cfg, sec = _connector_form()
    try:
        out = _done(ssvc.create_source(t, name=f.get("name"), transport=f.get("transport", "syslog"), parser_id=f.get("parser_id") or None,
                                       match_hostname=f.get("match_hostname", ""), unparsed_policy=f.get("unparsed_policy", "keep"),
                                       note=f.get("note", ""), connector=f.get("connector", ""), connector_config=cfg, secrets=sec,
                                       interval_s=f.get("interval_s") or None, silence_alert_minutes=f.get("silence_alert_minutes") or 0,
                                       by=current_user.email))
        if f.get("cidr"):
            try:
                _done(ssvc.add_allowed_ip(t, cidr=f.get("cidr"), protocols=f.getlist("protocols") or ["tls"], description=f"Fonte {out.obj.name}",
                                          source_id=out.obj.id, allow_wide=_form_bool("allow_wide"), by=current_user.email))
            except ServiceError as e:
                _fail(e)
        return redirect(url_for("admin.source", sid=out.obj.id))
    except ServiceError as e:
        _fail(e)
        return redirect(url_for("admin.sources"))


@bp.get("/fontes/<int:sid>")
def source(sid):
    s = Session.get(Source, sid) or abort(404)
    ips = Session.execute(select(AllowedIP).where(AllowedIP.tenant_id == s.tenant_id, (AllowedIP.source_id == sid) | AllowedIP.source_id.is_(None))
                          .order_by(AllowedIP.cidr)).scalars().all()
    recent = Session.execute(select(Event).where(Event.source_id == sid).order_by(Event.id.desc()).limit(20)).scalars().all()
    series = common.source_series(sid)
    return render_template("admin/source.html", nav="sources", s=s, ips=ips, recent=recent, series=series, inputs=common.input_parsers(),
                           connector=connectors_pkg.get(s.connector) if s.connector else None, connectors=connectors_pkg.REGISTRY,
                           syslog=common.syslog_info(), protocols=ssvc.PROTOCOLS, unparsed=ssvc.UNPARSED)


@bp.post("/fontes/<int:sid>/editar")
def source_edit(sid):
    s = Session.get(Source, sid) or abort(404)
    f = request.form
    cfg, sec = _connector_form(f.get("connector") or s.connector)
    try:
        _done(ssvc.update_source(s, name=f.get("name"), parser_id=f.get("parser_id") or None, match_hostname=f.get("match_hostname", ""),
                                 unparsed_policy=f.get("unparsed_policy"), note=f.get("note"), active=_form_bool("active"),
                                 silence_alert_minutes=f.get("silence_alert_minutes") or 0,
                                 connector=f.get("connector") or None, connector_config=cfg if s.transport == "api" else None,
                                 secrets=sec, interval_s=f.get("interval_s") or None, by=current_user.email))
    except ServiceError as e:
        _fail(e)
    return redirect(url_for("admin.source", sid=sid))


@bp.post("/fontes/<int:sid>/acao")
def source_action(sid):
    s = Session.get(Source, sid) or abort(404)
    act = request.form.get("action")
    if act == "delete":
        tid = s.tenant_id
        _done(ssvc.delete_source(s))
        return redirect(url_for("admin.tenant", tid=tid))
    if act in ("test", "run") and s.transport == "api":
        from ..engine import collect
        c = connectors_pkg.get(s.connector)
        if act == "test":
            from ..services import secrets_box
            try:
                msg = c.test(s.connector_config or {}, secrets_box.open_(s.secret_enc, f"source:{s.id}"))
                flash(f"✓ {msg}")
            except Exception as e:  # noqa: BLE001
                flash(f"Teste falhou: {e}", "error")
        else:
            s.next_run_at = utcnow() - timedelta(seconds=1)
            Session.commit()
            collect.run_due()
            flash("Coleta executada. Veja o resultado em “Última coleta”.")
        audit.log(f"source.connector_{act}", s.name, actor=current_user, tenant_id=s.tenant_id, ip=client_ip())
        Session.commit()
    return redirect(url_for("admin.source", sid=sid))


# ------------------------------------------------------------------------------------------------ firewall
@bp.get("/firewall")
def firewall():
    rows = Session.execute(select(AllowedIP).join(Tenant, Tenant.id == AllowedIP.tenant_id).order_by(Tenant.name, AllowedIP.cidr)).scalars().all()
    return render_template("admin/firewall.html", nav="firewall", rows=rows, tenants=common.tenants(), all_sources=common.all_sources(),
                           protocols=ssvc.PROTOCOLS, fw=common.fw_status(), syslog=common.syslog_info(),
                           ingest=settings.get("ingest_status") or {})


@bp.post("/firewall/novo")
def firewall_new():
    f = request.form
    t = Session.get(Tenant, int(f.get("tenant_id") or 0)) or abort(404)
    try:
        _done(ssvc.add_allowed_ip(t, cidr=f.get("cidr"), protocols=f.getlist("protocols"), description=f.get("description", ""),
                                  source_id=f.get("source_id") or None, allow_wide=_form_bool("allow_wide"), by=current_user.email))
    except ServiceError as e:
        _fail(e)
    return redirect(request.form.get("next") or url_for("admin.firewall"))


@bp.post("/firewall/<int:aid>/acao")
def firewall_action(aid):
    a = Session.get(AllowedIP, aid) or abort(404)
    act = request.form.get("action")
    try:
        if act == "delete":
            _done(ssvc.delete_allowed_ip(a))
        elif act == "toggle":
            _done(ssvc.update_allowed_ip(a, active=not a.active))
        elif act == "protocols":
            _done(ssvc.update_allowed_ip(a, protocols=request.form.getlist("protocols")))
    except ServiceError as e:
        _fail(e)
    return redirect(request.form.get("next") or url_for("admin.firewall"))


# ------------------------------------------------------------------------------------------------ destinos
@bp.get("/destinos")
def destinations():
    rows = Session.execute(select(Destination).join(Tenant, Tenant.id == Destination.tenant_id).order_by(Tenant.name, Destination.name)).scalars().all()
    pending = dict(Session.execute(select(EventDelivery.destination_id, func.count()).where(EventDelivery.status == "pending")
                                   .group_by(EventDelivery.destination_id)).all())
    return render_template("admin/destinations.html", nav="dests", rows=rows, pending=pending, tenants=common.tenants(), kinds=senders.KINDS)


def _dest_form():
    f = request.form
    kind = f.get("kind")
    spec = senders.KINDS.get(kind) or {"fields": [], "secrets": []}
    cfg = {x.name: f.get(f"c_{x.name}") for x in spec["fields"] if f.get(f"c_{x.name}") is not None}
    sec = {x.name: f.get(f"s_{x.name}") for x in spec["secrets"] if f.get(f"s_{x.name}")}
    filt = {"source_ids": f.getlist("source_ids"), "min_severity_id": f.get("min_severity_id") or None,
            "class_uids": [x for x in (f.get("class_uids") or "").replace(" ", "").split(",") if x]}
    return kind, cfg, sec, filt


@bp.route("/destinos/novo", methods=["GET", "POST"])
def destination_new():
    if request.method == "GET":
        kind = request.args.get("kind")
        tid = request.args.get("tenant_id", type=int)
        return render_template("admin/destination_edit.html", nav="dests", d=None, kind=kind, kinds=senders.KINDS, tenants=common.tenants(),
                               tenant_id=tid, outputs=catalog.output_choices(),
                               tenant_sources=common.sources_of(tid) if tid else [])
    f = request.form
    t = Session.get(Tenant, int(f.get("tenant_id") or 0)) or abort(404)
    kind, cfg, sec, filt = _dest_form()
    try:
        out = _done(dsvc.create_destination(t, name=f.get("name"), kind=kind, format=f.get("format"), config=cfg, secrets=sec, filters=filt,
                                            include_unparsed=_form_bool("include_unparsed"), active=_form_bool("active"), by=current_user.email))
        return redirect(url_for("admin.destination", did=out.obj.id))
    except ServiceError as e:
        _fail(e)
        return redirect(url_for("admin.destination_new", kind=kind, tenant_id=t.id))


@bp.route("/destinos/<int:did>", methods=["GET", "POST"])
def destination(did):
    d = Session.get(Destination, did) or abort(404)
    if request.method == "POST":
        f = request.form
        _, cfg, sec, filt = _dest_form()
        try:
            _done(dsvc.update_destination(d, name=f.get("name"), format=f.get("format"), config=cfg, secrets=sec, filters=filt,
                                          include_unparsed=_form_bool("include_unparsed"), active=_form_bool("active"),
                                          batch_size=f.get("batch_size") or None, by=current_user.email))
        except ServiceError as e:
            _fail(e)
        return redirect(url_for("admin.destination", did=did))
    counts = dict(Session.execute(select(EventDelivery.status, func.count()).where(EventDelivery.destination_id == did)
                                  .group_by(EventDelivery.status)).all())
    last_err = Session.execute(select(EventDelivery).where(EventDelivery.destination_id == did, EventDelivery.last_error != "")
                               .order_by(EventDelivery.event_id.desc()).limit(10)).scalars().all()
    return render_template("admin/destination_edit.html", nav="dests", d=d, kind=d.kind, kinds=senders.KINDS, tenants=common.tenants(),
                           tenant_id=d.tenant_id, outputs=catalog.output_choices(), counts=counts, last_err=last_err,
                           tenant_sources=common.sources_of(d.tenant_id), series=common.dest_series(did))


@bp.post("/destinos/<int:did>/acao")
def destination_action(did):
    d = Session.get(Destination, did) or abort(404)
    act = request.form.get("action")
    if act == "test":
        ok, msg = dsvc.test_destination(d)
        audit.log("destination.tested", d.name, actor=current_user, tenant_id=d.tenant_id, details={"ok": ok}, ip=client_ip())
        Session.commit()
        flash(("✓ " if ok else "Falhou: ") + msg, None if ok else "error")
    elif act == "delete":
        tid = d.tenant_id
        _done(dsvc.delete_destination(d))
        return redirect(url_for("admin.tenant", tid=tid, tab="destinos"))
    elif act == "retry":
        n = Session.execute(text("""update event_deliveries set next_attempt_at = now() where destination_id = :d and status = 'pending'"""),
                            {"d": did}).rowcount
        d.paused_until, d.consecutive_failures = None, 0
        Session.commit()
        flash(f"{n} entrega(s) pendente(s) liberadas para reenvio agora.")
    return redirect(url_for("admin.destination", did=did))


@bp.get("/destinos/wazuh/<path:name>")
def wazuh_pack(name):
    base = os.path.join(current_app.root_path, "..", "deploy", "wazuh")
    allowed = {"trustparser_decoders.xml", "trustparser_rules.xml", "trustparser-wazuh5-integration.yml", "LEIA-ME.md"}
    if name not in allowed:
        abort(404)
    return send_file(os.path.abspath(os.path.join(base, name)), as_attachment=True, download_name=name)


# ------------------------------------------------------------------------------------------------ parsers e formatos
@bp.get("/parsers")
def parsers():
    rows = Session.execute(select(Parser).order_by(Parser.kind, Parser.vendor, Parser.name)).scalars().all()
    usage = dict(Session.execute(select(Source.parser_id, func.count()).group_by(Source.parser_id)).all())
    return render_template("admin/parsers.html", nav="parsers", rows=rows, usage=usage)


@bp.route("/parsers/<int:pid>", methods=["GET", "POST"])
def parser(pid):
    p = Session.get(Parser, pid) or abort(404)
    versions = Session.execute(select(ParserVersion).where(ParserVersion.parser_id == pid).order_by(ParserVersion.version.desc())).scalars().all()
    cur = Session.get(ParserVersion, p.current_version_id) if p.current_version_id else None
    vsel = request.args.get("v", type=int)
    view = next((v for v in versions if v.id == vsel), cur or (versions[0] if versions else None))
    preview = None
    if request.method == "POST":  # testar com amostra (não grava nada)
        lines = (request.form.get("samples") or "").splitlines()[:2000]
        spec = view.spec if view else {}
        if p.kind == "input":
            preview = catalog.coverage(spec, lines, keep=10)
            for ex in preview.get("examples", [])[:4]:
                ex["outputs"] = {fmt: formats.to_line(formats.render(fmt, ex["event"], ex["input"], {"tenant": "teste"}))
                                 for fmt in ("udm", "cef", "leef", "wazuh_json")}
        audit.log("parser.preview", p.slug, actor=current_user, details={"lines": len(lines)}, ip=client_ip())
        Session.commit()
    return render_template("admin/parser.html", nav="parsers", p=p, versions=versions, cur=cur, view=view, preview=preview,
                           secops=bool(p.kind == "input" and catalog.secops_cbn(p.slug)),
                           spec_json=json.dumps(view.spec, ensure_ascii=False, indent=1) if view else "",
                           tests_json=json.dumps(view.tests, ensure_ascii=False, indent=1) if view else "[]")


@bp.post("/parsers/<int:pid>/acao")
def parser_action(pid):
    p = Session.get(Parser, pid) or abort(404)
    act = request.form.get("action")
    try:
        if act == "publish":
            v = Session.get(ParserVersion, int(request.form["version_id"]))
            if v is None or v.parser_id != pid:
                abort(404)
            _done(catalog.publish(v, current_user.email))
        elif act == "rollback":
            _done(catalog.rollback_to(p, int(request.form["version_id"]), current_user.email))
        elif act in ("activate", "deactivate"):
            _done(catalog.set_active(p, act == "activate"))
        elif act == "reject":
            v = Session.get(ParserVersion, int(request.form["version_id"]))
            if v and v.status == "draft":
                v.status = "rejected"
                audit.log("parser.version_rejected", p.slug, actor=current_user, details={"version": v.version}, ip=client_ip())
                Session.commit()
                flash(f"Versão {v.version} descartada.")
        elif act == "new_version":  # edição manual do JSON (vira rascunho; publicar exige testes ok)
            try:
                spec = json.loads(request.form.get("spec") or "{}")
                tests = json.loads(request.form.get("tests") or "[]")
            except ValueError as e:
                raise ServiceError(f"JSON inválido: {e}") from e
            v = catalog.add_version(p, spec, tests, by=current_user.email, notes=request.form.get("notes", "Edição manual"))
            if p.origin == "builtin":
                p.origin = "manual"
            audit.log("parser.version_created", p.slug, actor=current_user, details={"version": v.version}, ip=client_ip())
            Session.commit()
            rep = v.report or {}
            flash(f"Rascunho v{v.version} criado: {rep.get('passed', 0)}/{rep.get('total', 0)} testes ok. Revise e publique.")
            return redirect(url_for("admin.parser", pid=pid, v=v.id))
    except ServiceError as e:
        _fail(e)
    return redirect(url_for("admin.parser", pid=pid))


@bp.get("/parsers/<int:pid>/secops.conf")
def parser_secops(pid):
    """Parser no formato do Google SecOps (CBN), para importar direto no SecOps quando ele recebe os logs sem o Trust Parser."""
    p = Session.get(Parser, pid) or abort(404)
    found = catalog.secops_cbn(p.slug) or abort(404)
    audit.log("parser.secops_export", p.slug, actor=current_user, details={"version": found[1]}, ip=client_ip())
    Session.commit()
    return Response(found[0], mimetype="text/plain",
                    headers={"Content-Disposition": f'attachment; filename="secops-parser-{p.slug}-v{found[1]}.conf"'})


@bp.get("/parsers/secops-leia-me")
def parser_secops_readme():
    base = os.path.abspath(os.path.join(current_app.root_path, "..", "deploy", "secops", "LEIA-ME.md"))
    return send_file(base, as_attachment=True, download_name="secops-parsers-LEIA-ME.md", mimetype="text/markdown")


# ------------------------------------------------------------------------------------------------ uploads
@bp.get("/uploads")
def uploads():
    rows = Session.execute(select(Upload).order_by(Upload.id.desc()).limit(100)).scalars().all()
    return render_template("admin/uploads.html", nav="uploads", rows=rows, tenants=common.tenants(), inputs=common.input_parsers(),
                           all_sources=common.all_sources(), outputs=catalog.output_choices())


@bp.post("/uploads/novo")
def upload_new():
    request.max_content_length = current_app.config["UPLOAD_MAX_MB"] * 1024 * 1024 + 65536
    f = request.form
    t = Session.get(Tenant, int(f.get("tenant_id") or 0)) or abort(404)
    try:
        up = common.ingest_upload(t, request.files.get("file"), source_id=f.get("source_id") or None, parser_id=f.get("parser_id") or None,
                                  send=_form_bool("send"), by=current_user.email)
        audit.log("upload.created", up.filename, actor=current_user, tenant_id=t.id, details={"lines": up.lines, "send": up.send_to_destinations}, ip=client_ip())
        Session.commit()
        flash(f"Arquivo recebido: {up.lines} linha(s). O processamento leva alguns segundos.")
        return redirect(url_for("admin.upload", uid=up.id))
    except ServiceError as e:
        _fail(e)
        return redirect(url_for("admin.uploads"))


@bp.get("/uploads/<int:uid>")
def upload(uid):
    up = Session.get(Upload, uid) or abort(404)
    sample = Session.execute(select(Event).where(Event.upload_id == uid).order_by(Event.line_no).limit(30)).scalars().all()
    errors = Session.execute(select(Event.error, func.count()).where(Event.upload_id == uid, Event.status == "unparsed")
                             .group_by(Event.error).order_by(func.count().desc()).limit(8)).all()
    return render_template("admin/upload.html", nav="uploads", up=up, sample=sample, errors=errors, outputs=catalog.output_choices())


@bp.get("/uploads/<int:uid>/download")
def upload_download(uid):
    up = Session.get(Upload, uid) or abort(404)
    audit.log("upload.downloaded", up.filename, actor=current_user, tenant_id=up.tenant_id, details={"format": request.args.get("fmt")}, ip=client_ip())
    Session.commit()
    return common.download_response(select(Event).where(Event.upload_id == uid).order_by(Event.line_no), request.args.get("fmt", "ocsf_json"),
                                    f"{os.path.splitext(up.filename)[0]}", request.args.get("unparsed") == "1")


# ------------------------------------------------------------------------------------------------ eventos (buffer) e não reconhecidos
@bp.get("/eventos")
def events():
    q, filt = common.events_query(request.args)
    rows = Session.execute(q.order_by(Event.id.desc()).limit(100)).scalars().all()
    return render_template("admin/events.html", nav="events", rows=rows, filt=filt, tenants=common.tenants(), all_sources=common.all_sources(),
                           outputs=catalog.output_choices(), unparsed_view=False)


@bp.get("/eventos/download")
def events_download():
    q, filt = common.events_query(request.args)
    audit.log("events.downloaded", json.dumps(filt, default=str)[:300], actor=current_user, details={"format": request.args.get("fmt")}, ip=client_ip())
    Session.commit()
    return common.download_response(q.order_by(Event.id), request.args.get("fmt", "ocsf_json"), "eventos", request.args.get("unparsed") == "1")


@bp.get("/nao-reconhecidos")
def unparsed():
    args = dict(request.args)
    args["status"] = "unparsed"
    q, filt = common.events_query(args)
    rows = Session.execute(q.order_by(Event.id.desc()).limit(200)).scalars().all()
    groups = Session.execute(select(Event.source_id, Event.error, func.count()).where(Event.status == "unparsed")
                             .group_by(Event.source_id, Event.error).order_by(func.count().desc()).limit(30)).all()
    return render_template("admin/events.html", nav="unparsed", rows=rows, filt=filt, tenants=common.tenants(), all_sources=common.all_sources(),
                           outputs=catalog.output_choices(), unparsed_view=True, groups=groups, src_names=common.source_names(),
                           inputs=common.input_parsers())


@bp.post("/nao-reconhecidos/estudio")
def unparsed_to_studio():
    from ..engine import studio
    ids = [int(x) for x in request.form.getlist("event_id")][:500]
    if not ids:
        flash("Selecione ao menos uma linha.", "error")
        return redirect(url_for("admin.unparsed"))
    lines = [r for (r,) in Session.execute(select(Event.raw).where(Event.id.in_(ids)))]
    pid = request.form.get("parser_id") or None
    try:
        job = studio.create_job(kind="fix" if pid else "input", title=request.form.get("title") or f"Linhas não reconhecidas ({len(lines)})",
                                vendor=request.form.get("vendor", ""), product=request.form.get("product", ""),
                                request=request.form.get("request", ""), samples="\n".join(lines), parser_id=pid, mask=True,
                                by=current_user.email)
        audit.log("studio.requested", job.title, actor=current_user, details={"kind": job.kind, "lines": len(lines)}, ip=client_ip())
        Session.commit()
        flash("Pedido enviado ao Estúdio IA. Você recebe um aviso quando ficar pronto.")
        return redirect(url_for("admin.studio_job", jid=job.id))
    except ServiceError as e:
        _fail(e)
        return redirect(url_for("admin.unparsed"))


# ------------------------------------------------------------------------------------------------ Estúdio IA
@bp.get("/estudio")
def studio():
    jobs = Session.execute(select(StudioJob).order_by(StudioJob.id.desc()).limit(100)).scalars().all()
    from ..services import ai
    return render_template("admin/studio.html", nav="studio", jobs=jobs, inputs=common.input_parsers(),
                           budget=ai.budget_left() if current_app.config.get("OPENROUTER_API_KEY") else None,
                           spent=settings.get("ai_spend_usd") or 0, ai_on=bool(current_app.config.get("OPENROUTER_API_KEY")))


@bp.post("/estudio/novo")
def studio_new():
    from ..engine import studio as st
    request.max_content_length = 20 * 1024 * 1024
    f = request.form
    samples = f.get("samples", "")
    up = request.files.get("samples_file")
    if up and up.filename:
        samples += "\n" + "\n".join(common.read_upload_lines(up)[:5000])
    docs = f.get("docs", "")
    dfile = request.files.get("docs_file")
    if dfile and dfile.filename:
        docs += "\n" + common.read_doc_file(dfile)
    try:
        job = st.create_job(kind=f.get("kind", "input"), title=f.get("title"), vendor=f.get("vendor", ""), product=f.get("product", ""),
                            request=f.get("request", ""), samples=samples, docs=docs, docs_urls=(f.get("docs_urls") or "").split(),
                            mask=_form_bool("mask"), mask_terms=f.get("mask_terms", ""), parser_id=f.get("parser_id") or None,
                            by=current_user.email)
        audit.log("studio.requested", job.title, actor=current_user, details={"kind": job.kind}, ip=client_ip())
        Session.commit()
        flash("Pedido enviado ao Estúdio IA. Leva de 1 a 5 minutos; você recebe um aviso quando ficar pronto.")
        return redirect(url_for("admin.studio_job", jid=job.id))
    except ServiceError as e:
        _fail(e)
        return redirect(url_for("admin.studio"))


@bp.get("/estudio/<int:jid>")
def studio_job(jid):
    job = Session.get(StudioJob, jid) or abort(404)
    v = Session.get(ParserVersion, job.result_version_id) if job.result_version_id else None
    return render_template("admin/studio_job.html", nav="studio", job=job, v=v, p=Session.get(Parser, job.parser_id) if job.parser_id else None,
                           spec_json=json.dumps(v.spec, ensure_ascii=False, indent=1) if v else "")


@bp.post("/estudio/<int:jid>/decidir")
def studio_decide(jid):
    job = Session.get(StudioJob, jid) or abort(404)
    v = Session.get(ParserVersion, job.result_version_id) if job.result_version_id else None
    try:
        if request.form.get("decision") == "approve" and v is not None:
            _done(catalog.publish(v, current_user.email))
            job.status = "approved"
        else:
            if v is not None and v.status == "draft":
                v.status = "rejected"
            job.status = "rejected"
        job.decided_by, job.decided_at = current_user.email, utcnow()
        audit.log("studio." + job.status, job.title, actor=current_user, ip=client_ip())
        Session.commit()
    except ServiceError as e:
        _fail(e)
    return redirect(url_for("admin.studio_job", jid=jid))


# ------------------------------------------------------------------------------------------------ configurações
@bp.route("/configuracoes", methods=["GET", "POST"])
def config():
    if request.method == "POST":
        f = request.form
        act = f.get("action")
        try:
            if act == "ops":
                rec = [e.strip().lower() for e in (f.get("ops_recipients") or "").replace(";", ",").replace("\n", ",").split(",") if e.strip()]
                bad = [e for e in rec if not people.norm_email(e)]
                if bad:
                    raise ServiceError(f"E-mail inválido: {', '.join(bad)}")
                settings.set_("ops_recipients", rec)
                settings.set_("ops_include_admins", _form_bool("ops_include_admins"))
                for k, lo, hi in (("dest_fail_threshold", 1, 100), ("drift_threshold_pct", 1, 100)):
                    if f.get(k):
                        settings.set_(k, max(lo, min(hi, int(f.get(k)))))
                audit.log("settings.ops", ",".join(rec), actor=current_user, ip=client_ip())
                Session.commit()
                flash("Destinatários dos avisos atualizados.")
            elif act == "buffer":
                vals = {"buffer_hours": (1, 24), "undelivered_max_hours": (2, 72), "buffer_max_mb": (500, 40000), "upload_retention_hours": (1, 72)}
                for k, (lo, hi) in vals.items():
                    if f.get(k):
                        settings.set_(k, max(lo, min(hi, float(f.get(k)))))
                audit.log("settings.buffer", "", actor=current_user, details={k: f.get(k) for k in vals}, ip=client_ip())
                Session.commit()
                flash("Retenção do buffer atualizada.")
            elif act == "admin_add":
                _done(people.add_admin(name=f.get("name"), email=f.get("email")))
            elif act in ("admin_suspend", "admin_activate", "admin_remove"):
                u = Session.get(User, int(f.get("user_id"))) or abort(404)
                _done(people.set_admin_status(u, {"admin_suspend": "suspended", "admin_activate": "active", "admin_remove": "removed"}[act], current_user))
            elif act == "admin_resend":
                u = Session.get(User, int(f.get("user_id"))) or abort(404)
                _done(people.resend_invite(u))
            elif act == "test_ops":
                from ..services import ops_alerts
                n = ops_alerts._send("test", "Teste dos avisos operacionais", f"opstest:{utcnow():%Y%m%d%H%M%S}", title="Teste de aviso",
                                     lines=[("Pedido por", current_user.email)], action="Se você recebeu, os avisos estão chegando.", link="/admin/configuracoes")
                Session.commit()
                flash(f"Aviso de teste enviado para {n} destinatário(s).")
        except ServiceError as e:
            _fail(e)
        except Exception as e:  # noqa: BLE001
            _fail(ServiceError(f"Valor inválido: {e}"))
        return redirect(url_for("admin.config"))
    from ..services import ops_alerts
    return render_template("admin/config.html", nav="config", s=settings.all_(), admins=people.admins(), recipients_effective=ops_alerts.recipients())


# ------------------------------------------------------------------------------------------------ auditoria e ajuda
@bp.get("/auditoria")
def audit_view():
    q = select(AuditLog).order_by(AuditLog.id.desc())
    if request.args.get("q"):
        like = f"%{request.args['q']}%"
        q = q.where((AuditLog.action.ilike(like)) | (AuditLog.target.ilike(like)) | (AuditLog.actor_label.ilike(like)))
    rows = Session.execute(q.limit(300)).scalars().all()
    return render_template("admin/audit.html", nav="audit", rows=rows, term=request.args.get("q", ""),
                           tenants={t.id: t.name for t in common.tenants()})


@bp.get("/ajuda")
def help():
    return render_template("admin/help.html", nav="help", syslog=common.syslog_info())


def _a(action, target, tenant_id=None, **details):
    audit.log(action, target, actor=current_user, tenant_id=tenant_id, details=details, ip=client_ip())


# ------------------------------------------------------------------ API (chaves)
def _api_page(new_secret=None, new_key=None, status=200):
    keys = Session.execute(select(ApiKey).options(joinedload(ApiKey.tenant)).order_by(ApiKey.revoked_at.is_not(None), ApiKey.created_at.desc())).scalars().all()
    tenants = Session.execute(select(Tenant).order_by(Tenant.name)).scalars().all()
    return render_template("admin/api_keys.html", nav="api", keys=keys, tenants=tenants, usage=api_keys.usage_30d(),
                           permissions=api_keys.PERMISSIONS, read_perms=api_keys.READ_PERMISSIONS, write_perms=api_keys.WRITE_PERMISSIONS,
                           eva_perms=api_keys.EVA_PERMISSIONS, write_like=api_keys.WRITE_LIKE, is_write=api_keys.is_write,
                           mfa_ok=bool(current_user.totp_enabled), new_secret=new_secret, new_key=new_key, now=utcnow(),
                           api_base=emails.base_url() + "/api/v1"), status


def _mfa_confirmed() -> bool:
    """Chave com escrita: quem cria ou rotaciona confirma com o código MFA do momento."""
    code = (request.form.get("mfa_code") or "").strip().replace(" ", "")
    return bool(current_user.totp_enabled and code and authsvc.verify_totp(current_user.totp_secret, code))


@bp.get("/api")
def api_keys_page():
    return _api_page()


@bp.post("/api/keys")
def api_key_create():
    f = request.form
    tenant_id = f.get("tenant_id", type=int) or None
    ips = [x for x in re.split(r"[\s,;]+", f.get("allowed_ips", "")) if x]
    if api_keys.is_write(f.getlist("permissions")) and not _mfa_confirmed():
        flash("Chave não criada: chaves com escrita exigem o código MFA de quem cria"
              + ("" if current_user.totp_enabled else " — ative o MFA em Minha conta") + ".", "error")
        return redirect(url_for("admin.api_keys_page"))
    try:
        k, secret = api_keys.create(name=f.get("name"), owner_email=(people.norm_email(f.get("owner_email")) or ""), tenant_id=tenant_id,
                                    permissions=f.getlist("permissions"), allowed_ips=ips,
                                    rate_per_min=f.get("rate_per_min", api_keys.DEFAULT_RATE), days=f.get("days", api_keys.DEFAULT_DAYS),
                                    created_by=current_user.email)
    except api_keys.ApiKeyError as e:
        Session.rollback()
        flash(f"Chave não criada: {e}.", "error")
        return redirect(url_for("admin.api_keys_page"))
    _a("api.chave_criada", f"{k.name} (tpk_live_{k.prefix}…)", k.tenant_id, escopo="tenant" if k.tenant_id else "global",
       permissoes=k.permissions, ips=k.allowed_ips, vence=k.expires_at.isoformat(), escrita=api_keys.is_write(k.permissions))
    Session.commit()
    return _api_page(new_secret=secret, new_key=k)


def _api_key(kid) -> ApiKey:
    return Session.get(ApiKey, kid) or abort(404)


@bp.post("/api/keys/<int:kid>/revoke")
def api_key_revoke(kid):
    k = _api_key(kid)
    try:
        api_keys.revoke(k, current_user.email)
    except api_keys.ApiKeyError as e:
        flash(f"Não revogada: {e}.", "error")
        return redirect(url_for("admin.api_keys_page"))
    _a("api.chave_revogada", f"{k.name} (tpk_live_{k.prefix}…)", k.tenant_id)
    Session.commit()
    flash(f"Chave “{k.name}” revogada. Ela deixou de funcionar agora.")
    return redirect(url_for("admin.api_keys_page"))


@bp.post("/api/keys/<int:kid>/rotate")
def api_key_rotate(kid):
    k = _api_key(kid)
    if api_keys.is_write(k.permissions) and not _mfa_confirmed():
        flash("Não rotacionada: chaves com escrita exigem o código MFA de quem rotaciona.", "error")
        return redirect(url_for("admin.api_keys_page"))
    try:
        new, secret = api_keys.rotate(k, current_user.email)
    except api_keys.ApiKeyError as e:
        Session.rollback()
        flash(f"Não foi possível rotacionar: {e}.", "error")
        return redirect(url_for("admin.api_keys_page"))
    _a("api.chave_rotacionada", f"{k.name}: tpk_live_{k.prefix}… → tpk_live_{new.prefix}…", k.tenant_id,
       antiga_vence=k.expires_at.isoformat())
    Session.commit()
    return _api_page(new_secret=secret, new_key=new)


