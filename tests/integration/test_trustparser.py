"""Integração do Trust Parser: firewall, roteamento do syslog, pipeline ponta a ponta, entregas, segredos, isolamento
de tenant (tela e API), uploads e expurgo do buffer."""
from __future__ import annotations

import base64
import io
import json
import socket
import threading
from datetime import timedelta

import pytest

NGINX = ('2026-10-05T11:38:35.575Z 05/Oct/2026:08:38:35 -0300 | 203.0.113.7 | - | "api.exemplo.com.br" | "GET /contas/1 HTTP/1.1" | 200 | 1103 | '
         '"-" | "IOS-APP" | "198.51.100.20, 203.0.113.7" | SSLVerify: "NONE" - 200 | SSL_DN: "-" | - - - "TLSv1.3/TLS_AES_256_GCM_SHA384" - "-" ')


def _src(f, t, name="Nginx", parser="nginx-access-pipe", policy="keep"):
    from sqlalchemy import select
    from app.models import Parser
    from app.services import sources
    pid = f.s().execute(select(Parser.id).where(Parser.slug == parser)).scalar_one() if parser else None
    out = sources.create_source(t, name=name, transport="syslog", parser_id=pid, unparsed_policy=policy)
    f.s().commit()
    return out.obj


# ------------------------------------------------------------------------------------------------ firewall
def test_allowed_ip_rules(f):
    from app.services import sources
    from app.services.changes import ServiceError
    a, b = f.tenant("A"), f.tenant("B")
    for bad in ("0.0.0.0/0", "2001:db8::1", "abc", "127.0.0.1"):
        with pytest.raises(ServiceError):
            sources.add_allowed_ip(a, cidr=bad)
    with pytest.raises(ServiceError):
        sources.add_allowed_ip(a, cidr="10.0.0.0/8")
    sources.add_allowed_ip(a, cidr="10.0.0.0/8", allow_wide=True, protocols=["udp"])
    sources.add_allowed_ip(a, cidr="200.1.2.3", protocols=["tls", "tcp"])
    f.s().commit()
    with pytest.raises(ServiceError):  # mesmo IP em outro tenant
        sources.add_allowed_ip(b, cidr="200.1.2.3/32")
    with pytest.raises(ServiceError):  # duplicado
        sources.add_allowed_ip(a, cidr="200.1.2.3")
    st = sources.firewall_state()
    assert st == {"tls": ["200.1.2.3/32"], "tcp": ["200.1.2.3/32"], "udp": ["10.0.0.0/8"]}
    from app.services import tenants
    tenants.update_tenant(a, status="suspended")
    f.s().commit()
    assert sources.firewall_state() == {"tls": [], "tcp": [], "udp": []}


def test_ingest_router_resolves_tenant_source_and_protocol(f, app):
    from app import db
    from app.ingest import Router
    from app.services import sources
    t = f.tenant("A")
    s1 = _src(f, t, "Fw matriz")
    s2 = _src(f, t, "Fw filial")
    s2.match_hostname = "^filial"
    sources.add_allowed_ip(t, cidr="200.1.2.0/24", protocols=["tcp"])
    sources.add_allowed_ip(t, cidr="200.9.9.9", protocols=["udp"], source_id=s1.id)
    f.s().commit()
    r = Router(db.engine)
    r.refresh(force=True)
    assert r.resolve("200.9.9.9", "udp", "") == (t.id, s1.id)
    assert r.resolve("200.9.9.9", "tcp", "") is None          # protocolo não liberado
    assert r.resolve("200.1.2.5", "tcp", "filial-fw") == (t.id, s2.id)
    assert r.resolve("200.1.2.5", "tcp", "outro") == (t.id, s1.id)  # única fonte sem regra de hostname
    assert r.resolve("8.8.8.8", "tcp", "") is None


# ------------------------------------------------------------------------------------------------ pipeline
class SyslogSink:
    def __init__(self):
        self.lines, self.sock = [], socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while True:
            c, _ = self.sock.accept()
            threading.Thread(target=self._conn, args=(c,), daemon=True).start()

    def _conn(self, c):
        if True:
            buf = b""
            while True:
                d = c.recv(65536)
                if not d:
                    break
                buf += d
                *done, buf = buf.split(b"\n")
                self.lines += [x.decode() for x in done]


def _dest(f, t, kind, fmt, cfg, secrets=None, **kw):
    from app.models import Destination
    from app.services import secrets_box
    d = Destination(tenant_id=t.id, name=f"{kind}-{fmt}", kind=kind, format=fmt, config=cfg, **kw)
    f.s().add(d)
    f.s().flush()
    if secrets:
        d.secret_enc = secrets_box.seal(secrets, f"dest:{d.id}")
    f.s().commit()
    return d


def _ingest(f, t, s, lines, ip="200.1.2.3", transport="tcp"):
    from app.db import utcnow
    from app.models import Event
    for ln in lines:
        f.s().add(Event(tenant_id=t.id, source_id=s.id, received_at=utcnow(), peer_ip=ip, transport=transport, raw=ln))
    f.s().commit()


def test_end_to_end_syslog_to_wazuh_and_qradar(f):
    import time
    from app.engine import pipeline
    from app.models import Source
    sink = SyslogSink()
    t = f.tenant("A")
    s = _src(f, t)
    _dest(f, t, "wazuh", "wazuh_json", {"host": "127.0.0.1", "port": str(sink.port), "transport": "tcp", "header": "rfc3164"})
    _dest(f, t, "qradar", "leef", {"host": "127.0.0.1", "port": str(sink.port), "transport": "tcp", "header": "rfc3164", "hostname": "cli-a"})
    _ingest(f, t, s, [NGINX] * 5 + ["linha que nenhum parser entende"])
    assert pipeline.process_received() == 6
    assert pipeline.deliver_all() == 10
    for _ in range(50):
        if len(sink.lines) >= 10:
            break
        time.sleep(0.05)
    waz = [x for x in sink.lines if '"tp"' in x]
    leef = [x for x in sink.lines if "LEEF:2.0" in x]
    assert len(waz) == 5 and len(leef) == 5
    assert " trustparser: " in waz[0] and json.loads(waz[0].split("trustparser: ", 1)[1])["tp"]["src_ip"] == "198.51.100.20"
    assert " cli-a trustparser: LEEF:2.0|NGINX|NGINX|" in leef[0]
    src = f.s().get(Source, s.id)
    f.s().refresh(src)
    assert (src.events_total, src.parsed_total, src.unparsed_total) == (6, 5, 1)


def test_unparsed_policies(f):
    from sqlalchemy import func, select
    from app.engine import pipeline
    from app.models import Event, EventDelivery
    t = f.tenant("A")
    s_drop = _src(f, t, "drop", policy="drop")
    s_fwd = _src(f, t, "fwd", policy="forward_raw")
    _dest(f, t, "syslog", "cef", {"host": "127.0.0.1", "port": "9", "transport": "udp"}, include_unparsed=True)
    _ingest(f, t, s_drop, ["xxx"])
    _ingest(f, t, s_fwd, ["yyy"])
    pipeline.process_received()
    assert f.s().execute(select(func.count()).select_from(Event).where(Event.source_id == s_drop.id)).scalar() == 0
    assert f.s().execute(select(func.count()).select_from(EventDelivery)).scalar() == 1


def test_secops_batch_isolates_rejected_event(f, monkeypatch):
    from app.engine import pipeline, senders
    from app.models import Destination, EventDelivery
    sent = []

    def fake(cfg, secrets, events, client=None):
        assert secrets["service_account_json"] == "{SA}"
        if any(e["metadata"].get("product_event_type") == "500" for e in events):
            raise senders.SendError("Google SecOps rejeitou o lote (HTTP 400)", permanent=True)
        sent.extend(events)
    monkeypatch.setattr(senders, "send_chronicle", fake)
    t = f.tenant("A")
    s = _src(f, t)
    d = _dest(f, t, "secops_chronicle", "udm", {"location": "us", "project_id": "p", "instance_id": "i"}, {"service_account_json": "{SA}"})
    _ingest(f, t, s, [NGINX, NGINX.replace("| 200 | 1103", "| 500 | 1103"), NGINX])
    pipeline.process_received()
    pipeline.deliver_all()
    assert len(sent) == 2 and all(e["metadata"]["event_type"] == "NETWORK_HTTP" for e in sent)
    st = {x.status for x in f.s().query(EventDelivery).filter_by(destination_id=d.id)}
    assert st == {"sent", "failed"}
    assert f.s().get(Destination, d.id).sent_total == 2


def test_destination_down_retries_and_alerts(f, monkeypatch, no_smtp):
    from app.engine import pipeline
    from app.models import Destination, EventDelivery
    from app.services import settings
    settings.set_("ops_recipients", ["ops@exemplo.com.br"])
    settings.set_("ops_include_admins", False)
    t = f.tenant("A")
    s = _src(f, t)
    d = _dest(f, t, "syslog", "cef", {"host": "127.0.0.1", "port": "1", "transport": "tcp"})
    _ingest(f, t, s, [NGINX])
    pipeline.process_received()
    for _ in range(5):
        f.s().query(EventDelivery).update({"next_attempt_at": pipeline.utcnow() - timedelta(seconds=1)})
        f.s().query(Destination).update({"paused_until": None})
        f.s().commit()
        pipeline.deliver_all()
    d = f.s().get(Destination, d.id)
    assert d.status == "err" and d.consecutive_failures >= 5 and d.alerted_at is not None
    assert f.s().query(EventDelivery).one().status == "pending"   # continua guardado para reenvio
    assert any("Destino com falha" in m["Subject"] for m in no_smtp)


def test_purge_keeps_undelivered_until_24h(f):
    from app.db import utcnow
    from app.engine import pipeline
    from app.models import Event, EventDelivery
    t = f.tenant("A")
    s = _src(f, t)
    d = _dest(f, t, "syslog", "cef", {"host": "127.0.0.1", "port": "9", "transport": "udp"})
    _ingest(f, t, s, [NGINX, NGINX])
    pipeline.process_received()
    evs = f.s().query(Event).order_by(Event.id).all()
    evs[0].received_at = utcnow() - timedelta(hours=3)
    evs[0].pending_deliveries = 0
    f.s().query(EventDelivery).filter_by(event_id=evs[0].id).delete()
    evs[1].received_at = utcnow() - timedelta(hours=3)  # pendente: fica
    f.s().commit()
    pipeline.purge()
    assert [e.id for e in f.s().query(Event)] == [evs[1].id]
    f.s().query(Event).update({"received_at": utcnow() - timedelta(hours=25)})
    f.s().commit()
    pipeline.purge()
    assert f.s().query(Event).count() == 0


# ------------------------------------------------------------------------------------------------ segredos e destinos
def test_destination_secret_is_encrypted_and_never_returned(f, app):
    from app.models import Destination
    from app.services import destinations
    t = f.tenant("A")
    sa = json.dumps({"type": "service_account", "private_key": "-----BEGIN PRIVATE KEY-----\nX\n-----END PRIVATE KEY-----\n",
                     "client_email": "x@p.iam.gserviceaccount.com"})
    out = destinations.create_destination(t, name="SecOps", kind="secops_chronicle", config={"location": "us", "project_id": "p", "instance_id": "i"},
                                          secrets={"service_account_json": sa}, by="t")
    f.s().commit()
    d = f.s().get(Destination, out.obj.id)
    assert b"BEGIN PRIVATE KEY" not in d.secret_enc and d.secret_set_by == "t"
    from app.services import secrets_box
    assert secrets_box.open_(d.secret_enc, f"dest:{d.id}")["service_account_json"] == sa
    with pytest.raises(secrets_box.SecretsError):  # não serve para outro registro
        secrets_box.open_(d.secret_enc, f"dest:{d.id + 1}")
    from app.services.changes import ServiceError
    with pytest.raises(ServiceError):
        destinations.create_destination(t, name="X", kind="secops_chronicle", config={"location": "us", "project_id": "p", "instance_id": "i"},
                                        secrets={"service_account_json": "{}"})
    with pytest.raises(ServiceError):  # rede interna do servidor não pode ser destino
        destinations.create_destination(t, name="Y", kind="syslog", config={"host": "127.0.0.1", "port": "514"})


def test_api_tenant_isolation_and_no_secrets(client, fx, app):
    with app.app_context():
        a, b = fx.tenant("A"), fx.tenant("B")
        _dest(fx, b, "webhook", "ocsf_json", {"url": "https://example.org/hook"}, {"auth_value": "Bearer SEGREDO"})
        src_b = _src(fx, b)
        ha = fx.api_key(["fontes:gerenciar", "destinos:ler"], tenant=a)
        hg = fx.api_key(["destinos:ler", "fontes:ler"])
        bid, sbid = b.id, src_b.id
    r = client.get(f"/api/v1/sources/{sbid}", headers=ha)
    assert r.status_code == 404
    assert client.get("/api/v1/destinations", headers=ha).json["data"] == []
    r = client.post("/api/v1/allowed-ips", headers=ha, json={"tenant_id": bid, "cidr": "200.1.1.1"})
    assert r.status_code == 404
    body = client.get("/api/v1/destinations", headers=hg).get_data(as_text=True)
    assert "SEGREDO" not in body and "credentials_set_at" in body


def test_api_parse_and_upload(client, fx, app):
    import time
    with app.app_context():
        t = fx.tenant("A")
        h = fx.api_key(["uploads:enviar", "parsers:ler"])
        tid = t.id
    r = client.post("/api/v1/parse", headers=h, json={"lines": [NGINX, "nada"], "format": "cef"})
    assert r.status_code == 200 and r.json["parsed"] == 1 and r.json["results"][0]["output"].startswith("CEF:0|NGINX|NGINX|")
    r = client.post("/api/v1/uploads", headers=h, json={"tenant_id": tid, "filename": "x.log", "content": NGINX + "\n" + NGINX})
    assert r.status_code == 201 and r.json["lines"] == 2
    with app.app_context():
        from app.engine import pipeline
        pipeline.process_received()
    r = client.get(f"/api/v1/uploads/{r.json['id']}/download?format=udm", headers=h)
    lines = r.get_data(as_text=True).strip().splitlines()
    assert len(lines) == 2 and json.loads(lines[0])["metadata"]["event_type"] == "NETWORK_HTTP"


def test_xlsx_upload_reads_raw_log_column(f):
    from openpyxl import Workbook
    from app.web.common import read_upload_lines
    wb = Workbook()
    ws = wb.active
    ws.append(["timestamp", "raw log"])
    ws.append(["2026-10-05T11:38:35Z", NGINX])
    buf = io.BytesIO()
    wb.save(buf)

    class FakeFile:
        filename = "export.xlsx"

        def read(self):
            return buf.getvalue()
    assert read_upload_lines(FakeFile()) == [NGINX]


# ------------------------------------------------------------------------------------------------ telas
def test_admin_pages_render(client, fx, app, login):
    with app.app_context():
        u = fx.user("adm@exemplo.com.br", "admin")
        t = fx.tenant("A")
        s = _src(fx, t)
        tid, sid = t.id, s.id
    login(u)
    for url in ["/admin/", "/admin/tenants", f"/admin/tenants/{tid}", f"/admin/tenants/{tid}?tab=ips", f"/admin/tenants/{tid}?tab=pessoas",
                "/admin/fontes", f"/admin/fontes/{sid}", "/admin/firewall", "/admin/destinos", "/admin/destinos/novo",
                "/admin/destinos/novo?kind=secops_chronicle", "/admin/destinos/novo?kind=wazuh", "/admin/parsers", "/admin/uploads",
                "/admin/eventos", "/admin/nao-reconhecidos", "/admin/estudio", "/admin/configuracoes", "/admin/auditoria", "/admin/ajuda",
                "/admin/api", "/admin/eva/"]:
        r = client.get(url)
        assert r.status_code == 200, (url, r.status_code)


def test_tenant_user_sees_only_own_area(client, fx, app, login):
    with app.app_context():
        t = fx.tenant("A")
        u = fx.user("gestor@exemplo.com.br", "manager", tenant=t)
    login(u)
    for url in ["/t/", "/t/fontes", "/t/destinos", "/t/uploads", "/t/eventos", "/t/pessoas"]:
        assert client.get(url).status_code == 200, url
    for url in ["/admin/", "/admin/firewall", "/admin/destinos"]:
        assert client.get(url).status_code == 403, url


def test_wazuh_pack_downloads(client, fx, app, login):
    with app.app_context():
        u = fx.user("adm@exemplo.com.br", "admin")
    login(u)
    for n in ("trustparser_decoders.xml", "trustparser_rules.xml", "LEIA-ME.md"):
        assert client.get(f"/admin/destinos/wazuh/{n}").status_code == 200, n
    assert client.get("/admin/destinos/wazuh/..%2Fetc%2Fpasswd").status_code == 404


def test_studio_output_examples_never_use_buffer_data(f):
    """Exemplos enviados à IA para desenhar saídas são sintéticos — nada do buffer (dados de clientes)."""
    from app.db import utcnow
    from app.engine import studio
    from app.models import Event
    t = f.tenant("A")
    f.s().add(Event(tenant_id=t.id, received_at=utcnow(), raw="x", status="parsed",
                    event={"time": "2026-10-08T00:00:00.000Z", "class_uid": 9999, "message": "SEGREDO-DO-CLIENTE"}))
    f.s().commit()
    import json
    assert "SEGREDO-DO-CLIENTE" not in json.dumps(studio._sample_events())
