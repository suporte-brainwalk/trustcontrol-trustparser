"""Conectores API PULL: todos os testes usam httpx.MockTransport (nenhum acesso à rede)."""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from app.engine.connectors import REGISTRY, ConnectorError, PullResult, get
from app.engine.connectors import base as cbase

NOW = lambda: datetime.now(timezone.utc)  # noqa: E731


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    slept: list[float] = []
    monkeypatch.setattr(cbase, "_sleep", slept.append)
    return slept


class Server:
    """Roteia por (método, sufixo do caminho) e grava as requisições."""

    def __init__(self, routes):
        self.routes = routes
        self.calls: list[httpx.Request] = []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.calls.append(req)
        for (method, suffix), fn in self.routes.items():
            if req.method == method and req.url.path.endswith(suffix):
                r = fn(req)
                return r if isinstance(r, httpx.Response) else httpx.Response(200, json=r)
        return httpx.Response(404, json={"error": "no route " + req.url.path})

    def client(self):
        return httpx.Client(transport=httpx.MockTransport(self))

    def hits(self, suffix):
        return [c for c in self.calls if c.url.path.endswith(suffix)]


def assert_lines(res: PullResult):
    for line in res.lines:
        obj = json.loads(line)
        assert isinstance(obj, dict)
        assert line == json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    json.dumps(res.cursor)  # cursor serializável


def form(req):
    return parse_qs(req.content.decode())


def basic(req):
    return base64.b64decode(req.headers["Authorization"].split()[1]).decode()


# ---------------------------------------------------------------------------------------------------------------------
# Registro / contrato
# ---------------------------------------------------------------------------------------------------------------------
def test_registry_and_parser_slugs():
    expected = {
        "withsecure-elements": "withsecure-elements-api-event",
        "cortex-xdr": "cortex-xdr-api-alert",
        "trend-vision-one": "trend-vision-one-api-alert",
        "watchguard-epdr": "watchguard-epdr-api-json",
        "axur": "axur-api-ticket",
        "tenable": "tenable-vuln-export",
    }
    assert {k: v.parser_slug for k, v in REGISTRY.items()} == expected
    for c in REGISTRY.values():
        sch = c.schema()
        assert sch["secret_fields"] and all(f["kind"] == "secret" for f in sch["secret_fields"])
        json.dumps(sch)
    with pytest.raises(ConnectorError):
        get("nao-existe")


def test_missing_required_fields():
    with pytest.raises(ConnectorError, match="obrigatórios"):
        get("axur").pull({}, {}, {})


def test_base_url_rejects_http():
    with pytest.raises(ConnectorError, match="https"):
        get("axur").pull({"base_url": "http://api.axur.com"}, {"api_key": "k" * 10}, {})


def test_transport_error_is_connector_error(no_sleep):
    def boom(req):
        raise httpx.ConnectError("x", request=req)
    c = httpx.Client(transport=httpx.MockTransport(boom))
    with pytest.raises(ConnectorError, match="conectar"):
        get("axur").test({}, {"api_key": "segredo-123"}, client=c)
    assert len(no_sleep) == 2  # 3 tentativas


# ---------------------------------------------------------------------------------------------------------------------
# WithSecure Elements
# ---------------------------------------------------------------------------------------------------------------------
WS_CFG = {"client_id": "cid-1", "organization_id": "org-uuid"}
WS_SEC = {"client_secret": "S3cr3t-WS"}


def ws_event(i, ts):
    return {"id": f"ev{i}", "engine": "deepGuard", "severity": "warning", "persistenceTimestamp": iso(ts),
            "message": "Arquivo bloqueado ç", "details": {"a": "1"}}


def test_withsecure_auth_pagination_lookback():
    t0 = NOW() - timedelta(seconds=30)
    pages = {None: {"items": [ws_event(1, t0), ws_event(2, t0 + timedelta(seconds=1))], "nextAnchor": "A2"},
             "A2": {"items": [ws_event(3, t0 + timedelta(seconds=2))]}}

    def events(req):
        f = form(req)
        return pages[(f.get("anchor") or [None])[0]]
    srv = Server({("POST", "/as/token.oauth2"): lambda r: {"access_token": "tok-1", "expires_in": 1799},
                  ("POST", "/security-events/v1/security-events"): events})
    res = get("withsecure-elements").pull(WS_CFG, WS_SEC, {}, client=srv.client())
    assert_lines(res)
    assert [json.loads(x)["id"] for x in res.lines] == ["ev1", "ev2", "ev3"]
    tok = srv.hits("/as/token.oauth2")[0]
    assert basic(tok) == "cid-1:S3cr3t-WS"
    assert form(tok) == {"grant_type": ["client_credentials"], "scope": ["connect.api.read"]}
    ev = srv.hits("/security-events")[0]
    assert ev.headers["Authorization"] == "Bearer tok-1"
    assert ev.headers["User-Agent"] == "TrustParser/1.0"
    f = form(ev)
    assert f["engineGroup"] == ["epp", "edr", "ecp", "xm"] and f["order"] == ["asc"] and f["organizationId"] == ["org-uuid"]
    start = cbase.parse_ts(f["persistenceTimestampStart"][0])
    assert abs((NOW() - timedelta(minutes=60) - start).total_seconds()) < 5  # 1ª execução: retroativo de 60 min
    assert form(srv.hits("/security-events")[1])["anchor"] == ["A2"]
    assert res.cursor["boundary"] == ["ev3"] and cbase.parse_ts(res.cursor["since"]) == cbase.parse_ts(iso(t0 + timedelta(seconds=2)))


def test_withsecure_cursor_dedupes_boundary():
    t0 = NOW() - timedelta(minutes=10)
    cursor = {"since": iso(t0), "boundary": ["ev1"]}
    srv = Server({("POST", "/as/token.oauth2"): lambda r: {"access_token": "t"},
                  ("POST", "/security-events/v1/security-events"):
                      lambda r: {"items": [ws_event(1, t0), ws_event(9, t0), ws_event(10, t0 + timedelta(seconds=5))]}})
    res = get("withsecure-elements").pull(WS_CFG, WS_SEC, cursor, client=srv.client())
    assert [json.loads(x)["id"] for x in res.lines] == ["ev9", "ev10"]
    assert cbase.parse_ts(form(srv.hits("/security-events")[0])["persistenceTimestampStart"][0]) == cbase.parse_ts(iso(t0))


def test_withsecure_empty_run_advances_cursor():
    old = NOW() - timedelta(days=3)
    srv = Server({("POST", "/as/token.oauth2"): lambda r: {"access_token": "t"},
                  ("POST", "/security-events/v1/security-events"): lambda r: {"items": []}})
    res = get("withsecure-elements").pull(WS_CFG, WS_SEC, {"since": iso(old), "boundary": []}, client=srv.client())
    assert res.lines == [] and cbase.parse_ts(res.cursor["since"]) > NOW() - timedelta(minutes=5)


def test_withsecure_401_and_400_token():
    srv = Server({("POST", "/as/token.oauth2"): lambda r: httpx.Response(401, text="bad S3cr3t-WS")})
    with pytest.raises(ConnectorError, match="HTTP 401") as e:
        get("withsecure-elements").pull(WS_CFG, WS_SEC, {}, client=srv.client())
    assert "S3cr3t-WS" not in str(e.value)
    srv = Server({("POST", "/as/token.oauth2"): lambda r: httpx.Response(400, json={"error": "invalid_client"})})
    with pytest.raises(ConnectorError, match="invalid_client"):
        get("withsecure-elements").test(WS_CFG, WS_SEC, client=srv.client())


def test_withsecure_429_retry(no_sleep):
    n = {"c": 0}

    def events(req):
        n["c"] += 1
        if n["c"] == 1:
            return httpx.Response(429, headers={"Retry-After": "7"})
        return {"items": [ws_event(1, NOW())]}
    srv = Server({("POST", "/as/token.oauth2"): lambda r: {"access_token": "t"},
                  ("POST", "/security-events/v1/security-events"): events})
    res = get("withsecure-elements").pull(WS_CFG, WS_SEC, {}, client=srv.client())
    assert len(res.lines) == 1 and no_sleep == [7.0]


def test_withsecure_test_ok():
    srv = Server({("POST", "/as/token.oauth2"): lambda r: {"access_token": "t"},
                  ("POST", "/security-events/v1/security-events"): lambda r: {"items": []}})
    msg = get("withsecure-elements").test(WS_CFG, WS_SEC, client=srv.client())
    assert msg.startswith("Conexão OK")
    assert form(srv.hits("/security-events")[0])["limit"] == ["1"]


# ---------------------------------------------------------------------------------------------------------------------
# Cortex XDR
# ---------------------------------------------------------------------------------------------------------------------
CX_CFG = {"fqdn": "empresa.xdr.us.paloaltonetworks.com", "api_key_id": "7", "key_type": "advanced"}
CX_SEC = {"api_key": "XDRKEY-secret"}


def cx_alerts_server(alerts):
    """Servidor que aplica filtro gte/lte em local_insert_ts e pagina por search_from/search_to."""
    def handler(req):
        body = json.loads(req.content)["request_data"]
        gte = next(f["value"] for f in body["filters"] if f["operator"] == "gte")
        lte = next(f["value"] for f in body["filters"] if f["operator"] == "lte")
        sel = [a for a in alerts if gte <= a["local_insert_ts"] <= lte]
        sel.sort(key=lambda a: a["creation_time"])
        page = sel[body["search_from"]:body["search_to"]]
        return {"reply": {"total_count": len(sel), "result_count": len(page), "alerts": page}}
    return Server({("POST", "/alerts/get_alerts_multi_events"): handler, ("POST", "/alerts/get_alerts"): handler})


def test_cortex_advanced_auth_and_pagination():
    base = cbase.to_ms(NOW() - timedelta(seconds=30))
    alerts = [{"alert_id": str(i), "local_insert_ts": base + i, "creation_time": base + i, "host_ip": ["10.0.0.1"]}
              for i in range(105)]
    srv = cx_alerts_server(alerts)
    res = get("cortex-xdr").pull(CX_CFG, CX_SEC, {}, client=srv.client())
    assert_lines(res)
    assert len(res.lines) == 105 and not res.more
    reqs = srv.calls
    assert str(reqs[0].url) == "https://api-empresa.xdr.us.paloaltonetworks.com/public_api/v2/alerts/get_alerts_multi_events"
    h = reqs[0].headers
    assert h["x-xdr-auth-id"] == "7" and len(h["x-xdr-nonce"]) == 64
    assert h["Authorization"] == hashlib.sha256(f"XDRKEY-secret{h['x-xdr-nonce']}{h['x-xdr-timestamp']}".encode()).hexdigest()
    b0, b1 = (json.loads(r.content)["request_data"] for r in reqs)
    assert (b0["search_from"], b0["search_to"], b1["search_from"]) == (0, 100, 100)
    gte = b0["filters"][0]["value"]
    assert abs(gte - cbase.to_ms(NOW() - timedelta(minutes=60))) < 5000
    assert cbase.to_ms(cbase.parse_ts(res.cursor["since"])) == base + 104 and res.cursor["boundary"] == ["104"]


def test_cortex_standard_key_and_v1_endpoint():
    srv = cx_alerts_server([])
    cfg = dict(CX_CFG, key_type="standard", endpoint="v1_alerts", fqdn="https://api-x.xdr.eu.paloaltonetworks.com/")
    msg = get("cortex-xdr").test(cfg, CX_SEC, client=srv.client())
    assert "Conexão OK" in msg
    r = srv.calls[0]
    assert r.headers["Authorization"] == "XDRKEY-secret" and "x-xdr-nonce" not in r.headers
    assert str(r.url) == "https://api-x.xdr.eu.paloaltonetworks.com/public_api/v1/alerts/get_alerts"


def test_cortex_cap_and_resume(monkeypatch):
    monkeypatch.setattr(cbase, "MAX_OBJECTS", 150)
    import app.engine.connectors.cortex_xdr as cx
    monkeypatch.setattr(cx, "MAX_OBJECTS", 150)
    base = cbase.to_ms(NOW() - timedelta(minutes=30))
    # creation_time decrescente em relação a local_insert_ts: o corte não pode perder alertas
    alerts = [{"alert_id": str(i), "local_insert_ts": base + i, "creation_time": base - i} for i in range(260)]
    srv = cx_alerts_server(alerts)
    cur, seen = {}, []
    for _ in range(3):
        res = get("cortex-xdr").pull(CX_CFG, CX_SEC, cur, client=srv.client())
        seen += [json.loads(x)["alert_id"] for x in res.lines]
        cur = res.cursor
        if not res.more:
            break
    assert sorted(seen, key=int) == [str(i) for i in range(260)] and len(seen) == 260
    assert "resume" not in cur


def test_cortex_401_402_429(no_sleep):
    srv = Server({("POST", "/get_alerts_multi_events"): lambda r: httpx.Response(401)})
    with pytest.raises(ConnectorError, match="Credenciais recusadas pelo Cortex XDR \\(HTTP 401\\)"):
        get("cortex-xdr").pull(CX_CFG, CX_SEC, {}, client=srv.client())
    srv = Server({("POST", "/get_alerts_multi_events"): lambda r: httpx.Response(402)})
    with pytest.raises(ConnectorError, match="licença"):
        get("cortex-xdr").pull(CX_CFG, CX_SEC, {}, client=srv.client())
    srv = Server({("POST", "/get_alerts_multi_events"): lambda r: httpx.Response(429)})
    with pytest.raises(ConnectorError, match="429"):
        get("cortex-xdr").pull(CX_CFG, CX_SEC, {}, client=srv.client())
    assert len(srv.calls) == 3 and no_sleep == [1.0, 2.0]


# ---------------------------------------------------------------------------------------------------------------------
# Trend Vision One
# ---------------------------------------------------------------------------------------------------------------------
V1_SEC = {"api_token": "V1TOKEN-abc"}


def test_vision_one_workbench_nextlink_and_filter():
    t0 = NOW() - timedelta(seconds=30)
    a = lambda i: {"id": f"WB-{i}", "createdDateTime": iso(t0 + timedelta(seconds=i)).replace(".000", ""),  # noqa: E731
                   "severity": "high", "model": "X"}

    def alerts(req):
        q = parse_qs(urlsplit(str(req.url)).query)
        if "skipToken" in q:
            return {"items": [a(3)]}
        return {"items": [a(1), a(2)], "nextLink": str(req.url) + "&skipToken=abc"}
    srv = Server({("GET", "/v3.0/workbench/alerts"): alerts})
    cfg = {"region": "eu", "filter": "severity eq 'high'"}
    res = get("trend-vision-one").pull(cfg, V1_SEC, {}, client=srv.client())
    assert_lines(res)
    assert [json.loads(x)["id"] for x in res.lines] == ["WB-1", "WB-2", "WB-3"]
    assert all(r.url.host == "api.eu.xdr.trendmicro.com" for r in srv.calls)
    assert all(r.headers["TMV1-Filter"] == "severity eq 'high'" for r in srv.calls)  # reenviado no nextLink
    assert srv.calls[0].headers["Authorization"] == "Bearer V1TOKEN-abc"
    q = parse_qs(srv.calls[0].url.query.decode())
    assert q["dateTimeTarget"] == ["createdDateTime"] and q["orderBy"] == ["createdDateTime asc"]
    assert abs((cbase.parse_ts(q["startDateTime"][0]) - (NOW() - timedelta(minutes=60))).total_seconds()) < 5
    assert res.cursor["workbench"]["boundary"] == ["WB-3"]


def test_vision_one_with_oat_stream():
    t0 = NOW() - timedelta(minutes=5)
    srv = Server({("GET", "/v3.0/workbench/alerts"): lambda r: {"items": []},
                  ("GET", "/v3.0/oat/detections"): lambda r: {"items": [
                      {"uuid": "u1", "ingestedDateTime": iso(t0), "detail": {"eventTime": "1649806995000"}}]}})
    res = get("trend-vision-one").pull({"region": "us", "streams": "workbench_oat", "filter": "x eq 'y'"},
                                       V1_SEC, {}, client=srv.client())
    assert [json.loads(x)["uuid"] for x in res.lines] == ["u1"]
    assert set(res.cursor) == {"workbench", "oat"}
    oat = srv.hits("/oat/detections")[0]
    assert "TMV1-Filter" not in oat.headers and "ingestedStartDateTime" in oat.url.query.decode()


def test_vision_one_cap_resume(monkeypatch):
    import app.engine.connectors.vision_one as v1
    monkeypatch.setattr(v1, "MAX_OBJECTS", 3)
    t0 = NOW() - timedelta(minutes=20)
    items = [{"id": f"W{i}", "createdDateTime": iso(t0 + timedelta(seconds=i))} for i in range(5)]

    def alerts(req):
        q = parse_qs(req.url.query.decode())
        if "skipToken" in q:
            return {"items": items[2:]}
        return {"items": items[:2], "nextLink": str(req.url) + "&skipToken=p2"}
    srv = Server({("GET", "/v3.0/workbench/alerts"): alerts})
    r1 = get("trend-vision-one").pull({"region": "us"}, V1_SEC, {}, client=srv.client())
    assert r1.more and len(r1.lines) == 3 and r1.cursor["workbench"]["resume"]["skip"] == 1
    r2 = get("trend-vision-one").pull({"region": "us"}, V1_SEC, r1.cursor, client=srv.client())
    assert [json.loads(x)["id"] for x in r1.lines + r2.lines] == [f"W{i}" for i in range(5)]
    assert not r2.more and "resume" not in r2.cursor["workbench"]


def test_vision_one_rejects_foreign_nextlink():
    srv = Server({("GET", "/v3.0/workbench/alerts"): lambda r: {"items": [], "nextLink": "https://evil.example/x"}})
    with pytest.raises(ConnectorError, match="outro host"):
        get("trend-vision-one").pull({"region": "us"}, V1_SEC, {}, client=srv.client())


def test_vision_one_403_and_429(no_sleep):
    srv = Server({("GET", "/v3.0/workbench/alerts"): lambda r: httpx.Response(403)})
    with pytest.raises(ConnectorError, match="HTTP 403"):
        get("trend-vision-one").test({"region": "us"}, V1_SEC, client=srv.client())
    n = {"c": 0}

    def flaky(req):
        n["c"] += 1
        return httpx.Response(429 if n["c"] == 1 else 200, json={"items": []})
    srv = Server({("GET", "/v3.0/workbench/alerts"): flaky})
    assert "Conexão OK" in get("trend-vision-one").test({"region": "us"}, V1_SEC, client=srv.client())
    assert no_sleep == [1.0]


# ---------------------------------------------------------------------------------------------------------------------
# WatchGuard EPDR
# ---------------------------------------------------------------------------------------------------------------------
WG_CFG = {"region": "deu", "account_id": "WGC-1-123abc456", "access_id": "acc_ro", "event_types": "1,18"}
WG_SEC = {"password": "WGpass!", "api_key": "WGKEY-123"}


def wg_server(events_by_type):
    def sec(req):
        t = int(req.url.path.split("/securityevents/")[1].split("/")[0])
        return {"data": events_by_type.get(t, []), "total_items": len(events_by_type.get(t, []))}
    return Server({("POST", "/oauth/token"): lambda r: {"access_token": "wgtok", "expires_in": 3600},
                   ("GET", "/export/1"): sec})


def test_watchguard_auth_types_dedupe_and_lookback():
    now = NOW()
    old = {"event_id": 1, "device_id": "d1", "date": iso(now - timedelta(hours=5)), "item_name": "Old"}
    new = {"event_id": 2, "device_id": "d1", "date": iso(now - timedelta(minutes=5)), "item_name": "Eicar"}
    ioa = {"event_id": 3, "device_id": "d2", "date": iso(now - timedelta(minutes=1)), "rule_mitre": "x"}
    srv = wg_server({1: [new, old], 18: [ioa]})
    res = get("watchguard-epdr").pull(WG_CFG, WG_SEC, {}, client=srv.client())
    assert_lines(res)
    objs = [json.loads(x) for x in res.lines]
    assert [o["event_id"] for o in objs] == [2, 3]  # 'old' fora do retroativo de 60 min
    assert objs[0]["security_event_type"] == 1 and objs[1]["security_event_type_name"] == "Indicators of Attack"
    tok = srv.hits("/oauth/token")[0]
    assert tok.url.host == "api.deu.cloud.watchguard.com" and basic(tok) == "acc_ro:WGpass!"
    assert form(tok)["scope"] == ["api-access"]
    ev = srv.hits("/export/1")[0]
    assert ev.url.path == "/rest/endpoint-security/management/api/v1/accounts/WGC-1-123abc456/securityevents/1/export/1"
    assert ev.headers["WatchGuard-API-Key"] == "WGKEY-123" and ev.headers["Authorization"] == "Bearer wgtok"
    assert len(srv.hits("/export/1")) == 2
    assert len(res.cursor["seen"]) == 3
    # 2ª execução: mesmos eventos + 1 novo → só o novo
    new2 = {"event_id": 4, "device_id": "d1", "date": iso(now)}
    srv2 = wg_server({1: [new, old, new2], 18: [ioa]})
    res2 = get("watchguard-epdr").pull(WG_CFG, WG_SEC, res.cursor, client=srv2.client())
    assert [json.loads(x)["event_id"] for x in res2.lines] == [4]


def test_watchguard_cap_note_and_errors():
    evs = [{"event_id": i, "date": iso(NOW())} for i in range(3000)]
    res = get("watchguard-epdr").pull(dict(WG_CFG, event_types="1"), WG_SEC, {}, client=wg_server({1: evs}).client())
    assert "3000" in res.note and len(res.lines) == 3000
    srv = Server({("POST", "/oauth/token"): lambda r: httpx.Response(401)})
    with pytest.raises(ConnectorError, match="HTTP 401"):
        get("watchguard-epdr").test(WG_CFG, WG_SEC, client=srv.client())
    with pytest.raises(ConnectorError, match="1 a 19"):
        get("watchguard-epdr").pull(dict(WG_CFG, event_types="99"), WG_SEC, {}, client=srv.client())


def test_watchguard_429_retry(no_sleep):
    n = {"c": 0}

    def tok(req):
        n["c"] += 1
        return httpx.Response(429, headers={"Retry-After": "2"}) if n["c"] == 1 else httpx.Response(200, json={"access_token": "t"})
    srv = Server({("POST", "/oauth/token"): tok, ("GET", "/export/1"): lambda r: {"data": []}})
    get("watchguard-epdr").pull(WG_CFG, WG_SEC, {}, client=srv.client())
    assert no_sleep == [2.0]


# ---------------------------------------------------------------------------------------------------------------------
# Axur
# ---------------------------------------------------------------------------------------------------------------------
AX_SEC = {"api_key": "AXUR-KEY-xyz"}


def ax_ticket(key, dt):
    return {"ticket": {"ticketKey": key, "last-update.date": dt.strftime("%Y-%m-%dT%H:%M:%SZ"), "customerKey": "ACME"},
            "detection": {"type": "phishing", "prediction.risk": "0.58"}}


def test_axur_pagination_and_cursor(monkeypatch):
    import app.engine.connectors.axur as ax
    monkeypatch.setattr(ax, "PAGE", 2)
    t0 = (NOW() - timedelta(seconds=40)).replace(microsecond=0)
    tickets = [ax_ticket(f"k{i}", t0 + timedelta(seconds=i)) for i in range(3)]

    def search(req):
        q = parse_qs(req.url.query.decode())
        page = int(q["page"][0])
        return {"tickets": tickets[(page - 1) * 2: page * 2], "pageable": {"pageNumber": page, "pageSize": 2, "total": 3}}
    srv = Server({("GET", "/tickets-api/tickets"): search})
    cfg = {"customer": "ACME", "extra_query": "current.type=phishing&page=9"}
    res = get("axur").pull(cfg, AX_SEC, {}, client=srv.client())
    assert_lines(res)
    assert [json.loads(x)["ticket"]["ticketKey"] for x in res.lines] == ["k0", "k1", "k2"]
    q = parse_qs(srv.calls[0].url.query.decode())
    assert srv.calls[0].url.path == "/gateway/1.0/api/tickets-api/tickets"
    assert q["sortBy"] == ["ticket.last-update.date"] and q["order"] == ["asc"] and q["timezone"] == ["Z"]
    assert q["ticket.customer"] == ["ACME"] and q["current.type"] == ["phishing"] and q["page"] == ["1"]
    since = datetime.strptime(q["ticket.last-update.date"][0][3:], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    assert abs((since - (NOW() - timedelta(minutes=60))).total_seconds()) < 5
    assert srv.calls[0].headers["Authorization"] == "Bearer AXUR-KEY-xyz"
    assert len(srv.calls) == 2
    # 2ª execução: ticket k2 atualizado de novo (mesmo ts) não repete; k3 novo entra
    srv2 = Server({("GET", "/tickets-api/tickets"): lambda r: {"tickets": [tickets[2], ax_ticket("k3", t0 + timedelta(seconds=9))],
                                                               "pageable": {"total": 2}}})
    res2 = get("axur").pull(cfg, AX_SEC, res.cursor, client=srv2.client())
    assert [json.loads(x)["ticket"]["ticketKey"] for x in res2.lines] == ["k3"]


def test_axur_401_and_test(no_sleep):
    srv = Server({("GET", "/tickets-api/tickets"): lambda r: httpx.Response(401, json={"message": "AXUR-KEY-xyz revoked"})})
    with pytest.raises(ConnectorError, match="Credenciais recusadas pelo Axur \\(HTTP 401\\)") as e:
        get("axur").pull({}, AX_SEC, {}, client=srv.client())
    assert "AXUR-KEY-xyz" not in str(e.value)
    srv = Server({("GET", "/tickets-api/tickets"): lambda r: httpx.Response(500, text="AXUR-KEY-xyz oops")})
    with pytest.raises(ConnectorError, match="HTTP 500") as e:
        get("axur").pull({}, AX_SEC, {}, client=srv.client())
    assert "AXUR-KEY-xyz" not in str(e.value) and len(srv.calls) == 3
    srv = Server({("GET", "/tickets-api/tickets"): lambda r: {"tickets": [], "pageable": {"total": 42}}})
    assert "42" in get("axur").test({}, AX_SEC, client=srv.client())


# ---------------------------------------------------------------------------------------------------------------------
# Tenable
# ---------------------------------------------------------------------------------------------------------------------
TN_SEC = {"access_key": "AK123", "secret_key": "SK456"}


def tn_finding(i):
    return {"asset": {"uuid": f"a{i}"}, "plugin": {"id": 1000 + i}, "severity": "high", "state": "OPEN",
            "last_found": "2026-10-08T00:00:00Z"}


def test_tenable_vm_export_flow():
    state = {"status": "PROCESSING", "chunks": [1]}
    srv = Server({
        ("POST", "/vulns/export"): lambda r: {"export_uuid": "exp-1"},
        ("GET", "/vulns/export/exp-1/status"): lambda r: {"status": state["status"], "chunks_available": state["chunks"],
                                                          "total_chunks": 2},
        ("GET", "/vulns/export/exp-1/chunks/1"): lambda r: [tn_finding(1), tn_finding(2)],
        ("GET", "/vulns/export/exp-1/chunks/2"): lambda r: [tn_finding(3)],
    })
    tn = get("tenable")
    r1 = tn.pull({}, TN_SEC, {}, client=srv.client())
    assert_lines(r1)
    assert len(r1.lines) == 2 and r1.cursor["job"]["uuid"] == "exp-1" and r1.cursor["job"]["done"] == [1]
    body = json.loads(srv.hits("/vulns/export")[0].content)
    assert body["filters"]["state"] == ["OPEN", "REOPENED", "FIXED"]
    assert body["filters"]["severity"] == ["low", "medium", "high", "critical"]
    assert abs(body["filters"]["since"] - (NOW() - timedelta(minutes=1440)).timestamp()) < 5
    assert srv.calls[0].headers["X-ApiKeys"] == "accessKey=AK123;secretKey=SK456"
    state.update(status="FINISHED", chunks=[1, 2])
    r2 = tn.pull({}, TN_SEC, r1.cursor, client=srv.client())
    assert [json.loads(x)["asset"]["uuid"] for x in r2.lines] == ["a3"]
    assert len(srv.hits("/chunks/1")) == 1 and "job" not in r2.cursor
    assert r2.cursor["since"] == r1.cursor["job"]["created"]
    assert len(srv.hits("/vulns/export")) == 1  # nenhum novo export criado na 2ª chamada


def test_tenable_vm_partial_chunk(monkeypatch):
    import app.engine.connectors.tenable as tnm
    monkeypatch.setattr(tnm, "MAX_OBJECTS", 2)
    srv = Server({
        ("POST", "/vulns/export"): lambda r: {"export_uuid": "e"},
        ("GET", "/vulns/export/e/status"): lambda r: {"status": "FINISHED", "chunks_available": [1]},
        ("GET", "/vulns/export/e/chunks/1"): lambda r: [tn_finding(i) for i in range(3)],
    })
    r1 = get("tenable").pull({}, TN_SEC, {}, client=srv.client())
    assert r1.more and len(r1.lines) == 2 and r1.cursor["job"]["partial"] == [1, 2]
    r2 = get("tenable").pull({}, TN_SEC, r1.cursor, client=srv.client())
    assert [json.loads(x)["asset"]["uuid"] for x in r2.lines] == ["a2"] and not r2.more and "job" not in r2.cursor


def test_tenable_errors(no_sleep):
    srv = Server({("POST", "/vulns/export"): lambda r: httpx.Response(409, json={"active_job_id": "x"})})
    with pytest.raises(ConnectorError, match="409"):
        get("tenable").pull({}, TN_SEC, {}, client=srv.client())
    srv = Server({("GET", "/session"): lambda r: httpx.Response(401)})
    with pytest.raises(ConnectorError, match="Credenciais recusadas pelo Tenable \\(HTTP 401\\)"):
        get("tenable").test({}, TN_SEC, client=srv.client())
    n = {"c": 0}

    def sess(req):
        n["c"] += 1
        return httpx.Response(429, headers={"retry-after": "3"}) if n["c"] < 3 else httpx.Response(200, json={"username": "api@trust"})
    srv = Server({("GET", "/session"): sess})
    assert "api@trust" in get("tenable").test({}, TN_SEC, client=srv.client())
    assert no_sleep == [3.0, 3.0]


def test_tenable_sc_analysis():
    rows = [{"pluginID": str(i), "ip": "10.0.0.1", "lastSeen": "1751396645"} for i in range(3)]

    def analysis(req):
        b = json.loads(req.content)
        page = rows[b["startOffset"]:b["endOffset"]]
        return {"type": "regular", "response": {"totalRecords": str(len(rows)), "returnedRecords": len(page),
                                                "results": page}, "error_code": 0}
    srv = Server({("POST", "/rest/analysis"): analysis,
                  ("GET", "/rest/currentUser"): lambda r: {"response": {"username": "svc"}}})
    cfg = {"platform": "sc", "base_url": "sc.cliente.com.br"}
    assert "svc" in get("tenable").test(cfg, TN_SEC, client=srv.client())
    res = get("tenable").pull(cfg, TN_SEC, {}, client=srv.client())
    assert_lines(res) is None and len(res.lines) == 3
    r = srv.hits("/rest/analysis")[0]
    assert r.url.host == "sc.cliente.com.br" and r.headers["x-apikey"] == "accesskey=AK123; secretkey=SK456;"
    b = json.loads(r.content)
    assert b["query"]["tool"] == "vulndetails" and b["query"]["filters"][0]["filterName"] == "lastSeen"
    assert res.cursor["since"] > int((NOW() - timedelta(minutes=1)).timestamp())
    with pytest.raises(ConnectorError, match="URL do Tenable Security Center"):
        get("tenable").pull({"platform": "sc"}, TN_SEC, {}, client=srv.client())


def test_axur_page_guard(monkeypatch):
    import app.engine.connectors.axur as ax
    monkeypatch.setattr(ax, "PAGE", 2)
    monkeypatch.setattr(ax, "MAX_OBJECTS", 10)
    t = NOW()
    srv = Server({("GET", "/tickets-api/tickets"): lambda r: {"tickets": [ax_ticket("a", t), ax_ticket("b", t)]}})
    res = get("axur").pull({}, AX_SEC, {}, client=srv.client())
    assert res.more and len(res.lines) == 2
