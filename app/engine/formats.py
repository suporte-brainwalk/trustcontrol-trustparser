"""Formatos de saída: evento canônico (OCSF) → UDM (Google SecOps), JSON para Wazuh, CEF, LEEF 2.0, OCSF JSON, CSV e bruto.

Todos são determinísticos. Formatos novos criados no Estúdio IA usam um spec declarativo (serializer + map), executado em
`custom()` pelo mesmo motor de expressões do parsing.
"""
from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime

from . import dsl, paths

OCSF_VERSION = "1.3.0"
UDM_SEVERITY = {0: "UNKNOWN_SEVERITY", 1: "INFORMATIONAL", 2: "LOW", 3: "MEDIUM", 4: "HIGH", 5: "CRITICAL", 6: "CRITICAL"}
UDM_ACTION = {"Allowed": "ALLOW", "Blocked": "BLOCK", "Quarantined": "QUARANTINE", "Denied": "BLOCK", "Deleted": "BLOCK",
              "Isolated": "QUARANTINE", "Corrected": "ALLOW_WITH_MODIFICATION", "Detected": "UNKNOWN_ACTION"}
LOGON_MECHANISM = {2: "INTERACTIVE", 3: "NETWORK", 4: "BATCH", 5: "SERVICE", 7: "UNLOCK", 8: "NETWORK_CLEAR_TEXT",
                   9: "NEW_CREDENTIALS", 10: "REMOTE_INTERACTIVE", 11: "CACHED_INTERACTIVE"}

BUILTIN = {
    "udm": "Google SecOps · UDM (JSON)",
    "wazuh_json": "Wazuh · JSON",
    "ocsf_json": "OCSF · JSON",
    "cef": "CEF (ArcSight / genérico)",
    "leef": "LEEF 2.0 (QRadar)",
    "csv": "CSV (planilha)",
    "raw": "Linha original (bruto)",
}
FILE_EXT = {"udm": "jsonl", "wazuh_json": "jsonl", "ocsf_json": "jsonl", "cef": "txt", "leef": "txt", "csv": "csv", "raw": "txt"}


def _g(ev, p, default=None):
    return paths.get(ev, p, default)


def _first(*vals):
    for v in vals:
        if not paths.empty(v):
            return v
    return None


def _list(v):
    if paths.empty(v):
        return []
    return v if isinstance(v, list) else [v]


# ------------------------------------------------------------------------------------------------ UDM
def _udm_user(u: dict | None) -> dict:
    if not u:
        return {}
    out = {"userid": u.get("name"), "windows_sid": u.get("uid") if str(u.get("uid", "")).startswith("S-1-") else None,
           "product_object_id": u.get("uid") if not str(u.get("uid", "")).startswith("S-1-") else None,
           "user_display_name": _first(u.get("display_name"), u.get("full_name")),
           "email_addresses": _list(u.get("email_addr"))}
    return paths.prune(out)


def _udm_file(f: dict | None) -> dict:
    if not f:
        return {}
    out = {"full_path": f.get("path"), "size": str(f["size"]) if f.get("size") is not None else None}
    for h in f.get("hashes") or []:
        alg = str(h.get("algorithm", "")).upper().replace("-", "")
        if alg in ("SHA256", "SHA1", "MD5"):
            out[alg.lower()] = h.get("value")
    if f.get("signer"):
        out["signature_info"] = {"sigcheck": {"signers": [{"name": f["signer"]}]}}
    return paths.prune(out)


def _udm_process(p: dict | None) -> dict:
    if not p:
        return {}
    out = {"pid": str(p["pid"]) if p.get("pid") is not None else None, "command_line": p.get("cmd_line"),
           "file": _udm_file(p.get("file")) or ({"full_path": p.get("path")} if p.get("path") else None)}
    if p.get("name") and not out.get("file"):
        out["file"] = {"full_path": p["name"]}
    return paths.prune(out)


def udm_event_type(ev: dict) -> str:
    cls, act = ev.get("class_uid"), ev.get("activity_id")
    if cls == 4002:
        return "NETWORK_HTTP"
    if cls == 4001:
        return "NETWORK_CONNECTION"
    if cls == 4003:
        return "NETWORK_DNS"
    if cls == 3002:
        return "USER_LOGOUT" if act == 2 else "USER_LOGIN"
    if cls == 3001:
        return {1: "USER_CREATION", 6: "USER_DELETION", 3: "USER_CHANGE_PASSWORD", 4: "USER_CHANGE_PASSWORD"}.get(act, "USER_UNCATEGORIZED")
    if cls == 3006:
        return {6: "GROUP_CREATION", 5: "GROUP_DELETION"}.get(act, "GROUP_MODIFICATION")
    if cls == 1007:
        return {1: "PROCESS_LAUNCH", 2: "PROCESS_TERMINATION"}.get(act, "PROCESS_UNCATEGORIZED")
    if cls == 1001:
        return {1: "FILE_CREATION", 2: "FILE_READ", 3: "FILE_MODIFICATION", 4: "FILE_DELETION"}.get(act, "FILE_UNCATEGORIZED")
    if cls == 2004:
        return "SCAN_FILE" if ev.get("malware") or ev.get("file") else "STATUS_UPDATE"
    if cls == 1008:
        return "SYSTEM_AUDIT_LOG_UNCATEGORIZED"
    if cls == 2002 or cls == 2001:
        return "SCAN_VULN_HOST"
    return "GENERIC_EVENT"


def to_udm(ev: dict, raw: str = "", ctx: dict | None = None) -> dict:
    """Evento canônico → UDM (proto3 JSON). Se faltar o mínimo exigido pelo tipo, cai para GENERIC_EVENT."""
    ctx = ctx or {}
    et = udm_event_type(ev)
    md = {"event_timestamp": ev.get("time"), "event_type": et,
          "vendor_name": _g(ev, "metadata.product.vendor_name"), "product_name": _g(ev, "metadata.product.name"),
          "product_version": _g(ev, "metadata.product.version"),
          "product_event_type": str(_g(ev, "metadata.event_code") or "")[:64] or None,
          "product_log_id": _g(ev, "metadata.uid"), "description": ev.get("message"),
          "collected_timestamp": _g(ev, "metadata.logged_time")}
    dev = ev.get("device") or {}
    machine = paths.prune({"hostname": dev.get("hostname"), "ip": _list(dev.get("ips") or dev.get("ip")),
                           "asset_id": f"{_g(ev, 'metadata.product.vendor_name') or 'device'}:{dev['uid']}" if dev.get("uid") else None,
                           "administrative_domain": _g(ev, "actor.user.domain")})
    principal, target, network, sec = {}, {}, {}, {}
    src, dst = ev.get("src_endpoint") or {}, ev.get("dst_endpoint") or {}
    if et == "NETWORK_HTTP":
        if src:
            principal = paths.prune({"ip": _list(src.get("ip")), "port": src.get("port"), "hostname": src.get("hostname")})
        if machine and not principal.get("ip"):
            principal = {**machine, **principal}
        elif machine:
            principal.setdefault("hostname", machine.get("hostname"))
            principal.setdefault("asset_id", machine.get("asset_id"))
        url = _g(ev, "http_request.url") or {}
        target = paths.prune({"hostname": _first(url.get("hostname"), dst.get("hostname")), "ip": _list(dst.get("ip")),
                              "port": dst.get("port"), "url": url.get("url_string")})
        network = paths.prune({"ip_protocol": "TCP", "application_protocol": "HTTPS" if (url.get("scheme") == "https" or ev.get("tls")) else "HTTP",
                               "http": {"method": _g(ev, "http_request.http_method"), "response_code": _g(ev, "http_response.code"),
                                        "user_agent": _g(ev, "http_request.user_agent"), "referral_url": _g(ev, "http_request.referrer")},
                               "received_bytes": str(_g(ev, "http_response.length")) if _g(ev, "http_response.length") is not None else None,
                               "tls": {"version": _g(ev, "tls.version"), "cipher": _g(ev, "tls.cipher")}})
        cats = _g(ev, "http_request.url.categories")
        if cats:
            sec["category_details"] = _list(cats)
    elif et in ("USER_LOGIN", "USER_LOGOUT"):
        target = paths.prune({**machine, "user": _udm_user(ev.get("user"))})
        sip = src.get("ip") if src.get("ip") not in ("127.0.0.1", "::1", "0.0.0.0") else None
        if sip:  # login remoto: principal = máquina de origem; local: sem principal (guia UDM)
            principal = paths.prune({"ip": [sip], "port": src.get("port") or None, "hostname": src.get("hostname"),
                                     "user": _udm_user(_g(ev, "actor.user")), "process": _udm_process(_g(ev, "actor.process"))})
        lt = ev.get("logon_type_id")
        md["_extensions"] = {"auth": paths.prune({"type": "MACHINE", "mechanism": [LOGON_MECHANISM[lt]] if lt in LOGON_MECHANISM else ["MECHANISM_OTHER"]})}
        if ev.get("status") == "Failure":
            sec["category"] = ["AUTH_VIOLATION"]
            sec["action"] = ["BLOCK"]
        elif ev.get("status") == "Success":
            sec["action"] = ["ALLOW"]
    elif et.startswith("USER_") or et.startswith("GROUP_"):
        principal = paths.prune({**machine, "user": _udm_user(_g(ev, "actor.user"))})
        target = paths.prune({"user": _udm_user(ev.get("user")),
                              "group": paths.prune({"group_display_name": _g(ev, "group.name"), "windows_sid": _g(ev, "group.uid")})})
    elif et.startswith("PROCESS_"):
        principal = paths.prune({**machine, "user": _udm_user(_g(ev, "actor.user")), "process": _udm_process(_g(ev, "actor.process"))})
        target = paths.prune({"process": _udm_process(ev.get("process"))})
    elif et.startswith("FILE_") or et == "SCAN_FILE":
        principal = paths.prune({**machine, "user": _udm_user(_g(ev, "actor.user")), "process": _udm_process(_g(ev, "actor.process"))})
        target = paths.prune({**(machine if et == "SCAN_FILE" else {}), "file": _udm_file(ev.get("file"))})
        if ev.get("malware"):
            sec["category"] = ["SOFTWARE_MALICIOUS"]
            sec["threat_name"] = _g(ev, "malware.0.name")
    else:
        principal = paths.prune({**machine, "ip": _list(src.get("ip")) or machine.get("ip"), "hostname": _first(src.get("hostname"), machine.get("hostname")),
                                 "user": _udm_user(_g(ev, "actor.user"))})
        target = paths.prune({"hostname": dst.get("hostname"), "ip": _list(dst.get("ip")), "user": _udm_user(ev.get("user")),
                              "file": _udm_file(ev.get("file")), "process": _udm_process(ev.get("process"))})
    # resultado de segurança
    disp = _first(ev.get("disposition"), ev.get("action"))
    if disp and "action" not in sec:
        sec["action"] = [UDM_ACTION.get(disp, "UNKNOWN_ACTION")]
    if ev.get("severity_id") is not None and ev.get("class_uid") in (2004, 3002, 3001, 3006, 1007, 2002) or disp:
        sec["severity"] = UDM_SEVERITY.get(ev.get("severity_id"), "UNKNOWN_SEVERITY")
    sec["summary"] = _first(_g(ev, "finding_info.title"), ev.get("message") if (disp or ev.get("class_uid") == 2004) else None)
    sec["rule_name"] = _first(_g(ev, "rule.name"), _g(ev, "policy.name"))
    sec["rule_id"] = _g(ev, "rule.uid")
    sec["description"] = _first(ev.get("status_detail"), _g(ev, "finding_info.desc"))
    sec = paths.prune(sec)
    ext = md.pop("_extensions", None)
    udm = {"metadata": paths.prune(md), "principal": principal, "target": target, "network": network}
    if ext:
        udm["extensions"] = ext
    if sec:
        udm["security_result"] = [sec]
    obs = ev.get("observer") or {}
    proxy = ev.get("proxy_endpoint") or {}
    inter = []
    if proxy.get("ip"):
        inter.append({"ip": _list(proxy.get("ip"))})
    if obs.get("hostname"):
        udm["observer"] = {"hostname": obs["hostname"]}
    if inter:
        udm["intermediary"] = inter
    add = {}
    for k, v in paths.flatten(ev.get("unmapped") or {}).items():
        if not paths.empty(v):
            add[k[:120]] = str(v)[:2000]
    for k in ("policy.name", "policy.uid", "device.org.name", "device.logged_user", "status_code", "metadata.parser_case", "metadata.event_subtype"):
        v = _g(ev, k)
        if not paths.empty(v):
            add[k] = str(v)
    if ctx.get("tenant"):
        add["trustparser.tenant"] = ctx["tenant"]
    if add:
        udm["additional"] = add
    udm = paths.prune(udm)
    # mínimo por tipo (SecOps rejeita o lote se faltar): senão, GENERIC_EVENT
    ok = True
    p, t = udm.get("principal", {}), udm.get("target", {})
    if et == "NETWORK_HTTP":
        ok = bool(t.get("url")) and bool(t.get("hostname") or t.get("ip"))
    elif et == "NETWORK_CONNECTION":
        ok = bool(p) and bool(t)
    elif et in ("USER_LOGIN", "USER_LOGOUT"):
        ok = bool(t.get("user")) and bool(p or t.get("hostname") or t.get("ip") or t.get("asset_id"))
    elif et.startswith("USER_"):
        ok = bool(t.get("user")) and bool(p)
    elif et.startswith("GROUP_"):
        ok = bool(p) and bool(t)
    elif et.startswith("PROCESS_"):
        ok = bool(p) and bool(t.get("process"))
    elif et == "SCAN_FILE":
        ok = bool(t.get("file")) and bool(t.get("hostname") or t.get("ip") or t.get("asset_id"))
    elif et.startswith("FILE_"):
        ok = bool(p) and bool(t.get("file"))
    elif et in ("STATUS_UPDATE", "SYSTEM_AUDIT_LOG_UNCATEGORIZED"):
        ok = bool(p.get("hostname") or p.get("ip") or p.get("asset_id"))
    if not ok and et != "GENERIC_EVENT":
        udm["metadata"]["event_type"] = "GENERIC_EVENT"
        udm.setdefault("additional", {})["trustparser.udm_type_original"] = et
    return udm


# ------------------------------------------------------------------------------------------------ Wazuh / OCSF
def to_ocsf(ev: dict, raw: str = "", ctx: dict | None = None) -> dict:
    out = dict(ev)
    md = dict(out.get("metadata") or {})
    md["version"] = OCSF_VERSION
    out["metadata"] = md
    if (ctx or {}).get("include_raw") and raw:
        out["raw_data"] = raw
    return out


def to_wazuh(ev: dict, raw: str = "", ctx: dict | None = None) -> dict:
    """JSON para o Wazuh. Tudo sob a chave "tp" (evita colisão com campos reservados do Wazuh 4.x: srcip, user, url, action…);
    o decoder trustparser (XML 4.x / YAML 5.x, baixados na tela) extrai o JSON depois do cabeçalho syslog."""
    ctx = ctx or {}
    return {"tp": paths.prune({
        "integration": "trustparser", "tenant": ctx.get("tenant"), "source": ctx.get("source"), "parser": ctx.get("parser"),
        "time": ev.get("time"), "vendor": _g(ev, "metadata.product.vendor_name"), "product": _g(ev, "metadata.product.name"),
        "event_code": _g(ev, "metadata.event_code"), "class": ev.get("class_name"), "class_uid": ev.get("class_uid"),
        "activity": ev.get("activity_name"), "severity": ev.get("severity"), "severity_id": ev.get("severity_id"),
        "status": ev.get("status"), "disposition": ev.get("disposition"), "message": ev.get("message"),
        "src_ip": _g(ev, "src_endpoint.ip"), "src_port": _g(ev, "src_endpoint.port"),
        "dst_ip": _g(ev, "dst_endpoint.ip"), "dst_port": _g(ev, "dst_endpoint.port"),
        "host": _first(_g(ev, "device.hostname"), _g(ev, "dst_endpoint.hostname")),
        "actor_user": _first(_g(ev, "actor.user.full_name"), _g(ev, "actor.user.name")), "target_user": _g(ev, "user.name"),
        "url": _g(ev, "http_request.url.url_string"), "http_status": _g(ev, "http_response.code"),
        "file": _first(_g(ev, "file.path"), _g(ev, "process.file.path")), "rule": _first(_g(ev, "rule.name"), _g(ev, "policy.name")),
        "details": _wazuh_details(ev),
    })}


def _wazuh_details(ev: dict) -> dict:
    """Demais campos achatados (o decoder JSON do Wazuh aceita ~256 campos por evento: limitamos a 150)."""
    skip = ("time", "message", "class_name", "class_uid", "severity", "severity_id", "status", "disposition", "activity_name")
    flat = {k: v for k, v in paths.flatten({k: v for k, v in ev.items() if k not in skip}).items() if not paths.empty(v)}
    return {k.replace(".", "_")[:80]: (str(v)[:1000] if isinstance(v, str) else v) for k, v in list(flat.items())[:150]}


# ------------------------------------------------------------------------------------------------ CEF / LEEF
def _epoch_ms(iso):
    try:
        return str(int(datetime.fromisoformat(str(iso).replace("Z", "+00:00")).timestamp() * 1000))
    except (TypeError, ValueError):
        return None


def _common_kv(ev: dict) -> list[tuple[str, object]]:
    return [("src", _g(ev, "src_endpoint.ip")), ("spt", _g(ev, "src_endpoint.port")), ("shost", _first(_g(ev, "src_endpoint.hostname"), _g(ev, "device.hostname"))),
            ("dst", _g(ev, "dst_endpoint.ip")), ("dpt", _g(ev, "dst_endpoint.port")), ("dhost", _first(_g(ev, "dst_endpoint.hostname"), _g(ev, "http_request.url.hostname"))),
            ("suser", _first(_g(ev, "actor.user.full_name"), _g(ev, "actor.user.name"))), ("duser", _g(ev, "user.name")),
            ("act", _first(ev.get("disposition"), ev.get("action"))), ("outcome", ev.get("status")),
            ("request", _g(ev, "http_request.url.url_string")), ("requestMethod", _g(ev, "http_request.http_method")),
            ("requestClientApplication", _g(ev, "http_request.user_agent")),
            ("fname", _first(_g(ev, "file.name"), _g(ev, "process.file.name"))), ("filePath", _first(_g(ev, "file.path"), _g(ev, "process.file.path"))),
            ("sproc", _g(ev, "actor.process.name")), ("cat", ev.get("class_name")), ("msg", ev.get("message")),
            ("deviceExternalId", _g(ev, "device.uid")), ("dvchost", _g(ev, "observer.hostname"))]


def _cef_esc_h(v) -> str:
    return str(v if v is not None else "").replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def _cef_esc_v(v) -> str:
    return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\r", " ").replace("\n", "\\n")


def to_cef(ev: dict, raw: str = "", ctx: dict | None = None) -> str:
    sev10 = {0: 0, 1: 1, 2: 3, 3: 5, 4: 8, 5: 10, 6: 10}.get(ev.get("severity_id") or 0, 0)
    head = ["CEF:0", _g(ev, "metadata.product.vendor_name") or "Unknown", _g(ev, "metadata.product.name") or "Unknown",
            _g(ev, "metadata.product.version") or "", _g(ev, "metadata.event_code") or ev.get("class_uid") or "0",
            ev.get("activity_name") or ev.get("class_name") or "Event", sev10]
    kv = [("rt", _epoch_ms(ev.get("time")))] + _common_kv(ev)
    ext = " ".join(f"{k}={_cef_esc_v(v)}" for k, v in kv if not paths.empty(v))
    labels = [("cs1Label", "tenant"), ("cs1", (ctx or {}).get("tenant")), ("cs2Label", "policy"), ("cs2", _g(ev, "policy.name")),
              ("cs3Label", "rule"), ("cs3", _g(ev, "rule.name"))]
    extra = []
    for i in range(0, len(labels), 2):
        if not paths.empty(labels[i + 1][1]):
            extra.append(f"{labels[i][0]}={_cef_esc_v(labels[i][1])} {labels[i + 1][0]}={_cef_esc_v(labels[i + 1][1])}")
    return "|".join(_cef_esc_h(h) for h in head) + "|" + " ".join([x for x in [ext] + extra if x])


def to_leef(ev: dict, raw: str = "", ctx: dict | None = None) -> str:
    head = ["LEEF:2.0", _g(ev, "metadata.product.vendor_name") or "Unknown", _g(ev, "metadata.product.name") or "Unknown",
            _g(ev, "metadata.product.version") or "1.0", _g(ev, "metadata.event_code") or ev.get("class_uid") or "0", "^"]
    kv = [("devTime", _epoch_ms(ev.get("time"))), ("devTimeFormat", None), ("sev", {0: 0, 1: 1, 2: 3, 3: 5, 4: 8, 5: 10}.get(ev.get("severity_id") or 0, 0)),
          ("src", _g(ev, "src_endpoint.ip")), ("srcPort", _g(ev, "src_endpoint.port")), ("dst", _g(ev, "dst_endpoint.ip")),
          ("dstPort", _g(ev, "dst_endpoint.port")), ("usrName", _first(_g(ev, "user.name"), _g(ev, "actor.user.name"))),
          ("identSrc", _g(ev, "src_endpoint.ip")), ("identHostName", _g(ev, "device.hostname")),
          ("action", _first(ev.get("disposition"), ev.get("action"))), ("cat", ev.get("class_name")),
          ("url", _g(ev, "http_request.url.url_string")), ("method", _g(ev, "http_request.http_method")),
          ("userAgent", _g(ev, "http_request.user_agent")), ("responseCode", _g(ev, "http_response.code")),
          ("dhost", _first(_g(ev, "dst_endpoint.hostname"), _g(ev, "http_request.url.hostname"))),
          ("fileName", _first(_g(ev, "file.name"), _g(ev, "process.file.name"))), ("filePath", _first(_g(ev, "file.path"), _g(ev, "process.file.path"))),
          ("policy", _g(ev, "policy.name")), ("rule", _g(ev, "rule.name")), ("msg", ev.get("message")),
          ("tenant", (ctx or {}).get("tenant"))]
    body = "^".join(f"{k}={str(v).replace('^', ' ').replace(chr(10), ' ')}" for k, v in kv if not paths.empty(v))
    return "|".join(str(h).replace("|", "/") for h in head) + "|" + body


# ------------------------------------------------------------------------------------------------ CSV / bruto
CSV_COLUMNS = ["time", "tenant", "source", "class", "activity", "severity", "status", "disposition", "src_ip", "dst",
               "device", "user", "actor_user", "url", "file", "message"]


def csv_row(ev: dict, raw: str = "", ctx: dict | None = None) -> list:
    ctx = ctx or {}
    return [ev.get("time"), ctx.get("tenant"), ctx.get("source"), ev.get("class_name"), ev.get("activity_name"), ev.get("severity"),
            ev.get("status"), ev.get("disposition"), _g(ev, "src_endpoint.ip"),
            _first(_g(ev, "dst_endpoint.hostname"), _g(ev, "dst_endpoint.ip")), _g(ev, "device.hostname"),
            _g(ev, "user.name"), _first(_g(ev, "actor.user.full_name"), _g(ev, "actor.user.name")),
            _g(ev, "http_request.url.url_string"), _first(_g(ev, "file.path"), _g(ev, "process.file.path")), ev.get("message")]


def to_csv_line(ev: dict, raw: str = "", ctx: dict | None = None) -> str:
    buf = io.StringIO()
    csv.writer(buf).writerow(["" if v is None else v for v in csv_row(ev, raw, ctx)])
    return buf.getvalue().rstrip("\r\n")


def csv_header() -> str:
    return ",".join(CSV_COLUMNS)


# ------------------------------------------------------------------------------------------------ formatos do Estúdio
def custom(spec: dict, ev: dict, raw: str = "", ctx: dict | None = None):
    """Formato declarativo: {"serializer": "json|kv|template|cef|leef|csv", "map": {campo: expr}, "template": "..."}.
    As expressões leem do contexto {"e": evento canônico, "raw": linha original, "ctx": tenant/fonte}."""
    c = {"e": ev, "raw": raw, "ctx": ctx or {}}
    ser = spec.get("serializer", "json")
    if ser == "template":
        return dsl.evaluate({"template": spec.get("template", "")}, c)
    values = {}
    for k, expr in (spec.get("map") or {}).items():
        v = dsl.evaluate(expr, c)
        if not paths.empty(v):
            paths.set_(values, k, v) if ser == "json" else values.__setitem__(k, v)
    if ser == "json":
        return values
    if ser == "kv":
        sep, kvsep = spec.get("pair_sep", " "), spec.get("kv_sep", "=")
        return sep.join(f"{k}{kvsep}{_quote(v)}" for k, v in values.items())
    if ser == "csv":
        buf = io.StringIO()
        csv.writer(buf, delimiter=spec.get("delimiter", ",")).writerow([values.get(k, "") for k in spec.get("columns", list(values))])
        return buf.getvalue().rstrip("\r\n")
    if ser in ("cef", "leef"):
        h = spec.get("header", {})
        if ser == "cef":
            head = ["CEF:0", h.get("vendor", ""), h.get("product", ""), h.get("version", ""),
                    dsl.evaluate(h.get("event_id", "e.metadata.event_code"), c) or "0", dsl.evaluate(h.get("name", "e.class_name"), c) or "Event",
                    dsl.evaluate(h.get("severity", {"const": 0}), c)]
            return "|".join(_cef_esc_h(x) for x in head) + "|" + " ".join(f"{k}={_cef_esc_v(v)}" for k, v in values.items())
        head = ["LEEF:2.0", h.get("vendor", ""), h.get("product", ""), h.get("version", "1.0"),
                dsl.evaluate(h.get("event_id", "e.metadata.event_code"), c) or "0", "^"]
        return "|".join(str(x) for x in head) + "|" + "^".join(f"{k}={v}" for k, v in values.items())
    raise dsl.SpecError(f"serializer desconhecido: {ser}")


def _quote(v) -> str:
    s = str(v)
    return f'"{s}"' if re.search(r'[\s"=]', s) else s


FUNCS = {"udm": to_udm, "wazuh_json": to_wazuh, "ocsf_json": to_ocsf, "cef": to_cef, "leef": to_leef, "csv": to_csv_line}


def render(fmt: str, ev: dict | None, raw: str, ctx: dict | None = None, spec: dict | None = None):
    """Um evento no formato pedido. Para 'raw' (ou evento não reconhecido) devolve a linha original."""
    if fmt == "raw" or ev is None:
        return raw
    if spec is not None:
        return custom(spec, ev, raw, ctx)
    fn = FUNCS.get(fmt)
    if fn is None:
        raise dsl.SpecError(f"formato desconhecido: {fmt}")
    return fn(ev, raw, ctx)


def to_line(obj) -> str:
    return obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str)
