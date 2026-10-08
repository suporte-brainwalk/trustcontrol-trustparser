"""Destinos de saída por tenant (SecOps, Wazuh, QRadar, syslog, webhook): validação, segredos e teste de conexão."""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

from sqlalchemy import func, select

from ..db import Session, utcnow
from ..engine import senders
from ..models import Destination, Source, Tenant
from . import catalog, secrets_box
from .changes import Conflict, Outcome, ServiceError, clean, diff


def get_destination(did: int, tenant_id: int | None = None) -> Destination:
    d = Session.get(Destination, did)
    if d is None or (tenant_id is not None and d.tenant_id != tenant_id):
        raise ServiceError("Destino não encontrado.", 404)
    return d


def _check_host(host: str):
    """Destino não pode apontar para a rede interna do servidor (evita uso do Trust Parser como ponte)."""
    host = (host or "").strip()
    if not host:
        raise ServiceError("Informe o endereço do destino.")
    try:
        infos = socket.getaddrinfo(host, None)
        addrs = {i[4][0] for i in infos}
    except socket.gaierror:
        addrs = set()
    for a in addrs:
        ip = ipaddress.ip_address(a)
        if ip.is_loopback or ip.is_link_local or (ip.is_private and str(ip).startswith(("172.", "127."))):
            raise ServiceError(f"O endereço {host} aponta para a rede interna do servidor ({a}); use um endereço do destino.")


def _clean_config(kind: str, config: dict) -> dict:
    spec = senders.KINDS.get(kind)
    if spec is None:
        raise ServiceError("Tipo de destino inválido.")
    out = {}
    for f in spec["fields"]:
        v = (config or {}).get(f.name)
        v = f.default if v in (None, "") else v
        if f.required and (v is None or str(v).strip() == ""):
            raise ServiceError(f"Preencha “{f.label}”.")
        if v in (None, ""):
            continue
        v = str(v).strip() if f.kind != "textarea" else str(v).strip()[:20000]
        if f.kind == "select" and v not in {o[0] for o in f.options}:
            raise ServiceError(f"Valor inválido em “{f.label}”.")
        if f.kind == "number":
            try:
                n = int(v)
            except ValueError as e:
                raise ServiceError(f"“{f.label}” precisa ser um número.") from e
            if not 1 <= n <= 65535:
                raise ServiceError(f"“{f.label}” fora do intervalo 1–65535.")
            v = str(n)
        out[f.name] = v[:20000]
    if kind in ("wazuh", "qradar", "syslog"):
        _check_host(out["host"])
    if kind == "webhook":
        u = urlsplit(out["url"])
        if u.scheme != "https" or not u.hostname:
            raise ServiceError("A URL do webhook precisa ser https://…")
        _check_host(u.hostname)
    if kind == "secops_chronicle":
        if out.get("endpoint") and not out["endpoint"].startswith("https://"):
            raise ServiceError("O endpoint precisa começar com https://")
    return out


def _check_format(kind: str, fmt: str) -> str:
    spec = senders.KINDS[kind]
    allowed = spec["formats"]
    fmt = fmt or spec["default_format"]
    if allowed is not None and fmt not in allowed:
        raise ServiceError(f"Formato não aceito por este destino (use {', '.join(allowed)}).")
    if fmt not in dict(catalog.output_choices()):
        raise ServiceError("Formato de saída desconhecido.")
    return fmt


def _filters(tenant_id: int, filters: dict | None) -> dict:
    f = {}
    ids = [int(x) for x in (filters or {}).get("source_ids") or [] if str(x).strip()]
    if ids:
        valid = {i for (i,) in Session.execute(select(Source.id).where(Source.tenant_id == tenant_id, Source.id.in_(ids)))}
        if set(ids) - valid:
            raise ServiceError("Filtro com fonte de outro tenant ou inexistente.")
        f["source_ids"] = sorted(valid)
    ms = (filters or {}).get("min_severity_id")
    if ms not in (None, ""):
        ms = int(ms)
        if not 0 <= ms <= 6:
            raise ServiceError("Severidade mínima deve ficar entre 0 e 6.")
        if ms:
            f["min_severity_id"] = ms
    cls = [int(x) for x in (filters or {}).get("class_uids") or [] if str(x).strip()]
    if cls:
        f["class_uids"] = sorted(set(cls))
    return f


def _snap(d: Destination) -> dict:
    return dict(name=d.name, kind=d.kind, format=d.format, config={k: v for k, v in d.config.items() if k != "ca_pem"},
                filters=d.filters, include_unparsed=d.include_unparsed, active=d.active, batch_size=d.batch_size)


def create_destination(tenant: Tenant, *, name, kind, format=None, config=None, secrets=None, filters=None,
                       include_unparsed=False, active=True, by="") -> Outcome:
    name = clean(name)
    if not name:
        raise ServiceError("Informe o nome do destino.")
    if Session.execute(select(Destination.id).where(Destination.tenant_id == tenant.id, func.lower(Destination.name) == name.lower())).first():
        raise Conflict("Já existe um destino com esse nome neste tenant.")
    cfg = _clean_config(kind, config or {})
    fmt = _check_format(kind, format)
    d = Destination(tenant_id=tenant.id, name=name, kind=kind, format=fmt, config=cfg, filters=_filters(tenant.id, filters),
                    include_unparsed=bool(include_unparsed), active=bool(active))
    Session.add(d)
    Session.flush()
    _set_secrets(d, secrets or {}, by, creating=True)
    return Outcome(message=f"Destino “{d.name}” criado.", obj=d, tenant_id=tenant.id,
                   audit=[("destination.created", d.name, {"kind": kind, "format": fmt})])


def _set_secrets(d: Destination, secrets: dict, by: str, creating=False):
    spec = senders.KINDS[d.kind]
    names = {f.name for f in spec["secrets"]}
    given = {k: v for k, v in (secrets or {}).items() if v not in (None, "")}
    bad = set(given) - names
    if bad:
        raise ServiceError(f"Segredo desconhecido para este destino: {', '.join(sorted(bad))}")
    if "service_account_json" in given:
        import json
        try:
            info = json.loads(given["service_account_json"])
            assert info.get("type") == "service_account" and info.get("private_key") and info.get("client_email")
        except (ValueError, AssertionError) as e:
            raise ServiceError("O JSON informado não é uma conta de serviço do Google Cloud válida.") from e
    if given:
        d.secret_enc = secrets_box.merge(d.secret_enc, f"dest:{d.id}", given)
        d.secret_set_at, d.secret_set_by = utcnow(), by
    elif creating and any(f.required for f in spec["secrets"]):
        raise ServiceError("Informe as credenciais do destino.")


def update_destination(d: Destination, *, by="", **kw) -> Outcome:
    before = _snap(d)
    if "name" in kw and kw["name"] is not None:
        name = clean(kw["name"])
        if not name:
            raise ServiceError("Informe o nome do destino.")
        if Session.execute(select(Destination.id).where(Destination.tenant_id == d.tenant_id, Destination.id != d.id,
                                                        func.lower(Destination.name) == name.lower())).first():
            raise Conflict("Já existe um destino com esse nome neste tenant.")
        d.name = name
    if kw.get("config") is not None:
        merged = {**d.config, **{k: v for k, v in kw["config"].items() if v is not None}}
        d.config = _clean_config(d.kind, merged)
    if kw.get("format"):
        d.format = _check_format(d.kind, kw["format"])
    if kw.get("filters") is not None:
        d.filters = _filters(d.tenant_id, kw["filters"])
    for k in ("include_unparsed", "active"):
        if kw.get(k) is not None:
            setattr(d, k, bool(kw[k]))
    if kw.get("batch_size"):
        d.batch_size = max(1, min(1000, int(kw["batch_size"])))
    secret_changed = bool(kw.get("secrets") and any(v for v in kw["secrets"].values()))
    if secret_changed:
        _set_secrets(d, kw["secrets"], by)
    if d.active and before["active"] is False:
        d.paused_until, d.consecutive_failures = None, 0
    changes = diff(before, _snap(d))
    if secret_changed:
        changes["credenciais"] = ["(oculto)", "(atualizado)"]
    return Outcome(message=f"Destino “{d.name}” atualizado.", obj=d, tenant_id=d.tenant_id,
                   audit=[("destination.updated", d.name, changes)] if changes else [])


def delete_destination(d: Destination) -> Outcome:
    name, tid = d.name, d.tenant_id
    Session.delete(d)
    return Outcome(message=f"Destino “{name}” excluído.", tenant_id=tid, audit=[("destination.deleted", name, {})])


def test_destination(d: Destination) -> tuple[bool, str]:
    """Abre conexão/autentica e envia 1 evento de teste. Devolve (ok, mensagem amigável)."""
    try:
        sec = secrets_box.open_(d.secret_enc, f"dest:{d.id}")
    except secrets_box.SecretsError as e:
        return False, str(e)
    tenant = Session.get(Tenant, d.tenant_id)
    try:
        msg = senders.test_destination(d.kind, f"test:{d.id}", d.config, sec, d.format, tenant.name, catalog.output_spec(d.format))
        d.status, d.last_ok_at, d.last_error = "ok", utcnow(), ""
        return True, msg
    except senders.SendError as e:
        d.status, d.last_error, d.last_error_at = "err", str(e)[:1000], utcnow()
        return False, str(e)
    except Exception as e:  # noqa: BLE001 — qualquer erro vira mensagem, nunca 500
        d.status, d.last_error, d.last_error_at = "err", str(e)[:1000], utcnow()
        return False, f"Falha inesperada: {str(e)[:300]}"
    finally:
        senders.close(f"test:{d.id}")
