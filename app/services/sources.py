"""Fontes (syslog, upload, conector de API) e IPs liberados no firewall do syslog. Mesmas regras para a tela e a API."""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime

from sqlalchemy import func, select

from ..db import Session, utcnow
from ..models import AllowedIP, Parser, Source, Tenant
from . import secrets_box
from .changes import Conflict, Outcome, ServiceError, clean, diff

TRANSPORTS = {"syslog": "Syslog (TLS, TCP ou UDP)", "upload": "Upload de arquivo", "api": "Conector de API (coleta)"}
UNPARSED = {"keep": "Guardar em “Não reconhecidos” (não envia)", "forward_raw": "Encaminhar a linha bruta com etiqueta",
            "drop": "Descartar"}
PROTOCOLS = {"tls": "Syslog TLS (6514/TCP)", "tcp": "Syslog TCP sem TLS (514/TCP)", "udp": "Syslog UDP sem TLS (514/UDP)"}
MAX_PREFIX_V4 = 16  # faixas maiores que /16 exigem confirmação explícita


def _snap(s: Source) -> dict:
    return dict(name=s.name, transport=s.transport, parser_id=s.parser_id, match_hostname=s.match_hostname,
                unparsed_policy=s.unparsed_policy, active=s.active, connector=s.connector, interval_s=s.interval_s,
                silence_alert_minutes=s.silence_alert_minutes)


def get_source(sid: int, tenant_id: int | None = None) -> Source:
    s = Session.get(Source, sid)
    if s is None or (tenant_id is not None and s.tenant_id != tenant_id):
        raise ServiceError("Fonte não encontrada.", 404)
    return s


def _validate(tenant: Tenant, *, name, transport, parser_id, match_hostname, unparsed_policy, exclude_id=None):
    name = clean(name)
    if not name:
        raise ServiceError("Informe o nome da fonte.")
    if transport not in TRANSPORTS:
        raise ServiceError("Tipo de fonte inválido (syslog, upload ou api).")
    if unparsed_policy not in UNPARSED:
        raise ServiceError("Política de linhas não reconhecidas inválida (keep, forward_raw ou drop).")
    if parser_id:
        p = Session.get(Parser, int(parser_id))
        if p is None or p.kind != "input":
            raise ServiceError("Parser inválido.")
    if match_hostname:
        try:
            re.compile(match_hostname)
        except re.error as e:
            raise ServiceError(f"Expressão de hostname inválida: {e}") from e
    q = select(Source.id).where(Source.tenant_id == tenant.id, func.lower(Source.name) == name.lower())
    if exclude_id:
        q = q.where(Source.id != exclude_id)
    if Session.execute(q).first():
        raise Conflict("Já existe uma fonte com esse nome neste tenant.")
    return name


def create_source(tenant: Tenant, *, name, transport="syslog", parser_id=None, match_hostname="", unparsed_policy="keep",
                  note="", connector="", connector_config=None, secrets=None, interval_s=None, silence_alert_minutes=0,
                  by="", defer_secrets=False) -> Outcome:
    name = _validate(tenant, name=name, transport=transport, parser_id=parser_id, match_hostname=match_hostname,
                     unparsed_policy=unparsed_policy)
    s = Source(tenant_id=tenant.id, name=name, transport=transport, parser_id=int(parser_id) if parser_id else None,
               match_hostname=(match_hostname or "").strip()[:200], unparsed_policy=unparsed_policy, note=(note or "")[:2000],
               silence_alert_minutes=max(0, int(silence_alert_minutes or 0)))
    Session.add(s)
    Session.flush()
    if transport == "api":
        _set_connector(s, connector, connector_config or {}, secrets or {}, interval_s, by, defer_secrets=defer_secrets)
        if defer_secrets and s.secret_enc is None:
            s.active = False  # sem credenciais: fica inativa até um administrador cadastrar e ativar
    return Outcome(message=f"Fonte “{s.name}” criada.", obj=s, tenant_id=tenant.id,
                   audit=[("source.created", s.name, {"transport": transport, "parser_id": s.parser_id, "connector": s.connector})])


def _set_connector(s: Source, connector, config: dict, secrets: dict, interval_s, by: str, defer_secrets: bool = False):
    from ..engine import connectors
    try:
        c = connectors.get(connector) if connector else None
    except connectors.ConnectorError:
        c = None
    if c is None:
        raise ServiceError("Escolha o conector de API.")
    cfg = {}
    for f in c.fields:
        v = (config or {}).get(f.name, f.default)
        if f.required and (v is None or str(v).strip() == ""):
            raise ServiceError(f"Preencha “{f.label}”.")
        if v not in (None, ""):
            cfg[f.name] = str(v).strip()[:500]
    s.connector, s.connector_config = connector, cfg
    if any(v for v in (secrets or {}).values()):
        allowed = {f.name for f in c.secret_fields}
        bad = set(k for k, v in secrets.items() if v) - allowed
        if bad:
            raise ServiceError(f"Segredo desconhecido para este conector: {', '.join(sorted(bad))}")
        s.secret_enc = secrets_box.merge(s.secret_enc, f"source:{s.id}", secrets)
        s.secret_set_at, s.secret_set_by = utcnow(), by
    elif s.secret_enc is None and any(f.required for f in c.secret_fields) and not defer_secrets:
        raise ServiceError("Informe as credenciais do conector.")
    if not s.parser_id:
        p = Session.execute(select(Parser).where(Parser.slug == c.parser_slug)).scalar_one_or_none()
        if p is not None:
            s.parser_id = p.id
    s.interval_s = max(60, int(interval_s or c.default_interval_s))
    s.next_run_at = utcnow()


def update_source(s: Source, *, by="", **kw) -> Outcome:
    before = _snap(s)
    tenant = Session.get(Tenant, s.tenant_id)
    name = _validate(tenant, name=kw.get("name", s.name), transport=kw.get("transport", s.transport),
                     parser_id=kw.get("parser_id", s.parser_id), match_hostname=kw.get("match_hostname", s.match_hostname),
                     unparsed_policy=kw.get("unparsed_policy", s.unparsed_policy), exclude_id=s.id)
    s.name = name
    for k in ("transport", "unparsed_policy", "note"):
        if k in kw and kw[k] is not None:
            setattr(s, k, kw[k])
    if "match_hostname" in kw:
        s.match_hostname = (kw["match_hostname"] or "").strip()[:200]
    if "parser_id" in kw:
        s.parser_id = int(kw["parser_id"]) if kw["parser_id"] else None
    if "active" in kw and kw["active"] is not None:
        s.active = bool(kw["active"])
    if "silence_alert_minutes" in kw and kw["silence_alert_minutes"] is not None:
        s.silence_alert_minutes = max(0, int(kw["silence_alert_minutes"] or 0))
    if s.transport == "api" and ("connector" in kw or "connector_config" in kw or "secrets" in kw):
        _set_connector(s, kw.get("connector") or s.connector, kw.get("connector_config") or s.connector_config,
                       kw.get("secrets") or {}, kw.get("interval_s") or s.interval_s, by)
    changes = diff(before, _snap(s))
    if kw.get("secrets") and any(kw["secrets"].values()):
        changes["credenciais"] = ["(oculto)", "(atualizado)"]
    return Outcome(message=f"Fonte “{s.name}” atualizada.", obj=s, tenant_id=s.tenant_id,
                   audit=[("source.updated", s.name, changes)] if changes else [])


def delete_source(s: Source) -> Outcome:
    name, tid = s.name, s.tenant_id
    Session.delete(s)
    return Outcome(message=f"Fonte “{name}” excluída (e os IPs liberados só para ela).", tenant_id=tid,
                   audit=[("source.deleted", name, {})])


# ------------------------------------------------------------------------------------------------ IPs liberados
def norm_cidr(v: str, allow_wide: bool = False) -> str:
    v = (v or "").strip()
    try:
        net = ipaddress.ip_network(v, strict=False)
    except ValueError as e:
        raise ServiceError(f"IP ou faixa inválida: {v or '(vazio)'}") from e
    if net.version == 6:
        raise ServiceError("O syslog recebe só IPv4 (o endereço público do serviço é IPv4).")
    if net.prefixlen == 0:
        raise ServiceError("Liberar a internet inteira (0.0.0.0/0) não é permitido.")
    if net.prefixlen < MAX_PREFIX_V4 and not allow_wide:
        raise ServiceError(f"Faixa muito grande ({net}). Confirme a liberação de faixas maiores que /{MAX_PREFIX_V4}.")
    if net.is_loopback or net.is_multicast or net.is_reserved:
        raise ServiceError(f"Endereço não roteável: {net}")
    return str(net)


def add_allowed_ip(tenant: Tenant, *, cidr, protocols=("tls",), description="", source_id=None, expires_at: datetime | None = None,
                   allow_wide=False, by="") -> Outcome:
    net = norm_cidr(cidr, allow_wide)
    protos = sorted({p for p in (protocols or []) if p in PROTOCOLS})
    if not protos:
        raise ServiceError("Escolha ao menos um protocolo (TLS, TCP ou UDP).")
    if source_id:
        get_source(int(source_id), tenant.id)
    q = select(AllowedIP).where(AllowedIP.tenant_id == tenant.id, AllowedIP.cidr == net)
    q = q.where(AllowedIP.source_id == int(source_id)) if source_id else q.where(AllowedIP.source_id.is_(None))
    dup = Session.execute(q).scalar_one_or_none()
    if dup is not None:
        raise Conflict(f"{net} já está liberado para esta fonte/tenant.")
    other = Session.execute(select(Tenant.name).join(AllowedIP, AllowedIP.tenant_id == Tenant.id)
                            .where(AllowedIP.cidr == net, AllowedIP.tenant_id != tenant.id, AllowedIP.active.is_(True))).first()
    if other:
        raise Conflict(f"{net} já está liberado para outro tenant ({other[0]}). Um IP de origem só pode pertencer a um tenant.")
    a = AllowedIP(tenant_id=tenant.id, source_id=int(source_id) if source_id else None, cidr=net, protocols=protos,
                  description=clean(description, 200), expires_at=expires_at, created_by=by)
    Session.add(a)
    Session.flush()
    return Outcome(message=f"{net} liberado ({', '.join(p.upper() for p in protos)}). O firewall aplica em até 1 minuto.", obj=a,
                   tenant_id=tenant.id, audit=[("firewall.ip_added", net, {"protocols": protos, "source_id": a.source_id})])


def update_allowed_ip(a: AllowedIP, *, active=None, protocols=None, description=None) -> Outcome:
    before = dict(active=a.active, protocols=a.protocols, description=a.description)
    if active is not None:
        a.active = bool(active)
    if protocols is not None:
        protos = sorted({p for p in protocols if p in PROTOCOLS})
        if not protos:
            raise ServiceError("Escolha ao menos um protocolo.")
        a.protocols = protos
    if description is not None:
        a.description = clean(description, 200)
    return Outcome(message=f"{a.cidr} atualizado.", obj=a, tenant_id=a.tenant_id,
                   audit=[("firewall.ip_updated", a.cidr, diff(before, dict(active=a.active, protocols=a.protocols, description=a.description)))])


def delete_allowed_ip(a: AllowedIP) -> Outcome:
    cidr, tid = a.cidr, a.tenant_id
    Session.delete(a)
    return Outcome(message=f"{cidr} removido. O firewall bloqueia em até 1 minuto.", tenant_id=tid,
                   audit=[("firewall.ip_removed", cidr, {})])


def firewall_state() -> dict:
    """Estado desejado do firewall (lido pelo trustparser-fw no host): CIDRs por protocolo, só de tenants e fontes ativos."""
    now = utcnow()
    rows = Session.execute(select(AllowedIP).join(Tenant, Tenant.id == AllowedIP.tenant_id)
                           .where(AllowedIP.active.is_(True), Tenant.status == "active")).scalars().all()
    out = {"tls": set(), "tcp": set(), "udp": set()}
    for a in rows:
        if a.expires_at is not None and a.expires_at <= now:
            continue
        if a.source_id is not None:
            s = Session.get(Source, a.source_id)
            if s is None or not s.active:
                continue
        for p in a.protocols or []:
            if p in out:
                out[p].add(a.cidr)
    return {k: sorted(v) for k, v in out.items()}


def ip_owner(ip: str) -> list[tuple[int, int | None]]:
    """(tenant_id, source_id) dos registros que liberam este IP (mais específico primeiro)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return []
    found = []
    for a in Session.execute(select(AllowedIP).where(AllowedIP.active.is_(True))).scalars():
        net = ipaddress.ip_network(a.cidr, strict=False)
        if addr in net:
            found.append((net.prefixlen, a.tenant_id, a.source_id))
    found.sort(key=lambda x: -x[0])
    return [(t, s) for _, t, s in found]
