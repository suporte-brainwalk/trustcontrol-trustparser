"""API do Trust Parser: tenants, pessoas, fontes, IPs do firewall, destinos, parsers/formatos, uploads, eventos, parsing
avulso e Estúdio IA. As escritas chamam os mesmos serviços da tela (mesmas regras e auditoria)."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from flask import g, request
from pydantic import Field
from sqlalchemy import func, select

from ...db import Session, utcnow
from ...engine import connectors, dsl, formats, senders
from ...models import (AllowedIP, Destination, Event, EventDelivery, Parser, ParserVersion, Source, StudioJob, Tenant,
                       Upload, User)
from ...services import catalog, destinations as dsvc, people as psvc, sources as ssvc, tenants as tsvc
from ...services.changes import Outcome, ServiceError
from ..auth import check_tenant, tenant_scope
from ..errors import ApiError
from ..pagination import page
from ..registry import Page, Written, api_get, api_write, json_response
from ..schemas import In, Out, PageQuery, Query, TenantRef

# ------------------------------------------------------------------------------------------------ esquemas
class TenantOut(Out):
    id: int
    name: str
    segment: str
    internal: bool
    status: Literal["active", "suspended"]
    created_at: datetime
    updated_at: datetime


class TenantQuery(PageQuery):
    status: Literal["active", "suspended"] | None = None


class TenantCreate(In):
    name: str = Field(min_length=1, max_length=160)
    segment: str = Field("", max_length=60)
    internal: bool = False


class TenantUpdate(In):
    name: str | None = Field(None, max_length=160)
    segment: str | None = Field(None, max_length=60)
    internal: bool | None = None
    status: Literal["active", "suspended"] | None = None


class PersonOut(Out):
    email: str
    name: str
    role: Literal["manager", "reader"]
    status: str
    last_login_at: datetime | None


class PersonCreate(In):
    email: str = Field(max_length=254)
    name: str = Field("", max_length=160)
    role: Literal["manager", "reader"] = "reader"


class SourceOut(Out):
    id: int
    tenant: TenantRef
    name: str
    transport: Literal["syslog", "upload", "api"]
    parser_slug: str | None
    match_hostname: str
    unparsed_policy: str
    active: bool
    connector: str
    connector_config: dict
    credentials_set_at: datetime | None
    interval_s: int
    last_status: str
    last_error: str
    last_event_at: datetime | None
    events_total: int
    parsed_total: int
    unparsed_total: int
    silence_alert_minutes: int
    updated_at: datetime


class SourceQuery(PageQuery):
    tenant_id: int | None = None
    transport: Literal["syslog", "upload", "api"] | None = None


class SourceCreate(In):
    tenant_id: int
    name: str = Field(max_length=160)
    transport: Literal["syslog", "upload", "api"] = "syslog"
    parser_slug: str | None = Field(None, description="Parser fixo; vazio = autodetecção.")
    match_hostname: str = Field("", max_length=200)
    unparsed_policy: Literal["keep", "forward_raw", "drop"] = "keep"
    note: str = Field("", max_length=2000)
    connector: str = ""
    connector_config: dict = Field(default_factory=dict)
    secrets: dict = Field(default_factory=dict, description="Credenciais do conector (só escrita; nunca são devolvidas).")
    interval_s: int | None = Field(None, ge=60, le=86400)
    silence_alert_minutes: int = Field(0, ge=0, le=10080)


class SourceUpdate(In):
    name: str | None = Field(None, max_length=160)
    parser_slug: str | None = None
    match_hostname: str | None = Field(None, max_length=200)
    unparsed_policy: Literal["keep", "forward_raw", "drop"] | None = None
    note: str | None = Field(None, max_length=2000)
    active: bool | None = None
    connector_config: dict | None = None
    secrets: dict | None = None
    interval_s: int | None = Field(None, ge=60, le=86400)
    silence_alert_minutes: int | None = Field(None, ge=0, le=10080)


class AllowedIPOut(Out):
    id: int
    tenant: TenantRef
    source_id: int | None
    cidr: str
    protocols: list[str]
    description: str
    active: bool
    created_by: str
    created_at: datetime


class AllowedIPQuery(PageQuery):
    tenant_id: int | None = None


class AllowedIPCreate(In):
    tenant_id: int
    cidr: str = Field(max_length=64, description="IPv4 ou faixa CIDR (até /16; mais que isso exige allow_wide).")
    protocols: list[Literal["tls", "tcp", "udp"]] = Field(default_factory=lambda: ["tls"])
    source_id: int | None = None
    description: str = Field("", max_length=200)
    allow_wide: bool = False


class AllowedIPUpdate(In):
    active: bool | None = None
    protocols: list[Literal["tls", "tcp", "udp"]] | None = None
    description: str | None = Field(None, max_length=200)


class FirewallOut(Out):
    syslog: dict = Field(description="Endereço e portas para configurar os equipamentos.")
    desired: dict = Field(description="Faixas liberadas por protocolo.")
    in_sync: bool = Field(description="O firewall do servidor já aplicou o estado atual.")
    applied_at: str | None


class DestinationOut(Out):
    id: int
    tenant: TenantRef
    name: str
    kind: str
    format: str
    config: dict
    credentials_set_at: datetime | None
    filters: dict
    include_unparsed: bool
    active: bool
    status: str
    last_ok_at: datetime | None
    last_error: str
    sent_total: int
    failed_total: int
    pending: int
    updated_at: datetime


class DestinationQuery(PageQuery):
    tenant_id: int | None = None


class DestinationCreate(In):
    tenant_id: int
    name: str = Field(max_length=160)
    kind: Literal["secops_chronicle", "secops_legacy", "wazuh", "qradar", "syslog", "webhook"]
    format: str | None = None
    config: dict = Field(default_factory=dict)
    secrets: dict = Field(default_factory=dict, description="Credenciais (só escrita; nunca são devolvidas).")
    filters: dict = Field(default_factory=dict)
    include_unparsed: bool = False
    active: bool = True


class DestinationUpdate(In):
    name: str | None = Field(None, max_length=160)
    format: str | None = None
    config: dict | None = None
    secrets: dict | None = None
    filters: dict | None = None
    include_unparsed: bool | None = None
    active: bool | None = None
    batch_size: int | None = Field(None, ge=1, le=1000)


class TestResult(Out):
    ok: bool
    message: str


class ParserOut(Out):
    id: int
    kind: Literal["input", "output"]
    slug: str
    name: str
    vendor: str
    product: str
    description: str
    origin: str
    basis: Literal["real", "docs"]
    active: bool
    current_version: int | None


class VersionOut(Out):
    id: int
    version: int
    status: str
    notes: str
    created_by: str
    created_at: datetime
    published_at: datetime | None
    tests_passed: int | None
    tests_total: int | None


class ParserDetail(ParserOut):
    versions: list[VersionOut]
    spec: dict | None = Field(None, description="Spec da versão publicada.")


class ParserQuery(Query):
    kind: Literal["input", "output"] | None = None


class PublishIn(In):
    version_id: int


class LinesIn(In):
    lines: list[str] = Field(max_length=5000)
    parser_slug: str | None = Field(None, description="Vazio = autodetecção.")
    format: str = Field("ocsf_json", description="Formato de saída (udm, wazuh_json, ocsf_json, cef, leef, csv, raw ou slug criado no Estúdio).")


class ParsedLine(Out):
    ok: bool
    parser: str | None
    output: dict | str | None
    error: str | None


class ParseOut(Out):
    total: int
    parsed: int
    results: list[ParsedLine]


class UploadIn(In):
    tenant_id: int
    filename: str = Field(max_length=255)
    content: str = Field(description="Conteúdo do arquivo (texto, uma linha por evento).", max_length=40_000_000)
    parser_slug: str | None = None
    source_id: int | None = None
    send_to_destinations: bool = False


class UploadOut(Out):
    id: int
    tenant: TenantRef
    filename: str
    lines: int
    parsed: int
    unparsed: int
    status: str
    send_to_destinations: bool
    created_at: datetime
    expires_at: datetime


class UploadQuery(PageQuery):
    tenant_id: int | None = None


class DownloadQuery(Query):
    format: str = "ocsf_json"
    include_unparsed: bool = False


class EventOut(Out):
    id: int
    tenant_id: int | None
    source_id: int | None
    received_at: datetime
    peer_ip: str
    transport: str
    status: str
    raw: str
    event: dict | None
    error: str


class EventQuery(PageQuery):
    tenant_id: int | None = None
    source_id: int | None = None
    status: Literal["parsed", "unparsed", "received"] | None = None
    minutes: int | None = Field(None, ge=1, le=1440)


class EventDownloadQuery(Query):
    tenant_id: int | None = None
    source_id: int | None = None
    status: Literal["parsed", "unparsed"] | None = None
    minutes: int | None = Field(None, ge=1, le=1440)
    format: str = "ocsf_json"
    include_unparsed: bool = False


class StudioJobOut(Out):
    id: int
    kind: str
    title: str
    status: str
    parser_slug: str | None
    result_version: int | None
    coverage_pct: float | None
    tests_passed: int | None
    tests_total: int | None
    error: str
    requested_by: str
    created_at: datetime
    finished_at: datetime | None


class StudioJobCreate(In):
    kind: Literal["input", "output", "fix"]
    title: str = Field(max_length=200)
    vendor: str = Field("", max_length=80)
    product: str = Field("", max_length=120)
    request: str = Field("", max_length=5000)
    samples: str = Field("", max_length=2_000_000)
    docs: str = Field("", max_length=500_000)
    docs_urls: list[str] = Field(default_factory=list, max_length=5)
    mask: bool = True
    mask_terms: str = Field("", max_length=2000)
    parser_slug: str | None = None


class StatsOut(Out):
    eps_5min: float
    events_last_hour: int
    parsed_last_hour: int
    unparsed_last_hour: int
    unparsed_in_buffer: int
    queued: int
    pending_deliveries: int
    destinations_with_error: int


TAG_T, TAG_S, TAG_F, TAG_D, TAG_P, TAG_U, TAG_E, TAG_ST = (["Tenants"], ["Fontes"], ["Firewall do syslog"], ["Destinos"],
                                                          ["Parsers e formatos"], ["Uploads"], ["Eventos"], ["Estúdio IA"])


# ------------------------------------------------------------------------------------------------ utilitários
def _tref(t: Tenant) -> TenantRef:
    return TenantRef(id=t.id, name=t.name)


def _tenant(tid: int) -> Tenant:
    check_tenant(tid)
    t = Session.get(Tenant, tid)
    if t is None:
        raise ApiError(404, "Tenant não encontrado.")
    return t


def _scoped(stmt, col, tenant_id: int | None):
    scope = tenant_scope()
    if scope is not None:
        if tenant_id is not None and tenant_id != scope:
            raise ApiError(404, "Recurso não encontrado.")
        return stmt.where(col == scope)
    if tenant_id is not None:
        return stmt.where(col == tenant_id)
    return stmt


def _parser_id(slug: str | None, kind: str = "input") -> int | None:
    if not slug:
        return None
    p = Session.execute(select(Parser).where(Parser.slug == slug, Parser.kind == kind)).scalar_one_or_none()
    if p is None:
        raise ApiError(422, f"Parser '{slug}' não existe.")
    return p.id


def _actor() -> str:
    k = g.api_key
    return f"api:{k.owner_email or k.name}"


# ------------------------------------------------------------------------------------------------ tenants
def _tenant_out(t):
    return TenantOut(id=t.id, name=t.name, segment=t.segment or "", internal=t.internal, status=t.status, created_at=t.created_at,
                     updated_at=t.updated_at)


@api_get("/tenants", summary="Listar tenants", response=TenantOut, many=True, query=TenantQuery, permission="tenants:ler", tags=TAG_T)
def tenants(q: TenantQuery):
    stmt = _scoped(select(Tenant), Tenant.id, None)
    if q.status:
        stmt = stmt.where(Tenant.status == q.status)
    rows, nxt = page(Session, stmt, Tenant.id, Tenant.id, q.limit, q.cursor, desc=False)
    return Page([_tenant_out(t) for t in rows], nxt)


@api_get("/tenants/{tenant_id}", summary="Detalhe de um tenant", response=TenantOut, permission="tenants:ler", tags=TAG_T)
def tenant(tenant_id: int):
    return _tenant_out(_tenant(tenant_id))


@api_write("POST", "/tenants", summary="Criar tenant", permission="tenants:gerenciar", body=TenantCreate, response=TenantOut, status=201, tags=TAG_T)
def tenant_create(b: TenantCreate):
    out = tsvc.create_tenant(name=b.name, segment=b.segment, internal=b.internal)
    return Written(out, lambda: _tenant_out(Session.get(Tenant, out.obj.id)), location=f"/api/v1/tenants/{out.obj.id}")


@api_write("PATCH", "/tenants/{tenant_id}", summary="Editar/suspender tenant", permission="tenants:gerenciar", body=TenantUpdate,
           response=TenantOut, current=lambda tenant_id: _tenant_out(_tenant(tenant_id)), tags=TAG_T)
def tenant_update(b: TenantUpdate, tenant_id: int):
    t = _tenant(tenant_id)
    out = tsvc.update_tenant(t, **b.model_dump(exclude_none=True))
    return Written(out, lambda: _tenant_out(Session.get(Tenant, tenant_id)))


@api_get("/tenants/{tenant_id}/people", summary="Pessoas com acesso ao tenant", response=PersonOut, many=True, permission="pessoas:ler", tags=TAG_T)
def tenant_people(tenant_id: int):
    t = _tenant(tenant_id)
    return Page([PersonOut(email=u.email, name=u.name, role=u.role, status=u.status, last_login_at=u.last_login_at) for u in psvc.list_people(t)])


@api_write("POST", "/tenants/{tenant_id}/people", summary="Convidar pessoa (gestor ou leitor)", permission="pessoas:gerenciar",
           body=PersonCreate, response=PersonOut, status=201, tags=TAG_T)
def tenant_person_add(b: PersonCreate, tenant_id: int):
    t = _tenant(tenant_id)
    out = psvc.add(t, name=b.name, email=b.email, role=b.role)
    u = out.obj
    return Written(out, lambda: PersonOut(email=u.email, name=u.name, role=u.role, status=u.status, last_login_at=None))


@api_write("DELETE", "/tenants/{tenant_id}/people/{email}", summary="Remover acesso de uma pessoa", permission="pessoas:gerenciar",
           path_types={"email": "string"}, tags=TAG_T)
def tenant_person_remove(tenant_id: int, email: str):
    return Written(psvc.remove(_tenant(tenant_id), email), None, status=204)


# ------------------------------------------------------------------------------------------------ fontes
def _source_out(s: Source) -> SourceOut:
    return SourceOut(id=s.id, tenant=_tref(s.tenant), name=s.name, transport=s.transport, parser_slug=s.parser.slug if s.parser else None,
                     match_hostname=s.match_hostname, unparsed_policy=s.unparsed_policy, active=s.active, connector=s.connector,
                     connector_config=s.connector_config or {}, credentials_set_at=s.secret_set_at, interval_s=s.interval_s,
                     last_status=s.last_status, last_error=s.last_error, last_event_at=s.last_event_at, events_total=s.events_total,
                     parsed_total=s.parsed_total, unparsed_total=s.unparsed_total, silence_alert_minutes=s.silence_alert_minutes,
                     updated_at=s.updated_at)


def _source(sid: int) -> Source:
    s = Session.get(Source, sid)
    if s is None:
        raise ApiError(404, "Fonte não encontrada.")
    check_tenant(s.tenant_id)
    return s


@api_get("/sources", summary="Listar fontes de entrada", response=SourceOut, many=True, query=SourceQuery, permission="fontes:ler", tags=TAG_S)
def sources(q: SourceQuery):
    stmt = _scoped(select(Source), Source.tenant_id, q.tenant_id)
    if q.transport:
        stmt = stmt.where(Source.transport == q.transport)
    rows, nxt = page(Session, stmt, Source.id, Source.id, q.limit, q.cursor, desc=False)
    return Page([_source_out(s) for s in rows], nxt)


@api_get("/sources/{source_id}", summary="Detalhe de uma fonte", response=SourceOut, permission="fontes:ler", tags=TAG_S)
def source(source_id: int):
    return _source_out(_source(source_id))


@api_write("POST", "/sources", summary="Criar fonte (syslog, upload ou conector de API)", permission="fontes:gerenciar", body=SourceCreate,
           response=SourceOut, status=201, tags=TAG_S)
def source_create(b: SourceCreate):
    t = _tenant(b.tenant_id)
    out = ssvc.create_source(t, name=b.name, transport=b.transport, parser_id=_parser_id(b.parser_slug), match_hostname=b.match_hostname,
                             unparsed_policy=b.unparsed_policy, note=b.note, connector=b.connector, connector_config=b.connector_config,
                             secrets=b.secrets, interval_s=b.interval_s, silence_alert_minutes=b.silence_alert_minutes, by=_actor())
    return Written(out, lambda: _source_out(Session.get(Source, out.obj.id)), location=f"/api/v1/sources/{out.obj.id}")


@api_write("PATCH", "/sources/{source_id}", summary="Editar fonte", permission="fontes:gerenciar", body=SourceUpdate, response=SourceOut,
           current=lambda source_id: _source_out(_source(source_id)), tags=TAG_S)
def source_update(b: SourceUpdate, source_id: int):
    s = _source(source_id)
    kw = b.model_dump(exclude_unset=True)
    if "parser_slug" in kw:
        kw["parser_id"] = _parser_id(kw.pop("parser_slug"))
    out = ssvc.update_source(s, by=_actor(), **kw)
    return Written(out, lambda: _source_out(Session.get(Source, source_id)))


@api_write("DELETE", "/sources/{source_id}", summary="Excluir fonte", permission="fontes:gerenciar", tags=TAG_S)
def source_delete(source_id: int):
    return Written(ssvc.delete_source(_source(source_id)), None, status=204)


@api_get("/connectors", summary="Conectores de API disponíveis e seus campos", permission="fontes:ler", tags=TAG_S)
def connectors_list():
    reg = connectors.REGISTRY
    return {"data": [{"slug": k, "name": c.name, "vendor": c.vendor, "parser_slug": c.parser_slug, "default_interval_s": c.default_interval_s,
                      "fields": [{"name": f.name, "label": f.label, "required": f.required, "kind": f.kind, "options": [o[0] for o in (f.options or [])]} for f in c.fields],
                      "secret_fields": [{"name": f.name, "label": f.label, "required": f.required} for f in c.secret_fields]} for k, c in reg.items()]}


# ------------------------------------------------------------------------------------------------ firewall
def _ip_out(a: AllowedIP) -> AllowedIPOut:
    return AllowedIPOut(id=a.id, tenant=_tref(a.tenant), source_id=a.source_id, cidr=a.cidr, protocols=a.protocols or [], description=a.description,
                        active=a.active, created_by=a.created_by, created_at=a.created_at)


def _ip(aid: int) -> AllowedIP:
    a = Session.get(AllowedIP, aid)
    if a is None:
        raise ApiError(404, "Registro não encontrado.")
    check_tenant(a.tenant_id)
    return a


@api_get("/firewall", summary="Endereço do syslog e situação do firewall", response=FirewallOut, permission="fontes:ler", tags=TAG_F)
def firewall():
    from ...web import common
    st = common.fw_status()
    return FirewallOut(syslog=common.syslog_info(), desired=st["desired"] if tenant_scope() is None else {}, in_sync=st["in_sync"],
                       applied_at=(st["applied"] or {}).get("at"))


@api_get("/allowed-ips", summary="IPs liberados para enviar syslog", response=AllowedIPOut, many=True, query=AllowedIPQuery, permission="fontes:ler", tags=TAG_F)
def allowed_ips(q: AllowedIPQuery):
    stmt = _scoped(select(AllowedIP), AllowedIP.tenant_id, q.tenant_id)
    rows, nxt = page(Session, stmt, AllowedIP.id, AllowedIP.id, q.limit, q.cursor, desc=False)
    return Page([_ip_out(a) for a in rows], nxt)


@api_write("POST", "/allowed-ips", summary="Liberar IP no firewall do syslog", permission="fontes:gerenciar", body=AllowedIPCreate,
           response=AllowedIPOut, status=201, tags=TAG_F)
def allowed_ip_create(b: AllowedIPCreate):
    t = _tenant(b.tenant_id)
    if b.allow_wide and tenant_scope() is not None:
        raise ApiError(403, "Faixas maiores que /16 só por chave global.")
    out = ssvc.add_allowed_ip(t, cidr=b.cidr, protocols=b.protocols, description=b.description, source_id=b.source_id, allow_wide=b.allow_wide,
                              by=_actor())
    return Written(out, lambda: _ip_out(Session.get(AllowedIP, out.obj.id)), location=f"/api/v1/allowed-ips/{out.obj.id}")


@api_write("PATCH", "/allowed-ips/{ip_id}", summary="Ativar/desativar ou trocar protocolos", permission="fontes:gerenciar", body=AllowedIPUpdate,
           response=AllowedIPOut, tags=TAG_F)
def allowed_ip_update(b: AllowedIPUpdate, ip_id: int):
    out = ssvc.update_allowed_ip(_ip(ip_id), **b.model_dump(exclude_none=True))
    return Written(out, lambda: _ip_out(Session.get(AllowedIP, ip_id)))


@api_write("DELETE", "/allowed-ips/{ip_id}", summary="Remover IP do firewall", permission="fontes:gerenciar", tags=TAG_F)
def allowed_ip_delete(ip_id: int):
    return Written(ssvc.delete_allowed_ip(_ip(ip_id)), None, status=204)


# ------------------------------------------------------------------------------------------------ destinos
def _dest_out(d: Destination) -> DestinationOut:
    pending = Session.execute(select(func.count()).select_from(EventDelivery).where(EventDelivery.destination_id == d.id,
                                                                                   EventDelivery.status == "pending")).scalar_one()
    return DestinationOut(id=d.id, tenant=_tref(d.tenant), name=d.name, kind=d.kind, format=d.format, config=d.config or {},
                          credentials_set_at=d.secret_set_at, filters=d.filters or {}, include_unparsed=d.include_unparsed, active=d.active,
                          status=d.status, last_ok_at=d.last_ok_at, last_error=d.last_error, sent_total=d.sent_total, failed_total=d.failed_total,
                          pending=pending, updated_at=d.updated_at)


def _dest(did: int) -> Destination:
    d = Session.get(Destination, did)
    if d is None:
        raise ApiError(404, "Destino não encontrado.")
    check_tenant(d.tenant_id)
    return d


@api_get("/destination-kinds", summary="Tipos de destino, campos e formatos aceitos", permission="destinos:ler", tags=TAG_D)
def destination_kinds():
    return {"data": [{"kind": k, "name": v["name"], "help": v["help"], "formats": v["formats"] or [s for s, _ in catalog.output_choices()],
                      "default_format": v["default_format"],
                      "fields": [{"name": f.name, "label": f.label, "required": f.required, "kind": f.kind, "default": f.default,
                                  "options": [o[0] for o in f.options]} for f in v["fields"]],
                      "secret_fields": [{"name": f.name, "label": f.label, "required": f.required} for f in v["secrets"]]}
                     for k, v in senders.KINDS.items()]}


@api_get("/destinations", summary="Listar destinos", response=DestinationOut, many=True, query=DestinationQuery, permission="destinos:ler", tags=TAG_D)
def destinations(q: DestinationQuery):
    stmt = _scoped(select(Destination), Destination.tenant_id, q.tenant_id)
    rows, nxt = page(Session, stmt, Destination.id, Destination.id, q.limit, q.cursor, desc=False)
    return Page([_dest_out(d) for d in rows], nxt)


@api_get("/destinations/{destination_id}", summary="Detalhe de um destino (sem credenciais)", response=DestinationOut, permission="destinos:ler", tags=TAG_D)
def destination(destination_id: int):
    return _dest_out(_dest(destination_id))


@api_write("POST", "/destinations", summary="Criar destino", permission="destinos:gerenciar", body=DestinationCreate, response=DestinationOut,
           status=201, tags=TAG_D)
def destination_create(b: DestinationCreate):
    t = _tenant(b.tenant_id)
    out = dsvc.create_destination(t, name=b.name, kind=b.kind, format=b.format, config=b.config, secrets=b.secrets, filters=b.filters,
                                  include_unparsed=b.include_unparsed, active=b.active, by=_actor())
    return Written(out, lambda: _dest_out(Session.get(Destination, out.obj.id)), location=f"/api/v1/destinations/{out.obj.id}")


@api_write("PATCH", "/destinations/{destination_id}", summary="Editar destino (credenciais só escrita)", permission="destinos:gerenciar",
           body=DestinationUpdate, response=DestinationOut, current=lambda destination_id: _dest_out(_dest(destination_id)), tags=TAG_D)
def destination_update(b: DestinationUpdate, destination_id: int):
    out = dsvc.update_destination(_dest(destination_id), by=_actor(), **b.model_dump(exclude_none=True))
    return Written(out, lambda: _dest_out(Session.get(Destination, destination_id)))


@api_write("DELETE", "/destinations/{destination_id}", summary="Excluir destino", permission="destinos:gerenciar", tags=TAG_D)
def destination_delete(destination_id: int):
    return Written(dsvc.delete_destination(_dest(destination_id)), None, status=204)


@api_write("POST", "/destinations/{destination_id}/test", summary="Testar conexão (envia 1 evento de teste)", permission="destinos:gerenciar",
           response=TestResult, tags=TAG_D)
def destination_test(destination_id: int):
    d = _dest(destination_id)
    ok, msg = dsvc.test_destination(d)
    out = Outcome(message=msg, tenant_id=d.tenant_id, audit=[("destination.tested", d.name, {"ok": ok})])
    return Written(out, lambda: TestResult(ok=ok, message=msg))


# ------------------------------------------------------------------------------------------------ parsers e formatos
def _parser_out(p: Parser, cls=ParserOut, **extra):
    v = Session.get(ParserVersion, p.current_version_id) if p.current_version_id else None
    return cls(id=p.id, kind=p.kind, slug=p.slug, name=p.name, vendor=p.vendor, product=p.product, description=p.description,
               origin=p.origin, basis=p.basis, active=p.active, current_version=v.version if v else None, **extra)


@api_get("/parsers", summary="Parsers de entrada e formatos de saída", response=ParserOut, many=True, query=ParserQuery, permission="parsers:ler", tags=TAG_P)
def parsers(q: ParserQuery):
    stmt = select(Parser).order_by(Parser.kind, Parser.slug)
    if q.kind:
        stmt = stmt.where(Parser.kind == q.kind)
    return Page([_parser_out(p) for p in Session.execute(stmt).scalars()])


@api_get("/parsers/{parser_slug}", summary="Detalhe, versões e spec publicado", response=ParserDetail, permission="parsers:ler",
         path_types={"parser_slug": "string"}, tags=TAG_P)
def parser_detail(parser_slug: str):
    p = Session.execute(select(Parser).where(Parser.slug == parser_slug)).scalar_one_or_none()
    if p is None:
        raise ApiError(404, "Parser não encontrado.")
    vs = Session.execute(select(ParserVersion).where(ParserVersion.parser_id == p.id).order_by(ParserVersion.version.desc())).scalars().all()
    cur = next((v for v in vs if v.id == p.current_version_id), None)

    def rep(v):
        r = v.report or {}
        r = r.get("tests", r)
        return r.get("passed"), r.get("total")
    return _parser_out(p, ParserDetail, spec=cur.spec if cur else None,
                       versions=[VersionOut(id=v.id, version=v.version, status=v.status, notes=v.notes, created_by=v.created_by, created_at=v.created_at,
                                            published_at=v.published_at, tests_passed=rep(v)[0], tests_total=rep(v)[1]) for v in vs])


@api_write("POST", "/parsers/{parser_slug}/publish", summary="Publicar uma versão (rascunho ou anterior)", permission="parsers:gerenciar",
           body=PublishIn, response=ParserOut, path_types={"parser_slug": "string"}, tags=TAG_P)
def parser_publish(b: PublishIn, parser_slug: str):
    p = Session.execute(select(Parser).where(Parser.slug == parser_slug)).scalar_one_or_none()
    v = Session.get(ParserVersion, b.version_id)
    if p is None or v is None or v.parser_id != p.id:
        raise ApiError(404, "Versão não encontrada.")
    out = catalog.publish(v, _actor())
    return Written(out, lambda: _parser_out(Session.get(Parser, p.id)))


@api_write("POST", "/parse", summary="Parsear linhas (sem gravar) e devolver no formato pedido", permission="parsers:ler", body=LinesIn,
           response=ParseOut, counts=False, max_body=20 * 1024 * 1024, tags=TAG_P)
def parse_lines(b: LinesIn):
    if b.format not in dict(catalog.output_choices()):
        raise ApiError(422, "Formato de saída desconhecido.")
    pid = _parser_id(b.parser_slug)
    spec = catalog.output_spec(b.format)
    res, ok = [], 0
    for ln in b.lines:
        try:
            ev, _ = catalog.parse_line(ln, {}, pid)
            ok += 1
            outp = formats.render(b.format, ev, ln, {}, spec)
            res.append(ParsedLine(ok=True, parser=ev.get("metadata", {}).get("parser"), output=outp, error=None))
        except (dsl.ParseError, dsl.SpecError) as e:
            res.append(ParsedLine(ok=False, parser=None, output=None, error=str(e)))
    return Written(None, lambda: ParseOut(total=len(b.lines), parsed=ok, results=res))


# ------------------------------------------------------------------------------------------------ uploads
def _upload_out(u: Upload) -> UploadOut:
    return UploadOut(id=u.id, tenant=_tref(u.tenant), filename=u.filename, lines=u.lines, parsed=u.parsed, unparsed=u.unparsed, status=u.status,
                     send_to_destinations=u.send_to_destinations, created_at=u.created_at, expires_at=u.expires_at)


def _upload(uid: int) -> Upload:
    u = Session.get(Upload, uid)
    if u is None:
        raise ApiError(404, "Upload não encontrado.")
    check_tenant(u.tenant_id)
    return u


class _TextFile:
    def __init__(self, name, content):
        self.filename, self._c = name, content

    def read(self):
        return self._c.encode("utf-8")


@api_write("POST", "/uploads", summary="Enviar arquivo de log (texto) para parsing", permission="uploads:enviar", body=UploadIn,
           response=UploadOut, status=201, max_body=45 * 1024 * 1024, tags=TAG_U)
def upload_create(b: UploadIn):
    from ...web import common
    t = _tenant(b.tenant_id)
    name = b.filename if b.filename.lower().endswith(common.TEXT_EXT) else b.filename + ".txt"
    up = common.ingest_upload(t, _TextFile(name, b.content), source_id=b.source_id, parser_id=_parser_id(b.parser_slug),
                              send=b.send_to_destinations, by=_actor())
    out = Outcome(message="ok", obj=up, tenant_id=t.id, audit=[("upload.created", up.filename, {"lines": up.lines})])
    return Written(out, lambda: _upload_out(Session.get(Upload, up.id)), location=f"/api/v1/uploads/{up.id}")


@api_get("/uploads", summary="Listar uploads", response=UploadOut, many=True, query=UploadQuery, permission="uploads:ler", tags=TAG_U)
def uploads(q: UploadQuery):
    stmt = _scoped(select(Upload), Upload.tenant_id, q.tenant_id)
    rows, nxt = page(Session, stmt, Upload.id, Upload.id, q.limit, q.cursor, desc=True)
    return Page([_upload_out(u) for u in rows], nxt)


@api_get("/uploads/{upload_id}", summary="Situação de um upload", response=UploadOut, permission="uploads:ler", tags=TAG_U)
def upload(upload_id: int):
    return _upload_out(_upload(upload_id))


@api_get("/uploads/{upload_id}/download", summary="Baixar o resultado no formato pedido (texto, uma linha por evento)",
         query=DownloadQuery, permission="uploads:ler", tags=TAG_U)
def upload_download(q: DownloadQuery, upload_id: int):
    from ...web import common
    u = _upload(upload_id)
    return common.download_response(select(Event).where(Event.upload_id == u.id).order_by(Event.line_no), q.format, u.filename, q.include_unparsed)


# ------------------------------------------------------------------------------------------------ eventos e indicadores
def _event_out(e: Event) -> EventOut:
    return EventOut(id=e.id, tenant_id=e.tenant_id, source_id=e.source_id, received_at=e.received_at, peer_ip=e.peer_ip, transport=e.transport,
                    status=e.status, raw=e.raw, event=e.event, error=e.error)


def _events_stmt(q):
    stmt = _scoped(select(Event), Event.tenant_id, q.tenant_id)
    if q.source_id:
        stmt = stmt.where(Event.source_id == q.source_id)
    if q.status:
        stmt = stmt.where(Event.status == q.status)
    if q.minutes:
        from datetime import timedelta
        stmt = stmt.where(Event.received_at > utcnow() - timedelta(minutes=q.minutes))
    return stmt


@api_get("/events", summary="Eventos do buffer (até 2 h)", response=EventOut, many=True, query=EventQuery, permission="eventos:ler", tags=TAG_E)
def events(q: EventQuery):
    rows, nxt = page(Session, _events_stmt(q), Event.id, Event.id, q.limit, q.cursor, desc=True)
    return Page([_event_out(e) for e in rows], nxt)


@api_get("/events/download", summary="Baixar eventos do buffer no formato pedido", query=EventDownloadQuery, permission="eventos:ler", tags=TAG_E)
def events_download(q: EventDownloadQuery):
    from ...web import common
    return common.download_response(_events_stmt(q).order_by(Event.id), q.format, "eventos", q.include_unparsed)


@api_get("/stats", summary="Indicadores (EPS, cobertura, pendências)", response=StatsOut, permission="indicadores:ler", tags=TAG_E)
def stats():
    from ...web import common
    d = common.dashboard_data(tenant_scope())
    k = d["k"]
    derr = sum(1 for x in d["dests"] if x.status == "err" and x.active)
    return StatsOut(eps_5min=d["eps"], events_last_hour=k["last60"] or 0, parsed_last_hour=k["parsed60"] or 0, unparsed_last_hour=k["unparsed60"] or 0,
                    unparsed_in_buffer=k["unparsed_all"] or 0, queued=k["queued"] or 0, pending_deliveries=d["pending"] or 0, destinations_with_error=derr)


# ------------------------------------------------------------------------------------------------ Estúdio IA
def _job_out(j: StudioJob) -> StudioJobOut:
    v = Session.get(ParserVersion, j.result_version_id) if j.result_version_id else None
    rep = j.report or {}
    cov, tests = rep.get("coverage") or {}, rep.get("tests") or {}
    return StudioJobOut(id=j.id, kind=j.kind, title=j.title, status=j.status, parser_slug=j.parser.slug if j.parser else None,
                        result_version=v.version if v else None, coverage_pct=cov.get("pct"), tests_passed=tests.get("passed"),
                        tests_total=tests.get("total"), error=j.error, requested_by=j.requested_by, created_at=j.created_at, finished_at=j.finished_at)


@api_get("/studio/jobs", summary="Pedidos do Estúdio IA", response=StudioJobOut, many=True, query=PageQuery, permission="estudio:ler", tags=TAG_ST)
def studio_jobs(q: PageQuery):
    rows, nxt = page(Session, select(StudioJob), StudioJob.id, StudioJob.id, q.limit, q.cursor, desc=True)
    return Page([_job_out(j) for j in rows], nxt)


@api_get("/studio/jobs/{job_id}", summary="Detalhe de um pedido do Estúdio", response=StudioJobOut, permission="estudio:ler", tags=TAG_ST)
def studio_job(job_id: int):
    j = Session.get(StudioJob, job_id)
    if j is None:
        raise ApiError(404, "Pedido não encontrado.")
    return _job_out(j)


@api_write("POST", "/studio/jobs", summary="Pedir parser/formato ao Estúdio IA (resultado fica em rascunho)", permission="estudio:pedir",
           body=StudioJobCreate, response=StudioJobOut, status=201, max_body=10 * 1024 * 1024, tags=TAG_ST)
def studio_job_create(b: StudioJobCreate):
    from ...engine import studio
    job = studio.create_job(kind=b.kind, title=b.title, vendor=b.vendor, product=b.product, request=b.request, samples=b.samples, docs=b.docs,
                            docs_urls=b.docs_urls, mask=b.mask, mask_terms=b.mask_terms, parser_id=_parser_id(b.parser_slug), by=_actor())
    out = Outcome(message="ok", obj=job, audit=[("studio.requested", job.title, {"kind": job.kind})])
    return Written(out, lambda: _job_out(Session.get(StudioJob, job.id)), location=f"/api/v1/studio/jobs/{job.id}")
