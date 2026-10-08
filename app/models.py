"""Modelo de dados do Trust Parser."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (BigInteger, Boolean, CheckConstraint, DateTime, Float, ForeignKey, Index, Integer, LargeBinary, String,
                        Text, UniqueConstraint, func)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base, utcnow

SEVERITIES = ("critical", "high", "medium", "low")
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
SEV_PT = {"critical": "Crítica", "high": "Alta", "medium": "Média", "low": "Baixa", "unknown": "Não informada"}


def TS(**kw):
    return mapped_column(DateTime(timezone=True), **kw)



class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    updated_at: Mapped[datetime] = TS(server_default=func.now(), nullable=False)  # mantido por gatilho no banco
    email: Mapped[str] = mapped_column(String(254), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False, default="")
    role: Mapped[str] = mapped_column(String(16), nullable=False)  # admin | manager | reader
    tenant_id: Mapped[int | None] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="invited")  # invited|active|suspended
    totp_secret: Mapped[str | None] = mapped_column(String(64))
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    recovery_codes: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    created_at: Mapped[datetime] = TS(default=utcnow, nullable=False)
    last_login_at: Mapped[datetime | None] = TS()
    tenant = relationship("Tenant", back_populates="users")

    __table_args__ = (
        CheckConstraint("role in ('admin','manager','reader')", name="ck_user_role"),
        CheckConstraint("status in ('invited','active','suspended')", name="ck_user_status"),
        CheckConstraint("(role = 'admin' and tenant_id is null) or (role <> 'admin' and tenant_id is not null)",
                        name="ck_user_tenant"),
        CheckConstraint("email = lower(email)", name="ck_user_email_lower"),
    )

    # Flask-Login
    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return self.status == "active"

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    @property
    def is_admin(self):
        return self.role == "admin"


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[int] = mapped_column(primary_key=True)
    updated_at: Mapped[datetime] = TS(server_default=func.now(), nullable=False)  # mantido por gatilho no banco
    name: Mapped[str] = mapped_column(String(160), unique=True, nullable=False)
    segment: Mapped[str] = mapped_column(String(60), default="", nullable=False)
    internal: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="active", nullable=False)
    created_at: Mapped[datetime] = TS(default=utcnow, nullable=False)
    users = relationship("User", back_populates="tenant")

    __table_args__ = (
        CheckConstraint("status in ('active','suspended')", name="ck_tenant_status"),
    )


class MagicLink(Base):
    __tablename__ = "magic_links"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    purpose: Mapped[str] = mapped_column(String(10), nullable=False)  # login | invite
    expires_at: Mapped[datetime] = TS(nullable=False)
    used_at: Mapped[datetime | None] = TS()
    ip: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    created_at: Mapped[datetime] = TS(default=utcnow, nullable=False)


class Delivery(Base):
    __tablename__ = "deliveries"
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(12), nullable=False)  # alert|newsletter|auth|system
    ref_id: Mapped[int | None] = mapped_column(Integer)
    tenant_id: Mapped[int | None] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    recipient: Mapped[str] = mapped_column(String(254), nullable=False)
    effective_recipient: Mapped[str] = mapped_column(String(254), nullable=False)
    subject: Mapped[str] = mapped_column(Text, default="", nullable=False)
    status: Mapped[str] = mapped_column(String(10), default="pending", nullable=False)  # pending|sent|failed
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    smtp_response: Mapped[str] = mapped_column(Text, default="", nullable=False)
    dedupe_key: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    message_id: Mapped[str] = mapped_column(String(200), default="", nullable=False)
    created_at: Mapped[datetime] = TS(default=utcnow, nullable=False, index=True)
    sent_at: Mapped[datetime | None] = TS()
    next_attempt_at: Mapped[datetime | None] = TS()


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime] = TS(default=utcnow, nullable=False, index=True)
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    actor_label: Mapped[str] = mapped_column(String(254), nullable=False)
    tenant_id: Mapped[int | None] = mapped_column(ForeignKey("tenants.id", ondelete="SET NULL"), index=True)
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    target: Mapped[str] = mapped_column(Text, default="", nullable=False)
    details: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    ip: Mapped[str] = mapped_column(String(64), default="", nullable=False)


class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[dict] = mapped_column(JSONB, nullable=False)
    updated_at: Mapped[datetime] = TS(default=utcnow, onupdate=func.now(), nullable=False)



# ------------------------------------------------------------------ EVA (suporte por IA, por e-mail e API)
class EvaWhitelist(Base):
    """Quem pode pedir mudanças ao Eva. Donos (owner) incluem/removem pessoas; membros só pedem."""
    __tablename__ = "eva_whitelist"
    email: Mapped[str] = mapped_column(String(254), primary_key=True)
    name: Mapped[str] = mapped_column(String(160), default="", nullable=False)
    role: Mapped[str] = mapped_column(String(10), nullable=False)  # owner | member
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    added_by: Mapped[str] = mapped_column(String(254), default="", nullable=False)
    added_at: Mapped[datetime] = TS(default=utcnow, nullable=False)
    __table_args__ = (CheckConstraint("role in ('owner','member')", name="ck_eva_wl_role"),
                      CheckConstraint("email = lower(email)", name="ck_eva_wl_lower"))


class EvaThread(Base):
    """Conversa por e-mail (uma thread = uma sessão do agente)."""
    __tablename__ = "eva_threads"
    id: Mapped[int] = mapped_column(primary_key=True)
    subject: Mapped[str] = mapped_column(Text, default="", nullable=False)
    requester: Mapped[str] = mapped_column(String(254), nullable=False)
    state: Mapped[str] = mapped_column(String(24), default="em_andamento", nullable=False)
    # em_andamento | concluido | aguardando_trust | aguardando_rogerio | parado
    session_id: Mapped[str] = mapped_column(String(80), default="", nullable=False)
    message_ids: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)  # todos os Message-ID da conversa
    pending: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)       # próximos passos em aberto
    last_eva_at: Mapped[datetime | None] = TS()
    reminders_sent: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = TS(default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = TS(default=utcnow, onupdate=func.now(), nullable=False)


class EvaRequest(Base):
    __tablename__ = "eva_requests"
    id: Mapped[int] = mapped_column(primary_key=True)
    thread_id: Mapped[int] = mapped_column(ForeignKey("eva_threads.id", ondelete="CASCADE"), index=True, nullable=False)
    message_id: Mapped[str] = mapped_column(String(300), unique=True, nullable=False)
    sender: Mapped[str] = mapped_column(String(254), nullable=False)
    subject: Mapped[str] = mapped_column(Text, default="", nullable=False)
    received_at: Mapped[datetime] = TS(default=utcnow, nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(16), default="queued", nullable=False)  # queued|processing|done|failed
    intent: Mapped[str] = mapped_column(String(32), default="", nullable=False)
    summary: Mapped[str] = mapped_column(Text, default="", nullable=False)
    commit_sha: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    deployed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    rolled_back: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    reverted_by: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str] = mapped_column(Text, default="", nullable=False)
    reply_message_id: Mapped[str] = mapped_column(String(300), default="", nullable=False)
    details: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    finished_at: Mapped[datetime | None] = TS()


class EvaMessage(Base):
    """Mensagens de uma conversa com o Eva, dos dois canais (e-mail e API), de entrada e de saída."""
    __tablename__ = "eva_messages"
    id: Mapped[int] = mapped_column(primary_key=True)
    thread_id: Mapped[int] = mapped_column(ForeignKey("eva_threads.id", ondelete="CASCADE"), index=True, nullable=False)
    request_id: Mapped[int | None] = mapped_column(ForeignKey("eva_requests.id", ondelete="SET NULL"), index=True)
    direction: Mapped[str] = mapped_column(String(3), nullable=False)  # in | out
    channel: Mapped[str] = mapped_column(String(5), nullable=False)  # email | api
    author: Mapped[str] = mapped_column(String(254), nullable=False)
    subject: Mapped[str] = mapped_column(Text, default="", nullable=False)
    body_text: Mapped[str] = mapped_column(Text, default="", nullable=False)
    body_html: Mapped[str] = mapped_column(Text, default="", nullable=False)
    reply: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)  # resposta estruturada do Eva (saída)
    status_key: Mapped[str] = mapped_column(String(20), default="", nullable=False)
    status_text: Mapped[str] = mapped_column(String(300), default="", nullable=False)
    emailed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = TS(default=utcnow, nullable=False, index=True)
    attachments = relationship("EvaAttachment", order_by="EvaAttachment.id", lazy="selectin")


class EvaAttachment(Base):
    """Imagens enviadas pela API (entrada) e telas anexadas pelo Eva nas respostas (saída)."""
    __tablename__ = "eva_attachments"
    id: Mapped[int] = mapped_column(primary_key=True)
    message_id: Mapped[int] = mapped_column(ForeignKey("eva_messages.id", ondelete="CASCADE"), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    content_type: Mapped[str] = mapped_column(String(60), nullable=False)
    size: Mapped[int] = mapped_column(Integer, nullable=False)
    data: Mapped[bytes] = mapped_column(LargeBinary, nullable=False, deferred=True)
    created_at: Mapped[datetime] = TS(default=utcnow, nullable=False)



# ---------------------------------------------------------------- API (v1)
class ApiKey(Base):
    """Chave de API. O segredo nunca é gravado: só o prefixo público e o HMAC-SHA256 do segredo com o pepper do servidor."""
    __tablename__ = "api_keys"
    id: Mapped[int] = mapped_column(primary_key=True)
    prefix: Mapped[str] = mapped_column(String(16), unique=True, nullable=False)
    secret_hmac: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    owner_email: Mapped[str] = mapped_column(String(254), default="", nullable=False)
    tenant_id: Mapped[int | None] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    permissions: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    allowed_ips: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    rate_per_min: Mapped[int] = mapped_column(Integer, default=600, nullable=False)
    expires_at: Mapped[datetime] = TS(nullable=False)
    revoked_at: Mapped[datetime | None] = TS()
    revoked_by: Mapped[str] = mapped_column(String(254), default="", nullable=False)
    created_at: Mapped[datetime] = TS(default=utcnow, nullable=False)
    created_by: Mapped[str] = mapped_column(String(254), default="", nullable=False)
    last_used_at: Mapped[datetime | None] = TS()
    last_used_ip: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    replaced_by: Mapped[int | None] = mapped_column(ForeignKey("api_keys.id", ondelete="SET NULL"))
    protected: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)  # chave de sistema (gatilho no banco impede revogar/apagar)
    system_label: Mapped[str] = mapped_column(String(120), default="", nullable=False)
    tenant = relationship("Tenant")

    __table_args__ = (CheckConstraint("rate_per_min between 1 and 100000", name="ck_api_key_rate"),)

    @property
    def active(self) -> bool:
        return self.revoked_at is None and self.expires_at > utcnow()


class ApiUsageDaily(Base):
    __tablename__ = "api_usage_daily"
    key_id: Mapped[int] = mapped_column(ForeignKey("api_keys.id", ondelete="CASCADE"), primary_key=True)
    day: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    route: Mapped[str] = mapped_column(String(120), primary_key=True)
    status: Mapped[int] = mapped_column(Integer, primary_key=True)
    count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class ApiIdempotency(Base):
    """Respostas de POST guardadas por Idempotency-Key (24 h): repetir a chamada devolve o mesmo resultado sem duplicar."""
    __tablename__ = "api_idempotency"
    id: Mapped[int] = mapped_column(primary_key=True)
    key_id: Mapped[int] = mapped_column(ForeignKey("api_keys.id", ondelete="CASCADE"), nullable=False)
    idem_key: Mapped[str] = mapped_column(String(200), nullable=False)
    method: Mapped[str] = mapped_column(String(8), nullable=False)
    path: Mapped[str] = mapped_column(String(300), nullable=False)
    body_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[int] = mapped_column(Integer, nullable=False)
    response: Mapped[str] = mapped_column(Text, default="", nullable=False)
    location: Mapped[str] = mapped_column(String(300), default="", nullable=False)
    created_at: Mapped[datetime] = TS(default=utcnow, nullable=False, index=True)

    __table_args__ = (UniqueConstraint("key_id", "idem_key", name="uq_api_idempotency_key"),)


# ---------------------------------------------------------------- Trust Parser: parsers, fontes, destinos, eventos
class Parser(Base):
    """Parser de entrada (linha bruta → evento canônico) ou formato de saída (evento canônico → destino).
    O conteúdo executável fica nas versões (ParserVersion); a versão publicada é a que roda."""
    __tablename__ = "parsers"
    id: Mapped[int] = mapped_column(primary_key=True)
    updated_at: Mapped[datetime] = TS(server_default=func.now(), nullable=False)
    kind: Mapped[str] = mapped_column(String(8), nullable=False, default="input")  # input | output
    slug: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    vendor: Mapped[str] = mapped_column(String(80), default="", nullable=False)
    product: Mapped[str] = mapped_column(String(120), default="", nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    origin: Mapped[str] = mapped_column(String(10), default="builtin", nullable=False)  # builtin | studio | manual
    basis: Mapped[str] = mapped_column(String(10), default="real", nullable=False)  # real (amostra real) | docs (documentação)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=100, nullable=False)  # ordem na autodetecção (menor primeiro)
    current_version_id: Mapped[int | None] = mapped_column(ForeignKey("parser_versions.id", ondelete="SET NULL", use_alter=True))
    created_at: Mapped[datetime] = TS(default=utcnow, nullable=False)
    current_version = relationship("ParserVersion", foreign_keys=[current_version_id], post_update=True)
    __table_args__ = (CheckConstraint("kind in ('input','output')", name="ck_parser_kind"),)


class ParserVersion(Base):
    __tablename__ = "parser_versions"
    id: Mapped[int] = mapped_column(primary_key=True)
    parser_id: Mapped[int] = mapped_column(ForeignKey("parsers.id", ondelete="CASCADE"), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    spec: Mapped[dict] = mapped_column(JSONB, nullable=False)
    tests: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)  # [{input, expect:{caminho: valor}}]
    report: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)  # resultado dos testes na criação
    status: Mapped[str] = mapped_column(String(12), default="draft", nullable=False)  # draft|published|superseded|rejected
    notes: Mapped[str] = mapped_column(Text, default="", nullable=False)
    created_by: Mapped[str] = mapped_column(String(254), default="", nullable=False)
    created_at: Mapped[datetime] = TS(default=utcnow, nullable=False)
    published_by: Mapped[str] = mapped_column(String(254), default="", nullable=False)
    published_at: Mapped[datetime | None] = TS()
    studio_job_id: Mapped[int | None] = mapped_column(Integer)
    __table_args__ = (UniqueConstraint("parser_id", "version", name="uq_parser_version"),)


class Source(Base):
    """Origem de eventos de um tenant: syslog (identificada pelo IP de origem), upload ou conector de API."""
    __tablename__ = "sources"
    id: Mapped[int] = mapped_column(primary_key=True)
    updated_at: Mapped[datetime] = TS(server_default=func.now(), nullable=False)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    transport: Mapped[str] = mapped_column(String(10), nullable=False, default="syslog")  # syslog | upload | api
    parser_id: Mapped[int | None] = mapped_column(ForeignKey("parsers.id", ondelete="SET NULL"))  # None = autodetectar
    match_hostname: Mapped[str] = mapped_column(String(200), default="", nullable=False)  # regex opcional (várias fontes no mesmo IP)
    unparsed_policy: Mapped[str] = mapped_column(String(12), default="keep", nullable=False)  # keep | forward_raw | drop
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    note: Mapped[str] = mapped_column(Text, default="", nullable=False)
    # conector de API (transport = api)
    connector: Mapped[str] = mapped_column(String(40), default="", nullable=False)
    connector_config: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    secret_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    secret_set_at: Mapped[datetime | None] = TS()
    secret_set_by: Mapped[str] = mapped_column(String(254), default="", nullable=False)
    cursor: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    interval_s: Mapped[int] = mapped_column(Integer, default=300, nullable=False)
    next_run_at: Mapped[datetime | None] = TS()
    last_run_at: Mapped[datetime | None] = TS()
    last_status: Mapped[str] = mapped_column(String(8), default="pending", nullable=False)  # ok | err | pending
    last_error: Mapped[str] = mapped_column(Text, default="", nullable=False)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # saúde
    last_event_at: Mapped[datetime | None] = TS()
    events_total: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    parsed_total: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    unparsed_total: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    silence_alert_minutes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)  # 0 = não avisar fonte parada
    alerted_at: Mapped[datetime | None] = TS()
    created_at: Mapped[datetime] = TS(default=utcnow, nullable=False)
    tenant = relationship("Tenant")
    parser = relationship("Parser")
    __table_args__ = (CheckConstraint("transport in ('syslog','upload','api')", name="ck_source_transport"),
                      CheckConstraint("unparsed_policy in ('keep','forward_raw','drop')", name="ck_source_unparsed"),
                      UniqueConstraint("tenant_id", "name", name="uq_source_tenant_name"))


class AllowedIP(Base):
    """IP/faixa liberada no firewall para enviar syslog (aplicada no host pelo trustparser-fw)."""
    __tablename__ = "allowed_ips"
    id: Mapped[int] = mapped_column(primary_key=True)
    updated_at: Mapped[datetime] = TS(server_default=func.now(), nullable=False)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    source_id: Mapped[int | None] = mapped_column(ForeignKey("sources.id", ondelete="CASCADE"), index=True)
    cidr: Mapped[str] = mapped_column(String(64), nullable=False)
    protocols: Mapped[list] = mapped_column(JSONB, default=lambda: ["tls"], nullable=False)  # tls | tcp | udp
    description: Mapped[str] = mapped_column(String(200), default="", nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    expires_at: Mapped[datetime | None] = TS()
    created_by: Mapped[str] = mapped_column(String(254), default="", nullable=False)
    created_at: Mapped[datetime] = TS(default=utcnow, nullable=False)
    tenant = relationship("Tenant")
    source = relationship("Source")


class Destination(Base):
    """Destino dos eventos parseados de um tenant (SecOps, Wazuh, QRadar, syslog, webhook)."""
    __tablename__ = "destinations"
    id: Mapped[int] = mapped_column(primary_key=True)
    updated_at: Mapped[datetime] = TS(server_default=func.now(), nullable=False)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    format: Mapped[str] = mapped_column(String(80), nullable=False)  # código do formato (udm, wazuh_json, leef, cef, ocsf_json...) ou slug de saída
    config: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    secret_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    secret_set_at: Mapped[datetime | None] = TS()
    secret_set_by: Mapped[str] = mapped_column(String(254), default="", nullable=False)
    filters: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)  # {source_ids:[], min_severity_id:int}
    include_unparsed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    batch_size: Mapped[int] = mapped_column(Integer, default=200, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    status: Mapped[str] = mapped_column(String(8), default="pending", nullable=False)  # ok | err | pending
    last_ok_at: Mapped[datetime | None] = TS()
    last_error: Mapped[str] = mapped_column(Text, default="", nullable=False)
    last_error_at: Mapped[datetime | None] = TS()
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    sent_total: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    failed_total: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    paused_until: Mapped[datetime | None] = TS()
    alerted_at: Mapped[datetime | None] = TS()
    created_at: Mapped[datetime] = TS(default=utcnow, nullable=False)
    tenant = relationship("Tenant")
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_destination_tenant_name"),)


class Upload(Base):
    __tablename__ = "uploads"
    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    source_id: Mapped[int | None] = mapped_column(ForeignKey("sources.id", ondelete="SET NULL"))
    parser_id: Mapped[int | None] = mapped_column(ForeignKey("parsers.id", ondelete="SET NULL"))
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    size: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    lines: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    parsed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    unparsed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    send_to_destinations: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    status: Mapped[str] = mapped_column(String(12), default="queued", nullable=False)  # queued|processing|done|failed|expired
    error: Mapped[str] = mapped_column(Text, default="", nullable=False)
    created_by: Mapped[str] = mapped_column(String(254), default="", nullable=False)
    created_at: Mapped[datetime] = TS(default=utcnow, nullable=False, index=True)
    finished_at: Mapped[datetime | None] = TS()
    expires_at: Mapped[datetime] = TS(nullable=False)
    tenant = relationship("Tenant")
    source = relationship("Source")
    parser = relationship("Parser")


class Event(Base):
    """Buffer de eventos (curto): bruto + evento canônico. Expurgado em 2 h (24 h se ainda não entregue)."""
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    tenant_id: Mapped[int | None] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    source_id: Mapped[int | None] = mapped_column(ForeignKey("sources.id", ondelete="CASCADE"))
    upload_id: Mapped[int | None] = mapped_column(ForeignKey("uploads.id", ondelete="CASCADE"))
    received_at: Mapped[datetime] = TS(default=utcnow, nullable=False)
    peer_ip: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    transport: Mapped[str] = mapped_column(String(8), default="", nullable=False)  # tls|tcp|udp|upload|api
    line_no: Mapped[int | None] = mapped_column(Integer)
    raw: Mapped[str] = mapped_column(Text, nullable=False)
    event: Mapped[dict | None] = mapped_column(JSONB)
    parser_version_id: Mapped[int | None] = mapped_column(ForeignKey("parser_versions.id", ondelete="SET NULL"))
    status: Mapped[str] = mapped_column(String(10), default="received", nullable=False)  # received|parsed|unparsed|ignored
    error: Mapped[str] = mapped_column(Text, default="", nullable=False)
    pending_deliveries: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    __table_args__ = (Index("ix_events_received", "received_at"), Index("ix_events_status_id", "status", "id"),
                      Index("ix_events_source_received", "source_id", "received_at"), Index("ix_events_upload", "upload_id", "line_no"))


class EventDelivery(Base):
    __tablename__ = "event_deliveries"
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"), primary_key=True)
    destination_id: Mapped[int] = mapped_column(ForeignKey("destinations.id", ondelete="CASCADE"), primary_key=True)
    status: Mapped[str] = mapped_column(String(8), default="pending", nullable=False)  # pending|sent|failed|dropped
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    next_attempt_at: Mapped[datetime] = TS(default=utcnow, nullable=False)
    last_error: Mapped[str] = mapped_column(Text, default="", nullable=False)
    sent_at: Mapped[datetime | None] = TS()
    __table_args__ = (Index("ix_event_deliveries_pending", "destination_id", "status", "next_attempt_at"),)


class StudioJob(Base):
    """Pedido ao Estúdio IA: novo parser de entrada, novo formato de saída ou ajuste de parser existente."""
    __tablename__ = "studio_jobs"
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(8), nullable=False)  # input | output | fix
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    vendor: Mapped[str] = mapped_column(String(80), default="", nullable=False)
    product: Mapped[str] = mapped_column(String(120), default="", nullable=False)
    request: Mapped[str] = mapped_column(Text, default="", nullable=False)
    samples: Mapped[str] = mapped_column(Text, default="", nullable=False)
    docs: Mapped[str] = mapped_column(Text, default="", nullable=False)
    docs_urls: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    mask_data: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    parser_id: Mapped[int | None] = mapped_column(ForeignKey("parsers.id", ondelete="SET NULL"))
    result_version_id: Mapped[int | None] = mapped_column(ForeignKey("parser_versions.id", ondelete="SET NULL"))
    status: Mapped[str] = mapped_column(String(10), default="queued", nullable=False)  # queued|running|done|failed|approved|rejected
    report: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    log: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    ai_model: Mapped[str] = mapped_column(String(80), default="", nullable=False)
    ai_calls: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    ai_cost_usd: Mapped[float] = mapped_column(Float, default=0, nullable=False)
    error: Mapped[str] = mapped_column(Text, default="", nullable=False)
    requested_by: Mapped[str] = mapped_column(String(254), default="", nullable=False)
    created_at: Mapped[datetime] = TS(default=utcnow, nullable=False, index=True)
    started_at: Mapped[datetime | None] = TS()
    finished_at: Mapped[datetime | None] = TS()
    decided_by: Mapped[str] = mapped_column(String(254), default="", nullable=False)
    decided_at: Mapped[datetime | None] = TS()
    parser = relationship("Parser")


class MetricMinute(Base):
    """Contadores por minuto (fonte: recebidos/parseados/não reconhecidos; destino: enviados/falhas). Mantidos 7 dias."""
    __tablename__ = "metrics_minute"
    minute: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    kind: Mapped[str] = mapped_column(String(1), primary_key=True)  # s = fonte | d = destino
    ref_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    a: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    b: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    c: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
