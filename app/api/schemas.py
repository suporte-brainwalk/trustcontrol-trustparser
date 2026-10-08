"""Esquemas (Pydantic v2) de parâmetros e respostas da API v1. Deles sai o JSON Schema publicado no OpenAPI."""
from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["critical", "high", "medium", "low", "unknown"]


class Out(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Query(BaseModel):
    model_config = ConfigDict(extra="forbid")


class In(BaseModel):
    """Corpo de requisição de escrita: campos desconhecidos são recusados (evita erro silencioso de digitação)."""
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


Short = Annotated[str, Field(max_length=120)]
Term = Annotated[str, Field(max_length=200)]


class PageQuery(Query):
    limit: int = Field(50, ge=1, le=200, description="Itens por página (máx. 200).")
    cursor: str | None = Field(None, max_length=500, description="Valor de `next_cursor` da página anterior.")


class Problem(Out):
    """Erro no formato RFC 9457."""
    type: str
    title: str
    status: int
    detail: str
    request_id: str
    errors: list[dict] | None = None


class Health(Out):
    status: Literal["ok"] = "ok"


class TenantRef(Out):
    id: int
    name: str


class Me(Out):
    """A chave que fez a chamada."""
    name: str = Field(description="Sistema consumidor.")
    prefix: str = Field(description="Parte pública da chave (tpk_live_<prefixo>…).")
    scope: Literal["global", "tenant"]
    tenant: TenantRef | None = None
    permissions: list[str]
    rate_per_min: int
    allowed_ips: list[str]
    expires_at: datetime


# ---------------------------------------------------------------- referências
class VendorRef(Out):
    id: int
    name: str


class ProductRef(Out):
    id: int
    name: str


# ---------------------------------------------------------------- parâmetros
class VulnQuery(PageQuery):
    severity: list[Severity] | Severity | None = Field(None, description="Uma ou mais severidades (repita o parâmetro).")
    vendor_id: int | None = Field(None, ge=1, description="Somente deste fabricante.")
    kev: bool | None = Field(None, description="true = só as da lista CISA KEV (exploração ativa).")
    affected: bool | None = Field(None, description="true = só as que geraram alerta para algum tenant.")
    tenant_id: int | None = Field(None, ge=1, description="Só as que geraram alerta para este tenant (chave global).")
    q: str | None = Field(None, min_length=2, max_length=100, description="Busca no identificador (CVE/advisory), no título e no nome do fabricante.")
    detected_from: datetime | None = Field(None, description="Detectadas a partir de (ISO-8601).")
    detected_to: datetime | None = Field(None, description="Detectadas antes de (ISO-8601).")
    published_from: datetime | None = Field(None, description="Publicadas pelo fabricante a partir de (ISO-8601).")
    published_to: datetime | None = Field(None, description="Publicadas pelo fabricante antes de (ISO-8601).")
    updated_since: datetime | None = Field(None, description="Sincronização incremental: alteradas desde (ordem crescente de alteração).")


class AlertQuery(PageQuery):
    tenant_id: int | None = Field(None, ge=1, description="Somente deste tenant (chave global).")
    created_from: datetime | None = Field(None, description="Criados a partir de (ISO-8601).")
    created_to: datetime | None = Field(None, description="Criados antes de (ISO-8601).")
    updated_since: datetime | None = Field(None, description="Sincronização incremental.")


class TenantQuery(PageQuery):
    status: Literal["active", "suspended"] | None = None
    updated_since: datetime | None = Field(None, description="Sincronização incremental.")


class ProductQuery(PageQuery):
    vendor_id: int | None = Field(None, ge=1)
    active: bool | None = None


class SimpleListQuery(PageQuery):
    pass


# ---------------------------------------------------------------- vulnerabilidades
class Analysis(Out):
    status: str = Field(description="done = análise pronta; pending = em redação; skipped = não afetou tenant (sem análise).")
    description_pt: str = ""
    html: str = Field("", description="Análise, impacto e remediação em HTML simples (h3, p, ul/ol, li, strong).")


class AffectedTenant(Out):
    id: int
    name: str
    reason: Literal["threshold", "kev"] = Field(description="threshold = atingiu o limite do tenant; kev = exploração ativa.")
    alert_id: int


class VulnerabilityItem(Out):
    id: int
    key: str = Field(description="CVE ou identificador do advisory.")
    cve_ids: list[str]
    vendor: VendorRef | None
    products: list[ProductRef]
    title: str = Field(description="Título no idioma original do fabricante.")
    severity: Severity
    cvss: float | None
    kev: bool
    epss: float | None
    published_at: datetime | None
    detected_at: datetime
    updated_at: datetime
    advisory_url: str
    analysis_status: str
    affected_tenants: list[AffectedTenant]


class VulnerabilityDetail(VulnerabilityItem):
    advisory_id: str
    description: str = Field(description="Descrição original do fabricante.")
    cvss_vector: str
    kev_added_at: datetime | None
    affected_versions: str
    fixes: list
    cpes: list[str]
    analysis: Analysis


# ---------------------------------------------------------------- alertas
class AlertVuln(Out):
    id: int
    key: str
    title: str
    severity: Severity
    kev: bool


class AlertItemOut(Out):
    vulnerability: AlertVuln
    reason: Literal["threshold", "kev"]


class DeliveryOut(Out):
    recipient: str
    status: Literal["sent", "pending", "failed"]
    sent_at: datetime | None


class DeliverySummary(Out):
    total: int
    sent: int
    pending: int
    failed: int
    recipients: list[DeliveryOut] | None = Field(None, description="Por destinatário — somente com a permissão pessoas:ler.")


class AlertOut(Out):
    id: int
    tenant: TenantRef
    vendor: VendorRef | None
    status: str
    subject: str
    created_at: datetime
    sent_at: datetime | None
    updated_at: datetime
    items: list[AlertItemOut]
    deliveries: DeliverySummary


# ---------------------------------------------------------------- tenants
class TenantCounts(Out):
    assets: int
    people_with_access: int
    email_recipients: int
    alerted_vulnerabilities: int


class TenantOut(Out):
    id: int
    name: str
    segment: str
    internal: bool
    status: Literal["active", "suspended"]
    alert_threshold: Literal["critical", "high", "medium", "low"] = Field(description="Severidade mínima para alerta imediato.")
    daily_newsletter: bool
    all_vendors: bool = Field(description="true = recebe alertas de todos os fabricantes, ignorando o parque.")
    created_at: datetime
    updated_at: datetime
    counts: TenantCounts


class AssetOut(Out):
    id: int
    vendor: VendorRef
    product: ProductRef
    model: str
    version: str
    criticality: Literal["high", "medium", "low"]
    quantity: int | None
    updated_at: datetime


class PersonOut(Out):
    name: str
    email: str
    title: str
    kind: Literal["person", "list"]
    portal_access: Literal["none", "reader", "manager", "admin"] = Field(description="admin = administrador do portal.")
    access_status: Literal["invited", "active", "suspended"] | None
    receives_emails: bool = Field(description="Recebe alertas imediatos e a newsletter do tenant.")


# ---------------------------------------------------------------- catálogo
class ProductOut(Out):
    id: int
    vendor: VendorRef
    name: str
    models: list[str]
    correlation_terms: list[str] = Field(description="Nomes alternativos, CPEs e exclusões (prefixo !).")
    active: bool
    updated_at: datetime


class VendorOut(Out):
    id: int
    name: str
    active: bool
    updated_at: datetime
    products: list[ProductOut]


# ---------------------------------------------------------------- fontes
class SourceDay(Out):
    day: datetime
    checks: int
    failures: int
    avg_ms: int
    new_items: int


class SourceOut(Out):
    id: int
    vendor: VendorRef | None
    name: str
    kind: str
    url: str
    active: bool
    status: Literal["ok", "warn", "err", "pending"]
    note: str
    interval_seconds: int
    consecutive_failures: int
    last_run_at: datetime | None
    last_ok_at: datetime | None
    last_http_status: int | None
    last_ms: int | None
    last_items: int | None
    params: dict = Field(default_factory=dict, description="Parâmetros do leitor (seletores, caminhos JSON, palavra-chave da NVD…).")
    title_filter: str = Field("", description="Só itens cujo título contém este termo (vazio = todos).")
    updated_at: datetime


class SourceDetail(SourceOut):
    daily: list[SourceDay] = Field(description="Resumo por dia (últimos 30 dias).")


# ---------------------------------------------------------------- newsletter
class NewsletterOut(Out):
    id: int
    date: str = Field(description="Data da edição (DD/MM/AAAA).")
    title: str
    published_at: datetime | None
    sent_at: datetime | None
    item_count: int


class NewsItem(Out):
    title: str
    summary: str
    category: str
    severity: str
    subjects: list[str]
    source: str = Field(description="Veículo que publicou a notícia.")
    url: str
    published_at: str | None
    matches: list[str] = Field(description="Fabricantes do parque do tenant citados na notícia (selo 🎯). Vazio para chave global.")


class NewsletterDetail(NewsletterOut):
    items: list[NewsItem]


# ---------------------------------------------------------------- indicadores
class Stats(Out):
    scope: Literal["global", "tenant"]
    tenants_active: int | None = None
    tenants_suspended: int | None = None
    monitored_products: int
    vendors_active: int | None = None
    alerts_7d: int
    alerted_vulnerabilities_7d: int
    kev_7d: int
    vulnerabilities_24h: int | None = None
    sources_ok: int | None = None
    sources_warn: int | None = None
    sources_err: int | None = None
    last_scan_at: datetime | None = None


# ================================================================ escrita (modo administração)
# ---------------------------------------------------------------- catálogo
class VendorCreate(In):
    name: str = Field(min_length=1, max_length=120, description="Nome do fabricante (único).")
    product: str | None = Field(None, max_length=160, description="Primeiro produto (opcional).")
    models: list[Short] = Field(default_factory=list, max_length=60, description="Modelos do primeiro produto (opcional).")


class VendorUpdate(In):
    name: str | None = Field(None, min_length=1, max_length=120, description="Novo nome.")
    active: bool | None = Field(None, description="false = inativa (só se nenhum cliente tiver produtos dele no parque).")


class ProductCreate(In):
    name: str = Field(min_length=1, max_length=160, description="Nome do produto (único no fabricante).")
    models: list[Short] = Field(default_factory=list, max_length=60)
    correlation_terms: list[Term] | None = Field(None, max_length=60, description="Termos de correlação, CPEs e exclusões (prefixo !). Padrão: o nome.")
    active: bool = True


class ProductUpdate(In):
    name: str | None = Field(None, min_length=1, max_length=160)
    models: list[Short] | None = Field(None, max_length=60, description="Lista completa (substitui). Modelos em uso por clientes não podem sair.")
    correlation_terms: list[Term] | None = Field(None, max_length=60, description="Lista completa (substitui).")
    active: bool | None = None


# ---------------------------------------------------------------- tenants e parque
Threshold = Literal["critical", "high", "medium", "low"]
Criticality = Literal["high", "medium", "low"]


class ManagerIn(In):
    name: str | None = Field(None, max_length=160)
    email: str = Field(min_length=3, max_length=254, description="Recebe o convite de acesso como gestor do tenant.")


class TenantCreate(In):
    name: str = Field(min_length=1, max_length=160, description="Nome do tenant (único).")
    segment: str = Field("", max_length=60)
    internal: bool = Field(False, description="Tenant interno da Trust Control.")
    alert_threshold: Threshold | None = Field(None, description="Severidade mínima para alerta imediato. Padrão: o da configuração do portal.")
    daily_newsletter: bool = True
    all_vendors: bool = Field(False, description="true = recebe alertas de todos os fabricantes, ignorando o parque.")
    manager: ManagerIn | None = Field(None, description="Gestor do tenant: recebe o convite de acesso por e-mail na hora.")


class TenantUpdate(In):
    name: str | None = Field(None, min_length=1, max_length=160)
    segment: str | None = Field(None, max_length=60)
    internal: bool | None = None
    alert_threshold: Threshold | None = None
    daily_newsletter: bool | None = None
    all_vendors: bool | None = None
    status: Literal["active", "suspended"] | None = Field(None, description="suspended = deixa de receber alertas e newsletter (não há exclusão).")


class AssetIn(In):
    product_id: int = Field(ge=1)
    model: str = Field("", max_length=120)
    version: str = Field("", max_length=80)
    criticality: Criticality = "medium"
    quantity: int | None = Field(None, ge=0, le=1_000_000)


class AssetsAdd(In):
    items: list[AssetIn] = Field(min_length=1, max_length=100, description="De 1 a 100 itens; tudo ou nada.")


class AssetUpdate(In):
    model: str | None = Field(None, max_length=120)
    version: str | None = Field(None, max_length=80)
    criticality: Criticality | None = None
    quantity: int | None = Field(None, ge=0, le=1_000_000, description="null limpa a quantidade.")


class AssetBatch(Out):
    data: list[AssetOut]


# ---------------------------------------------------------------- pessoas
class PersonCreate(In):
    name: str = Field(min_length=1, max_length=160)
    email: str = Field(min_length=3, max_length=254)
    portal_access: Literal["none", "reader", "manager"] = Field("none", description="Acesso ao portal; reader/manager recebem convite por e-mail na hora.")
    receives_emails: bool = Field(True, description="Recebe alertas imediatos e a newsletter do tenant.")
    title: str = Field("", max_length=120, description="Cargo.")
    kind: Literal["person", "list"] = Field("person", description="list = lista ou grupo de e-mail (não entra no portal).")


class PersonUpdate(In):
    name: str | None = Field(None, min_length=1, max_length=160)
    title: str | None = Field(None, max_length=120)
    portal_access: Literal["none", "reader", "manager"] | None = Field(None, description="none tira o acesso (desativa o login).")
    receives_emails: bool | None = None


# ---------------------------------------------------------------- fontes
SourceKind = Literal["rss", "json_api", "csaf_rolie", "msrc_cvrf", "html_css", "nvd_cpe", "nvd_keyword"]
ParamValue = str | int | float | bool | dict | list


class SourceCreate(In):
    name: str = Field(min_length=1, max_length=160)
    kind: SourceKind = Field(description="Leitor: rss, json_api, csaf_rolie, msrc_cvrf, html_css, nvd_cpe ou nvd_keyword.")
    url: str = Field(min_length=9, max_length=2000, description="Endereço https:// da fonte.")
    params: dict[str, ParamValue] = Field(default_factory=dict, max_length=40, description="Parâmetros do leitor (os mesmos da tela).")
    title_filter: str = Field("", max_length=200)
    interval_seconds: int | None = Field(None, ge=60, le=86400, description="Ciclo de leitura. Padrão: 60 s (300 s para NVD e HTML).")
    vendor_id: int | None = Field(None, ge=1, description="Fabricante da fonte.")
    active: bool = True


class SourceUpdate(In):
    name: str | None = Field(None, min_length=1, max_length=160)
    kind: SourceKind | None = None
    url: str | None = Field(None, min_length=9, max_length=2000)
    params: dict[str, ParamValue] | None = Field(None, max_length=40, description="Substitui todos os parâmetros.")
    title_filter: str | None = Field(None, max_length=200)
    interval_seconds: int | None = Field(None, ge=60, le=86400)
    vendor_id: int | None = Field(None, ge=1, description="null desvincula do fabricante.")
    active: bool | None = Field(None, description="false pausa a fonte; true retoma.")


class SourceTest(SourceUpdate):
    """Configuração a testar. Com `source_id`, os campos enviados sobrepõem os da fonte existente."""
    source_id: int | None = Field(None, ge=1)


class SourceTestItem(Out):
    external_id: str
    title: str
    url: str
    published_at: datetime | None
    cve_ids: list[str]
    severity: str


class SourceTestResult(Out):
    ok: bool = Field(description="true = leu com sucesso e encontrou itens.")
    http_status: int | None
    ms: int
    error: str
    items: list[SourceTestItem] = Field(description="Até 10 itens lidos (nada é gravado).")


# ---------------------------------------------------------------- Jarbas
ThreadState = Literal["em_andamento", "concluido", "aguardando_trust", "aguardando_rogerio", "parado"]


class JarbasStatus(Out):
    online: bool = Field(description="Sinal de vida do Jarbas nos últimos 5 minutos.")
    last_signal_at: datetime | None
    mode: Literal["ativo", "demo"] = Field(description="ativo = atende toda a whitelist; demo = só o Rogério (freio de emergência).")
    queued: int = Field(description="Pedidos na fila.")
    processing: int
    processing_request: int | None = Field(description="Pedido em execução agora.")
    ai_access_ok: bool | None = Field(description="Acesso à IA do servidor válido.")
    email_in_ok: bool | None
    email_out_ok: bool | None


class JarbasWhitelistEntry(Out):
    email: str
    name: str
    role: Literal["owner", "member"] = Field(description="owner = dono (altera a whitelist); member = pode pedir.")
    active: bool
    added_by: str
    added_at: datetime


class JarbasRequestOut(Out):
    id: int
    channel: Literal["email", "api"]
    sender: str
    subject: str
    received_at: datetime
    status: Literal["queued", "processing", "done", "failed"]
    intent: str = Field(description="Tipo do pedido identificado pelo Jarbas (suporte, consulta, alteração…).")
    summary: str = Field(description="Resumo do que foi feito (sem o conteúdo dos e-mails).")
    commit: str | None = Field(description="Commit publicado, quando houve alteração do portal.")
    deployed: bool
    rolled_back: bool
    finished_at: datetime | None


class JarbasThreadOut(Out):
    id: int
    subject: str
    requester: str
    state: ThreadState
    pending: list[str] = Field(description="Próximos passos em aberto.")
    created_at: datetime
    updated_at: datetime
    last_jarbas_at: datetime | None


class JarbasThreadDetail(JarbasThreadOut):
    requests: list[JarbasRequestOut]


class JarbasThreadQuery(PageQuery):
    state: ThreadState | None = None


class WhitelistAdd(In):
    email: str = Field(min_length=3, max_length=254)
    name: str = Field("", max_length=160)


class ThreadUpdate(In):
    state: Literal["em_andamento", "concluido", "parado"]


# ---------------------------------------------------------------- conversa com o Jarbas
class ImageIn(In):
    name: str = Field("", max_length=120)
    content_type: Literal["image/png", "image/jpeg", "image/webp"]
    data: str = Field(min_length=8, max_length=7_000_000, description="Conteúdo da imagem em base64 (até 5 MB somando todas).")


class ConversationCreate(In):
    subject: str = Field(min_length=1, max_length=300)
    message: str = Field(min_length=1, max_length=20000, description="O pedido, como seria escrito no e-mail.")
    images: list[ImageIn] = Field(default_factory=list, max_length=4, description="Até 4 imagens (prints de tela, por exemplo).")
    cc: list[str] = Field(default_factory=list, max_length=10, description="Pessoas que também recebem a resposta por e-mail.")
    email_copy: bool = Field(True, description="true = além de ficar na API, a resposta sai pelo e-mail de sempre (para o responsável da chave e cc).")


class MessageCreate(In):
    message: str = Field(min_length=1, max_length=20000, description="Continuação da conversa — inclusive a resposta a uma confirmação do Jarbas.")
    images: list[ImageIn] = Field(default_factory=list, max_length=4)
    cc: list[str] = Field(default_factory=list, max_length=10)
    email_copy: bool = True


class ConversationAccepted(Out):
    conversation_id: int
    request_id: int
    message_id: int
    status: Literal["queued"] = "queued"
    queue_position: int = Field(description="Posição na fila do Jarbas (1 = o próximo).")
    poll: str = Field(description="Onde acompanhar a resposta (long polling).")


class AttachmentOut(Out):
    id: int
    name: str
    content_type: str
    size: int
    url: str = Field(description="Download autenticado (mesma chave).")


class MessageOut(Out):
    id: int
    direction: Literal["in", "out"] = Field(description="in = enviada ao Jarbas; out = resposta do Jarbas.")
    channel: Literal["email", "api"]
    author: str
    created_at: datetime
    subject: str
    text: str = Field(description="Texto da mensagem (na resposta do Jarbas, em texto simples).")
    html: str | None = Field(None, description="Resposta do Jarbas em HTML, idêntica ao e-mail.")
    status: str | None = Field(None, description="Resultado da resposta: publicado, sem_mudanca, nao_publicado, desfeito…")
    status_text: str | None = None
    reply: dict | None = Field(None, description="Resposta estruturada: saudacao, paragrafos, o_que_fiz, proximos_passos_*, fechamento…")
    request_id: int | None
    attachments: list[AttachmentOut]


class ConversationDetail(JarbasThreadOut):
    messages: list[MessageOut]
    requests: list[JarbasRequestOut]


class MessagesQuery(Query):
    after: int = Field(0, ge=0, description="Só mensagens com id maior que este (o último que você já recebeu).")
    wait: int = Field(0, ge=0, le=25, description="Segundos para segurar a conexão esperando novidade (long polling, até 25).")
