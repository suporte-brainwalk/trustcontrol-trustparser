"""Base dos conectores API PULL: contrato, cliente HTTP, retry/backoff e controle de cursor.

Cada conector coleta objetos JSON de uma API SaaS e devolve uma linha por objeto (JSON compacto), que o parser builtin
indicado em `parser_slug` interpreta. O cursor é um dict serializável em JSON (persistido pelo agendador entre execuções).

Regras de segurança: nenhum segredo é registrado em log nem incluído em mensagens de erro (ConnectorError é exibida ao
usuário); TLS sempre verificado; redirects não são seguidos (evita vazar o token para outro host).
"""
from __future__ import annotations

import email.utils
import importlib
import json
import logging
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterator
from urllib.parse import urlsplit

import httpx

log = logging.getLogger("trustparser.connectors")

USER_AGENT = "TrustParser/1.0"
MAX_OBJECTS = 5000           # máximo de objetos por chamada de pull(); acima disso more=True
MAX_TRIES = 3                # tentativas por requisição (429/5xx/erro de rede)
MAX_RETRY_WAIT = 60.0        # teto do Retry-After honrado (s)
BOUNDARY_MAX = 500           # máximo de ids guardados no cursor para dedupe na fronteira do watermark
RETRY_STATUSES = {429, 500, 502, 503, 504}

# Pontos de injeção para testes (sem dormir de verdade / relógio fixo).
_sleep: Callable[[float], None] = time.sleep


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------------------------------------------------
# Contrato
# --------------------------------------------------------------------------------------------------------------------
@dataclass
class Field:
    name: str
    label: str
    kind: str = "text"  # text|url|select|number|secret
    required: bool = True
    help: str = ""
    options: list[tuple[str, str]] | None = None
    default: str = ""


class ConnectorError(Exception):
    """Erro exibível ao usuário (pt-BR). Nunca contém segredos."""


@dataclass
class PullResult:
    lines: list[str]
    cursor: dict
    more: bool = False
    note: str = ""


class Connector:
    slug: str = ""
    name: str = ""
    vendor: str = ""
    parser_slug: str = ""
    fields: list[Field] = []
    secret_fields: list[Field] = []
    default_interval_s: int = 300

    def test(self, config: dict, secrets: dict, client: httpx.Client | None = None) -> str:
        raise NotImplementedError

    def pull(self, config: dict, secrets: dict, cursor: dict, client: httpx.Client | None = None) -> PullResult:
        raise NotImplementedError

    # -- utilidades comuns ------------------------------------------------------------------------------------------
    def schema(self) -> dict:
        """Descrição serializável para montar o formulário na GUI."""
        return {
            "slug": self.slug, "name": self.name, "vendor": self.vendor, "parser_slug": self.parser_slug,
            "default_interval_s": self.default_interval_s,
            "fields": [asdict(f) for f in self.fields],
            "secret_fields": [asdict(f) for f in self.secret_fields],
        }

    def validate(self, config: dict, secrets: dict) -> None:
        missing = [f.label for f in self.fields if f.required and not str(config.get(f.name) or f.default or "").strip()]
        missing += [f.label for f in self.secret_fields if f.required and not str(secrets.get(f.name) or "").strip()]
        if missing:
            raise ConnectorError("Preencha os campos obrigatórios: " + ", ".join(missing) + ".")

    def cfg(self, config: dict, name: str) -> str:
        """Valor de configuração (string sem espaços) com fallback para o default do Field."""
        v = config.get(name)
        if v is None or str(v).strip() == "":
            for f in self.fields:
                if f.name == name:
                    return f.default
            return ""
        return str(v).strip()

    def first_start(self, config: dict, now: datetime | None = None) -> datetime:
        """Início da 1ª coleta (cursor vazio), respeitando o default de lookback_minutes do conector."""
        return lookback_start({"lookback_minutes": self.cfg(config, "lookback_minutes") or 60}, now)

    def http(self, secrets: dict | None = None) -> "Http":
        return Http(self.vendor, secrets)


REGISTRY: dict[str, Connector] = {}


def register(cls: type[Connector]) -> type[Connector]:
    REGISTRY[cls.slug] = cls()
    return cls


def get(slug: str) -> Connector:
    if not REGISTRY:
        importlib.import_module(__package__)  # popula o registro (importa todos os módulos)
    try:
        return REGISTRY[slug]
    except KeyError:
        raise ConnectorError(f"Conector desconhecido: {slug}.") from None


# --------------------------------------------------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------------------------------------------------
def make_client() -> httpx.Client:
    return httpx.Client(
        timeout=httpx.Timeout(30.0, connect=10.0),
        headers={"User-Agent": USER_AGENT},
        follow_redirects=False,
        verify=True,
    )


@contextmanager
def client_scope(client: httpx.Client | None) -> Iterator[httpx.Client]:
    if client is not None:
        yield client
        return
    c = make_client()
    try:
        yield c
    finally:
        c.close()


def _retry_after(resp: httpx.Response, attempt: int) -> float:
    ra = resp.headers.get("Retry-After") or resp.headers.get("retry-after")
    if ra:
        ra = ra.strip()
        try:
            return min(max(float(ra), 0.0), MAX_RETRY_WAIT)
        except ValueError:
            try:
                dt = email.utils.parsedate_to_datetime(ra)
                return min(max((dt - utcnow()).total_seconds(), 0.0), MAX_RETRY_WAIT)
            except (TypeError, ValueError):
                pass
    return float(2 ** attempt)  # 1s, 2s, 4s…


class Http:
    """Requisições com retry/backoff e mapeamento de erros para ConnectorError (pt-BR, sem segredos)."""

    def __init__(self, vendor: str, secrets: dict | None = None):
        self.vendor = vendor
        self._secret_values = [str(v) for v in (secrets or {}).values() if v and len(str(v)) >= 4]

    def scrub(self, text: str) -> str:
        for s in self._secret_values:
            text = text.replace(s, "***")
        return text

    def request(self, client: httpx.Client, method: str, url: str, *, ok: tuple[int, ...] = (), **kw) -> httpx.Response:
        headers = {"User-Agent": USER_AGENT, **(kw.pop("headers", None) or {})}
        path = urlsplit(url).path
        last_exc: Exception | None = None
        for attempt in range(MAX_TRIES):
            try:
                resp = client.request(method, url, headers=headers, **kw)
            except httpx.TimeoutException as exc:
                last_exc = exc
                log.warning("%s %s %s: timeout (tentativa %d)", self.vendor, method, path, attempt + 1)
            except httpx.TransportError as exc:
                last_exc = exc
                log.warning("%s %s %s: erro de rede %s (tentativa %d)", self.vendor, method, path,
                            type(exc).__name__, attempt + 1)
            else:
                log.debug("%s %s %s → %d", self.vendor, method, path, resp.status_code)
                if resp.status_code in RETRY_STATUSES and attempt < MAX_TRIES - 1:
                    wait = _retry_after(resp, attempt)
                    log.info("%s %s %s → HTTP %d; nova tentativa em %.1fs", self.vendor, method, path,
                             resp.status_code, wait)
                    _sleep(wait)
                    continue
                self.check(resp, ok)
                return resp
            if attempt < MAX_TRIES - 1:
                _sleep(float(2 ** attempt))
        host = urlsplit(url).hostname or "?"
        if isinstance(last_exc, httpx.TimeoutException):
            raise ConnectorError(f"Tempo esgotado ao acessar {self.vendor} ({host}) após {MAX_TRIES} tentativas.")
        if isinstance(last_exc, httpx.ConnectError):
            raise ConnectorError(f"Não foi possível conectar a {self.vendor} ({host}). Verifique a URL/região e o DNS.")
        raise ConnectorError(f"Falha de comunicação com {self.vendor} ({host}).")

    def check(self, resp: httpx.Response, ok: tuple[int, ...] = ()) -> None:
        code = resp.status_code
        if code in ok or 200 <= code < 300:
            return
        if code in (401, 403):
            raise ConnectorError(
                f"Credenciais recusadas pelo {self.vendor} (HTTP {code}). Confira as credenciais, se a chave está "
                f"ativa e se ela tem permissão de leitura para os dados coletados.")
        if code == 429:
            raise ConnectorError(f"Limite de requisições do {self.vendor} excedido (HTTP 429) mesmo após "
                                 f"{MAX_TRIES} tentativas. A coleta continuará no próximo ciclo.")
        if 300 <= code < 400:
            raise ConnectorError(f"{self.vendor} respondeu com redirecionamento (HTTP {code}); confira a URL base/região.")
        snippet = self.scrub(" ".join((resp.text or "")[:300].split()))
        raise ConnectorError(f"{self.vendor} respondeu HTTP {code}" + (f": {snippet}" if snippet else "."))

    def json(self, client: httpx.Client, method: str, url: str, **kw) -> Any:
        resp = self.request(client, method, url, **kw)
        try:
            return resp.json()
        except ValueError:
            raise ConnectorError(f"Resposta inválida (não JSON) de {self.vendor} em {urlsplit(url).path}.") from None


# --------------------------------------------------------------------------------------------------------------------
# Datas, URLs, serialização
# --------------------------------------------------------------------------------------------------------------------
def dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def parse_ts(value: Any) -> datetime | None:
    """ISO-8601 (Z/offset/naive=UTC) ou epoch (s/ms, int ou string numérica) → datetime UTC."""
    if value is None or value == "":
        return None
    if isinstance(value, list):
        return parse_ts(value[0]) if value else None
    if isinstance(value, (int, float)) or (isinstance(value, str) and value.strip().lstrip("-").replace(".", "", 1).isdigit()):
        n = float(value)
        if n > 1e11:  # ms
            n /= 1000.0
        try:
            return datetime.fromtimestamp(n, timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    s = str(value).strip()
    if s.endswith("Z") or s.endswith("z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def to_ms(dt: datetime) -> int:
    return int(round(dt.timestamp() * 1000))


def from_ms(ms: int) -> datetime:
    return datetime.fromtimestamp(ms / 1000.0, timezone.utc)


def iso(dt: datetime, ms: bool = True) -> str:
    dt = dt.astimezone(timezone.utc)
    if ms:
        return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def lookback_start(config: dict, now: datetime | None = None) -> datetime:
    """Início da janela na primeira execução (cursor vazio): agora − lookback_minutes (padrão 60)."""
    try:
        minutes = int(str(config.get("lookback_minutes") or 60).strip())
    except ValueError:
        minutes = 60
    minutes = max(1, min(minutes, 60 * 24 * 30))
    return (now or utcnow()) - timedelta(minutes=minutes)


def base_url(value: str, default: str = "", *, vendor: str = "") -> str:
    """Normaliza URL base: exige https, sem barra final, sem query/fragmento."""
    v = (value or default or "").strip()
    if not v:
        raise ConnectorError(f"Informe a URL base do {vendor}.")
    if "://" not in v:
        v = "https://" + v
    parts = urlsplit(v)
    if parts.scheme != "https":
        raise ConnectorError(f"A URL base do {vendor} deve usar https://.")
    if not parts.hostname or parts.query or parts.fragment or parts.username:
        raise ConnectorError(f"URL base do {vendor} inválida: informe apenas https://host[/caminho].")
    return v.rstrip("/")


def same_origin(url: str, base: str) -> bool:
    a, b = urlsplit(url), urlsplit(base)
    return a.scheme == "https" and a.scheme == b.scheme and a.netloc.lower() == b.netloc.lower()


def csv_list(value: Any) -> list[str]:
    if isinstance(value, (list, tuple)):
        return [str(x).strip() for x in value if str(x).strip()]
    return [x.strip() for x in str(value or "").replace(";", ",").split(",") if x.strip()]


# --------------------------------------------------------------------------------------------------------------------
# Watermark + dedupe na fronteira
# --------------------------------------------------------------------------------------------------------------------
@dataclass
class Watermark:
    """Cursor incremental por timestamp crescente.

    Itens com ts < since são descartados; com ts == since, descartados se o id já está em `boundary` (ids vistos com
    exatamente esse ts). Requer que a API devolva os itens em ordem crescente de ts para que um corte por limite
    (MAX_OBJECTS) não pule itens.
    """
    since_ms: int
    boundary: set[str] = field(default_factory=set)

    def __post_init__(self):
        self._since0 = self.since_ms
        self._boundary0 = set(self.boundary)
        self._seen: set[str] = set()

    @classmethod
    def load(cls, cursor: dict, start: datetime) -> "Watermark":
        dt = parse_ts(cursor.get("since")) if cursor else None
        return cls(to_ms(dt or start), set(cursor.get("boundary") or []) if dt else set())

    def offer(self, ts: Any, key: str) -> bool:
        if key in self._seen:
            return False
        dt = parse_ts(ts)
        if dt is not None:
            t = to_ms(dt)
            if t < self._since0 or (t == self._since0 and key in self._boundary0):
                return False
            if t > self.since_ms:
                self.since_ms, self.boundary = t, {key}
            elif t == self.since_ms:
                self.boundary.add(key)
        self._seen.add(key)
        return True

    def finish(self, *, complete: bool, end: datetime | None = None, margin_s: int = 120) -> dict:
        """Cursor a persistir. Numa execução completa sem itens recentes, avança até end − margem."""
        since, boundary = self.since_ms, self.boundary
        if complete and end is not None:
            cand = to_ms(end) - margin_s * 1000
            if cand > since:
                since, boundary = cand, set()
        return {"since": iso(from_ms(since)), "boundary": sorted(boundary)[-BOUNDARY_MAX:]}
