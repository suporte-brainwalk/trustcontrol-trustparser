"""Envio dos eventos aos destinos: Google SecOps (API Chronicle e API de ingestão legada), Wazuh, QRadar, syslog genérico
e webhook. Cada destino tem campos de configuração (não secretos) e segredos (cifrados no banco)."""
from __future__ import annotations

import json
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx

from . import formats

TIMEOUT = httpx.Timeout(connect=10.0, read=60.0, write=60.0, pool=10.0)
UA = "TrustParser/1.0"


class SendError(Exception):
    """Falha de envio. `permanent` = não adianta repetir (ex.: evento rejeitado pelo destino)."""
    def __init__(self, msg: str, permanent: bool = False, bad_index: int | None = None):
        super().__init__(msg)
        self.permanent, self.bad_index = permanent, bad_index


@dataclass
class F:
    name: str
    label: str
    kind: str = "text"  # text | number | select | textarea | secret | bool
    required: bool = True
    help: str = ""
    options: list = field(default_factory=list)
    default: str = ""


CHRONICLE_LOCATIONS = [("us", "EUA (multirregião) · us"), ("southamerica-east1", "São Paulo · southamerica-east1"), ("eu", "Europa (multirregião) · eu"),
                       ("europe", "Europa · europe"), ("europe-west2", "Londres · europe-west2"), ("europe-west3", "Frankfurt · europe-west3"),
                       ("europe-west6", "Zurique · europe-west6"), ("europe-west9", "Paris · europe-west9"), ("europe-west12", "Turim · europe-west12"),
                       ("europe-central2", "Varsóvia · europe-central2"), ("northamerica-northeast2", "Toronto · northamerica-northeast2"),
                       ("asia-southeast1", "Singapura · asia-southeast1"), ("asia-south1", "Mumbai · asia-south1"),
                       ("asia-northeast1", "Tóquio · asia-northeast1"), ("australia-southeast1", "Sydney · australia-southeast1"),
                       ("me-west1", "Tel Aviv · me-west1"), ("me-central1", "Doha · me-central1"), ("me-central2", "Dammam · me-central2"),
                       ("africa-south1", "Joanesburgo · africa-south1")]
LEGACY_REGIONS = [("us", "EUA (multirregião)"), ("southamerica-east1", "São Paulo"), ("europe", "Europa (multirregião)"),
                  ("europe-west2", "Londres"), ("europe-west3", "Frankfurt"), ("europe-west6", "Zurique"), ("europe-west9", "Paris"),
                  ("europe-west12", "Turim"), ("europe-central2", "Varsóvia"), ("northamerica-northeast2", "Canadá"),
                  ("asia-southeast1", "Singapura"), ("asia-southeast2", "Jacarta"), ("asia-south1", "Mumbai"), ("asia-northeast1", "Tóquio"),
                  ("australia-southeast1", "Sydney"), ("me-west1", "Tel Aviv"), ("me-central1", "Doha"), ("me-central2", "Dammam"),
                  ("africa-south1", "Joanesburgo")]
SA_HELP = ("Conteúdo do arquivo JSON da conta de serviço do Google Cloud (chave privada). Fica cifrado no Trust Parser e "
           "nunca é exibido de volta.")
TRANSPORT = [("tcp", "TCP sem TLS"), ("tls", "TCP com TLS"), ("udp", "UDP")]
SYSLOG_HDR = [("rfc3164", "RFC 3164 (BSD) — recomendado para Wazuh 4.x e QRadar"), ("rfc5424", "RFC 5424")]

KINDS = {
    "secops_chronicle": {
        "name": "Google SecOps · API Chronicle (events:import)", "formats": ["udm"], "default_format": "udm",
        "help": "Recomendado. Envia eventos UDM já parseados (sem parser do Google). Exige a API Chronicle ativa no projeto e uma conta "
                "de serviço com a permissão chronicle.events.import (papel Chronicle API Editor).",
        "fields": [F("location", "Região da instância", "select", options=CHRONICLE_LOCATIONS, default="southamerica-east1"),
                   F("project_id", "ID do projeto Google Cloud", help="Projeto vinculado à instância do SecOps."),
                   F("instance_id", "Customer ID / ID da instância (UUID)", help="Em SecOps: Configurações do SIEM → Perfil."),
                   F("endpoint", "Endpoint (opcional)", required=False, help="Deixe vazio para https://<região>-chronicle.googleapis.com")],
        "secrets": [F("service_account_json", "Conta de serviço (JSON)", "textarea", help=SA_HELP)],
    },
    "secops_legacy": {
        "name": "Google SecOps · API de ingestão legada (udmevents:batchCreate)", "formats": ["udm"], "default_format": "udm",
        "help": "Para instâncias antigas. O Google descontinua esta API (novas instâncias desde 26/10/2026 não a aceitam; fim em 20/07/2027).",
        "fields": [F("region", "Região", "select", options=LEGACY_REGIONS, default="southamerica-east1"),
                   F("customer_id", "Customer ID (UUID)", help="Em SecOps: Configurações do SIEM → Perfil."),
                   F("namespace", "Namespace (opcional)", required=False)],
        "secrets": [F("service_account_json", "Conta de serviço de ingestão (JSON)", "textarea", help=SA_HELP)],
    },
    "wazuh": {
        "name": "Wazuh (syslog)", "formats": ["wazuh_json", "cef", "raw"], "default_format": "wazuh_json",
        "help": "O manager do Wazuh 4.x recebe syslog em TCP/UDP 514 (sem TLS). Instale o decoder e as regras do Trust Parser "
                "(baixe na página do destino). Para Wazuh 5.x, use o agente lendo arquivo ou rsyslog (ver documentação).",
        "fields": [F("host", "Endereço do manager"), F("port", "Porta", "number", default="514"),
                   F("transport", "Transporte", "select", options=TRANSPORT, default="tcp"),
                   F("header", "Cabeçalho syslog", "select", options=SYSLOG_HDR, default="rfc3164"),
                   F("hostname", "Hostname no cabeçalho", required=False, default="trustparser"),
                   F("ca_pem", "CA do servidor (PEM, só TLS)", "textarea", required=False)],
        "secrets": [],
    },
    "qradar": {
        "name": "IBM QRadar (syslog LEEF)", "formats": ["leef", "cef", "raw"], "default_format": "leef",
        "help": "QRadar identifica a fonte pelo hostname do cabeçalho syslog. TLS na 6514 (QRadar), TCP/UDP na 514.",
        "fields": [F("host", "Endereço do QRadar / Event Collector"), F("port", "Porta", "number", default="514"),
                   F("transport", "Transporte", "select", options=TRANSPORT, default="tcp"),
                   F("header", "Cabeçalho syslog", "select", options=SYSLOG_HDR, default="rfc3164"),
                   F("hostname", "Hostname no cabeçalho (identificador da fonte)", required=False, default="trustparser"),
                   F("ca_pem", "CA do servidor (PEM, só TLS)", "textarea", required=False)],
        "secrets": [],
    },
    "syslog": {
        "name": "Syslog genérico", "formats": None, "default_format": "cef",
        "help": "Qualquer SIEM/coletor que receba syslog. Escolha o formato do conteúdo.",
        "fields": [F("host", "Endereço"), F("port", "Porta", "number", default="514"),
                   F("transport", "Transporte", "select", options=TRANSPORT, default="tcp"),
                   F("header", "Cabeçalho syslog", "select", options=SYSLOG_HDR, default="rfc5424"),
                   F("hostname", "Hostname no cabeçalho", required=False, default="trustparser"),
                   F("ca_pem", "CA do servidor (PEM, só TLS)", "textarea", required=False)],
        "secrets": [],
    },
    "webhook": {
        "name": "Webhook HTTPS (JSON)", "formats": None, "default_format": "ocsf_json",
        "help": "POST de lotes em JSON (lista) ou NDJSON para uma URL HTTPS.",
        "fields": [F("url", "URL (https://…)"), F("body", "Corpo", "select", options=[("json", "Lista JSON"), ("ndjson", "NDJSON (um por linha)")], default="json"),
                   F("auth_header", "Nome do cabeçalho de autenticação", required=False, default="Authorization")],
        "secrets": [F("auth_value", "Valor do cabeçalho de autenticação", "secret", required=False, help="Ex.: Bearer xxxxx")],
    },
}


# ------------------------------------------------------------------------------------------------ syslog
def syslog_frame(payload: str, cfg: dict, severity: int = 6, facility: int = 1) -> str:
    pri = facility * 8 + severity
    host = (cfg.get("hostname") or "trustparser").replace(" ", "_")
    now = datetime.now(timezone.utc)
    if cfg.get("header", "rfc3164") == "rfc5424":
        return f"<{pri}>1 {now.isoformat(timespec='milliseconds').replace('+00:00', 'Z')} {host} trustparser - - - {payload}"
    return f"<{pri}>{now.strftime('%b')} {now.day:>2} {now.strftime('%H:%M:%S')} {host} trustparser: {payload}"


_sockets: dict = {}


def _tls_ctx(cfg: dict) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if cfg.get("ca_pem"):
        ctx.load_verify_locations(cadata=cfg["ca_pem"])
    return ctx


def _connect(key, cfg: dict):
    host, port, tr = cfg["host"], int(cfg.get("port") or 514), cfg.get("transport", "tcp")
    if tr == "udp":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((host, port))
        return s
    raw = socket.create_connection((host, port), timeout=10)
    raw.settimeout(30)
    if tr == "tls":
        return _tls_ctx(cfg).wrap_socket(raw, server_hostname=host)
    return raw


def send_syslog(dest_key, cfg: dict, lines: list[str], severities: list[int] | None = None):
    """Envia em uma conexão persistente (TCP/TLS: uma mensagem por linha, terminada em LF; UDP: um datagrama por mensagem)."""
    tr = cfg.get("transport", "tcp")
    msgs = [syslog_frame(ln.replace("\n", " ").replace("\r", " "), cfg, (severities or [6] * len(lines))[i]) for i, ln in enumerate(lines)]
    for attempt in (1, 2):
        s = _sockets.get(dest_key)
        try:
            if s is None:
                s = _connect(dest_key, cfg)
                _sockets[dest_key] = s
            if tr == "udp":
                for m in msgs:
                    s.send(m.encode("utf-8", "replace")[:65000])
            else:
                s.sendall(("\n".join(msgs) + "\n").encode("utf-8", "replace"))
            return
        except (OSError, ssl.SSLError) as e:
            close(dest_key)
            if attempt == 2:
                raise SendError(f"syslog {cfg.get('host')}:{cfg.get('port')}/{tr}: {e}") from e


def close(dest_key):
    s = _sockets.pop(dest_key, None)
    if s is not None:
        try:
            s.close()
        except OSError:
            pass


# ------------------------------------------------------------------------------------------------ Google SecOps
_tokens: dict = {}


def _google_token(sa_json: str, scopes: list[str]) -> str:
    from google.auth.transport.requests import Request
    from google.oauth2 import service_account
    key = (hash(sa_json), tuple(scopes))
    cred = _tokens.get(key)
    if cred is None:
        try:
            info = json.loads(sa_json)
        except ValueError as e:
            raise SendError("Conta de serviço inválida (o JSON não pôde ser lido).", permanent=True) from e
        try:
            cred = service_account.Credentials.from_service_account_info(info, scopes=scopes)
        except (ValueError, KeyError) as e:
            raise SendError(f"Conta de serviço inválida: {e}", permanent=True) from e
        _tokens[key] = cred
    if not cred.valid:
        try:
            cred.refresh(Request())
        except Exception as e:  # noqa: BLE001
            raise SendError(f"Google recusou a conta de serviço: {str(e)[:200]}") from e
    return cred.token


def _post_json(url: str, token: str, body: dict, client: httpx.Client | None = None) -> httpx.Response:
    c = client or httpx.Client(timeout=TIMEOUT, headers={"User-Agent": UA})
    try:
        return c.post(url, json=body, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    except httpx.HTTPError as e:
        raise SendError(f"falha de conexão com {url.split('/')[2]}: {e}") from e
    finally:
        if client is None:
            c.close()


def _check(r: httpx.Response, what: str):
    if r.status_code < 300:
        return
    detail = r.text[:400].replace("\n", " ")
    if r.status_code in (400, 413):
        raise SendError(f"{what} rejeitou o lote (HTTP {r.status_code}): {detail}", permanent=True)
    if r.status_code in (401, 403):
        raise SendError(f"{what} negou acesso (HTTP {r.status_code}): confira a conta de serviço, o papel IAM e o ID da instância. {detail}")
    raise SendError(f"{what} indisponível (HTTP {r.status_code}): {detail}")


def send_chronicle(cfg: dict, secrets: dict, events: list[dict], client=None):
    token = _google_token(secrets.get("service_account_json", ""), ["https://www.googleapis.com/auth/cloud-platform"])
    loc = cfg.get("location", "us")
    host = (cfg.get("endpoint") or f"https://{loc}-chronicle.googleapis.com").rstrip("/")
    url = f"{host}/v1/projects/{cfg['project_id']}/locations/{loc}/instances/{cfg['instance_id']}/events:import"
    _check(_post_json(url, token, {"inline_source": {"events": [{"udm": e} for e in events]}}, client), "Google SecOps")


def send_legacy(cfg: dict, secrets: dict, events: list[dict], client=None):
    token = _google_token(secrets.get("service_account_json", ""), ["https://www.googleapis.com/auth/malachite-ingestion"])
    region = cfg.get("region", "us")
    host = "https://malachiteingestion-pa.googleapis.com" if region == "us" else f"https://{region}-malachiteingestion-pa.googleapis.com"
    body = {"customer_id": cfg["customer_id"], "events": events}
    if cfg.get("namespace"):
        body["namespace"] = cfg["namespace"]
    _check(_post_json(f"{host}/v2/udmevents:batchCreate", token, body, client), "Google SecOps (API legada)")


# ------------------------------------------------------------------------------------------------ webhook
def send_webhook(cfg: dict, secrets: dict, payloads: list, client=None):
    url = cfg.get("url", "")
    if not url.startswith("https://"):
        raise SendError("A URL do webhook precisa começar com https://", permanent=True)
    headers = {"User-Agent": UA}
    if secrets.get("auth_value"):
        headers[cfg.get("auth_header") or "Authorization"] = secrets["auth_value"]
    if cfg.get("body", "json") == "ndjson":
        data, headers["Content-Type"] = "\n".join(formats.to_line(p) for p in payloads) + "\n", "application/x-ndjson"
    else:
        data, headers["Content-Type"] = json.dumps(payloads, ensure_ascii=False, default=str), "application/json"
    c = client or httpx.Client(timeout=TIMEOUT, follow_redirects=False)
    try:
        r = c.post(url, content=data.encode(), headers=headers)
    except httpx.HTTPError as e:
        raise SendError(f"falha de conexão com o webhook: {e}") from e
    finally:
        if client is None:
            c.close()
    if r.status_code >= 300:
        raise SendError(f"webhook respondeu HTTP {r.status_code}: {r.text[:200]}", permanent=r.status_code in (400, 413, 422))


# ------------------------------------------------------------------------------------------------ fachada
BATCH_LIMITS = {"secops_chronicle": (1000, 2_000_000), "secops_legacy": (500, 900_000), "webhook": (500, 4_000_000)}


def split_batches(kind: str, items: list, sizes: list[int]) -> list[list[int]]:
    """Índices agrupados respeitando quantidade e bytes por lote do destino."""
    max_n, max_b = BATCH_LIMITS.get(kind, (500, 4_000_000))
    out, cur, cur_b = [], [], 0
    for i, sz in enumerate(sizes):
        if cur and (len(cur) >= max_n or cur_b + sz > max_b):
            out.append(cur)
            cur, cur_b = [], 0
        cur.append(i)
        cur_b += sz
    if cur:
        out.append(cur)
    return out


def send(kind: str, dest_key, cfg: dict, secrets: dict, payloads: list, severities: list[int] | None = None, client=None):
    """Envia uma lista de payloads já formatados (dict para JSON/UDM, str para linhas)."""
    if kind == "secops_chronicle":
        return send_chronicle(cfg, secrets, payloads, client)
    if kind == "secops_legacy":
        return send_legacy(cfg, secrets, payloads, client)
    if kind == "webhook":
        return send_webhook(cfg, secrets, payloads, client)
    if kind in ("wazuh", "qradar", "syslog"):
        return send_syslog(dest_key, cfg, [formats.to_line(p) for p in payloads], severities)
    raise SendError(f"tipo de destino desconhecido: {kind}", permanent=True)


def heartbeat_event(tenant: str) -> dict:
    """Evento sintético usado no botão “Testar conexão” (canônico)."""
    now = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return {"time": now, "class_uid": 0, "class_name": "Base Event", "severity_id": 1, "severity": "Informational",
            "message": "Trust Parser · teste de conexão do destino",
            "metadata": {"product": {"vendor_name": "Trust Control", "name": "Trust Parser"}, "event_code": "connection_test"},
            "device": {"hostname": "trustparser.trustcontrol.nuvem.tec.br"}, "observer": {"hostname": "trustparser"},
            "unmapped": {"tenant": tenant, "teste": "sim"}}


def test_destination(kind: str, dest_key, cfg: dict, secrets: dict, fmt: str, tenant: str, spec=None) -> str:
    ev = heartbeat_event(tenant)
    if kind in ("secops_chronicle", "secops_legacy"):
        udm = formats.to_udm(ev, "", {"tenant": tenant})
        udm["metadata"]["event_type"] = "STATUS_HEARTBEAT"
        udm["principal"] = {"hostname": "trustparser.trustcontrol.nuvem.tec.br"}
        t0 = time.monotonic()
        send(kind, dest_key, cfg, secrets, [udm])
        return f"Evento de teste (STATUS_HEARTBEAT) aceito pelo Google SecOps em {int((time.monotonic() - t0) * 1000)} ms."
    payload = formats.render(fmt, ev, "Trust Parser teste de conexao", {"tenant": tenant, "source": "teste"}, spec)
    t0 = time.monotonic()
    send(kind, dest_key, cfg, secrets, [payload])
    if kind == "webhook":
        return f"Webhook respondeu com sucesso em {int((time.monotonic() - t0) * 1000)} ms."
    if cfg.get("transport") == "udp":
        return "Mensagem de teste enviada por UDP (o UDP não confirma recebimento — verifique no destino)."
    return f"Conexão aberta e mensagem de teste entregue a {cfg.get('host')}:{cfg.get('port')} ({cfg.get('transport', 'tcp').upper()})."
