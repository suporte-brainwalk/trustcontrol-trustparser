"""Palo Alto Networks Cortex XDR — alertas via REST API (pull).

Auth: chave Standard (x-xdr-auth-id + Authorization: <key>) ou Advanced (Authorization: sha256(key+nonce+timestamp),
x-xdr-nonce, x-xdr-timestamp). Base: https://api-<fqdn>/public_api/...
Coleta: POST get_alerts_multi_events (v2, padrão) ou get_alerts (v1) com filtro server_creation_time gte <cursor>,
ordenação creation_time asc e paginação search_from/search_to (100 por chamada). Cursor = local_insert_ts.
"""
from __future__ import annotations

import hashlib
import secrets as _secrets
import string
from datetime import timedelta
from urllib.parse import urlsplit

from .base import (MAX_OBJECTS, Connector, ConnectorError, Field, PullResult, Watermark, base_url, client_scope,
                   dumps, from_ms, iso, register, to_ms, utcnow)

PAGE = 100
MAX_OFFSET = 10000  # a API não pagina além de ~10.000 resultados por consulta
ENDPOINTS = {
    "v2_multi_events": "/public_api/v2/alerts/get_alerts_multi_events",
    "v1_multi_events": "/public_api/v1/alerts/get_alerts_multi_events",
    "v1_alerts": "/public_api/v1/alerts/get_alerts",
}


def _scalar(v):
    return v[0] if isinstance(v, list) and v else v


@register
class CortexXDR(Connector):
    slug = "cortex-xdr"
    name = "Cortex XDR (alertas via API)"
    vendor = "Cortex XDR"
    parser_slug = "cortex-xdr-api-alert"
    default_interval_s = 300
    fields = [
        Field("fqdn", "URL da API (FQDN)", "url",
              help="Settings → Configurations → Integrations → API Keys → 'Copy API URL'. "
                   "Ex.: https://api-empresa.xdr.us.paloaltonetworks.com"),
        Field("api_key_id", "API Key ID", "number", help="Coluna 'ID' da chave na lista de API Keys."),
        Field("key_type", "Tipo de chave", "select", default="advanced",
              options=[("advanced", "Advanced (recomendado)"), ("standard", "Standard")],
              help="Security Level escolhido ao gerar a chave."),
        Field("endpoint", "Endpoint de alertas", "select", required=False, default="v2_multi_events",
              options=[("v2_multi_events", "get_alerts_multi_events v2 (recomendado)"),
                       ("v1_multi_events", "get_alerts_multi_events v1 (legado)"),
                       ("v1_alerts", "get_alerts v1")]),
        Field("lookback_minutes", "Retroativo na 1ª coleta (min)", "number", required=False, default="60"),
    ]
    secret_fields = [
        Field("api_key", "API Key", "secret", help="Exibida uma única vez ao gerar a chave (papel mínimo: Viewer)."),
    ]

    # ------------------------------------------------------------------------------------------------------------
    def _base(self, config) -> str:
        raw = self.cfg(config, "fqdn")
        url = base_url(raw, vendor=self.vendor)
        host = urlsplit(url).hostname or ""
        if not host.startswith("api-"):
            url = url.replace("://" + host, "://api-" + host, 1)
        return url.split("/public_api")[0]

    def _headers(self, config, secrets) -> dict:
        key = str(secrets.get("api_key") or "")
        key_id = self.cfg(config, "api_key_id")
        if not key_id.isdigit():
            raise ConnectorError("API Key ID do Cortex XDR deve ser numérico.")
        h = {"x-xdr-auth-id": key_id, "Content-Type": "application/json", "Accept": "application/json"}
        if self.cfg(config, "key_type") == "standard":
            h["Authorization"] = key
            return h
        nonce = "".join(_secrets.choice(string.ascii_letters + string.digits) for _ in range(64))
        ts = str(int(utcnow().timestamp()) * 1000)
        h.update({"x-xdr-timestamp": ts, "x-xdr-nonce": nonce,
                  "Authorization": hashlib.sha256(f"{key}{nonce}{ts}".encode()).hexdigest()})
        return h

    def _post(self, c, config, secrets, filters, frm, to) -> dict:
        path = ENDPOINTS.get(self.cfg(config, "endpoint"), ENDPOINTS["v2_multi_events"])
        body = {"request_data": {"filters": filters, "search_from": frm, "search_to": to,
                                 "sort": {"field": "creation_time", "keyword": "asc"}}}
        http = self.http(secrets)
        resp = http.request(c, "POST", self._base(config) + path, json=body,
                            headers=self._headers(config, secrets), ok=(402,))
        if resp.status_code == 402:
            raise ConnectorError("A licença do Cortex XDR não cobre esta API (HTTP 402).")
        try:
            reply = resp.json().get("reply")
        except (ValueError, AttributeError):
            reply = None
        if not isinstance(reply, dict) or not isinstance(reply.get("alerts", []), list):
            raise ConnectorError(f"Resposta inesperada do {self.vendor} (sem reply.alerts).")
        return reply

    @staticmethod
    def _filters(start_ms: int, end_ms: int) -> list[dict]:
        return [{"field": "server_creation_time", "operator": "gte", "value": start_ms},
                {"field": "server_creation_time", "operator": "lte", "value": end_ms}]

    # ------------------------------------------------------------------------------------------------------------
    def test(self, config, secrets, client=None) -> str:
        self.validate(config, secrets)
        now = utcnow()
        with client_scope(client) as c:
            reply = self._post(c, config, secrets, self._filters(to_ms(now - timedelta(days=1)), to_ms(now)), 0, 1)
        total = reply.get("total_count")
        return f"Conexão OK com {self.vendor}: chave aceita; {total if total is not None else '?'} alerta(s) nas últimas 24h."

    def pull(self, config, secrets, cursor, client=None) -> PullResult:
        # A API só ordena por creation_time, enquanto o filtro/cursor usa server_creation_time (local_insert_ts).
        # Por isso, se o limite por chamada for atingido no meio de uma janela, guardamos a janela fixa + offset em
        # cursor["resume"] e só avançamos o watermark quando a janela inteira tiver sido lida.
        self.validate(config, secrets)
        cursor = cursor or {}
        now = utcnow()
        wm = Watermark.load(cursor, self.first_start(config, now))
        resume = cursor.get("resume") or {}
        start_ms = wm.since_ms
        end_ms = int(resume.get("end_ms") or to_ms(now))
        offset = int(resume.get("offset") or 0)
        if resume:
            wm.since_ms = int(resume.get("max_ms") or wm.since_ms)
            wm.boundary = set(resume.get("max_boundary") or [])
        lines: list[str] = []
        more = False
        note = ""
        with client_scope(client) as c:
            while True:
                reply = self._post(c, config, secrets, self._filters(start_ms, end_ms), offset, offset + PAGE)
                alerts = reply.get("alerts") or []
                consumed = 0
                for a in alerts:
                    consumed += 1
                    key = str(_scalar(a.get("alert_id")) or _scalar(a.get("external_id")) or dumps(a)[:200])
                    ts = _scalar(a.get("local_insert_ts")) or _scalar(a.get("detection_timestamp"))
                    if wm.offer(ts, key):
                        lines.append(dumps(a))
                        if len(lines) >= MAX_OBJECTS:
                            more = True
                            break
                if more:
                    offset += consumed
                    break
                offset += PAGE
                if len(alerts) < PAGE:
                    break
                if offset >= MAX_OFFSET:
                    note = "janela com mais de 10.000 alertas; parte pode não ter sido coletada"
                    break
        if more:
            cur = {"since": cursor.get("since") or iso(from_ms(start_ms)), "boundary": cursor.get("boundary") or [],
                   "resume": {"end_ms": end_ms, "offset": offset, "max_ms": wm.since_ms,
                              "max_boundary": sorted(wm.boundary)[-500:]}}
        else:
            cur = wm.finish(complete=not note, end=from_ms(end_ms))
        msg = f"{len(lines)} alerta(s) desde {iso(from_ms(start_ms))}"
        return PullResult(lines, cur, more, msg + (f"; {note}" if note else ""))
