"""Axur (Digital Risk Protection) — tickets via Tickets API (pull).

Auth: Authorization: Bearer <API key> (chave de usuário criada no Axur One).
Coleta: GET /tickets-api/tickets?ticket.last-update.date=ge:<cursor>&sortBy=ticket.last-update.date&order=asc
&timezone=Z&pageSize=200&page=N. Cada ticket é reenviado quando é atualizado (dedupe por ticketKey + last-update.date).
"""
from __future__ import annotations

from urllib.parse import parse_qsl

from .base import (MAX_OBJECTS, Connector, ConnectorError, Field, PullResult, Watermark, base_url, client_scope,
                   dumps, from_ms, register, utcnow)

DEFAULT_BASE = "https://api.axur.com/gateway/1.0/api"
PAGE = 200
RESERVED = {"page", "pageSize", "sortBy", "order", "timezone", "ticket.last-update.date", "ticket.customer"}


def _axur_dt(ms: int) -> str:
    return from_ms(ms).strftime("%Y-%m-%dT%H:%M:%S")


@register
class Axur(Connector):
    slug = "axur"
    name = "Axur (tickets de risco digital)"
    vendor = "Axur"
    parser_slug = "axur-api-ticket"
    default_interval_s = 600
    fields = [
        Field("base_url", "URL da API", "url", required=False, default=DEFAULT_BASE,
              help="Padrão: https://api.axur.com/gateway/1.0/api"),
        Field("customer", "Customer key (opcional, MSSP)", required=False,
              help="Chave do cliente filho (ex.: ACME) quando a chave pertence a um parceiro/MSSP."),
        Field("extra_query", "Filtros adicionais (opcional)", required=False,
              help="Query string extra da Tickets API, ex.: current.type=phishing,fraudulent-brand-use"),
        Field("lookback_minutes", "Retroativo na 1ª coleta (min)", "number", required=False, default="60"),
    ]
    secret_fields = [
        Field("api_key", "API Key", "secret",
              help="Axur One → Minhas preferências → API KEY (https://one.axur.com/preferences?tab=api-keys)."),
    ]

    def _params(self, config, since_ms: int | None, page: int, size: int) -> list[tuple[str, str]]:
        p = [("sortBy", "ticket.last-update.date"), ("order", "asc"), ("timezone", "Z"),
             ("page", str(page)), ("pageSize", str(size))]
        if since_ms is not None:
            p.append(("ticket.last-update.date", f"ge:{_axur_dt(since_ms)}"))
        if self.cfg(config, "customer"):
            p.append(("ticket.customer", self.cfg(config, "customer")))
        extra = self.cfg(config, "extra_query").lstrip("?")
        for k, v in parse_qsl(extra, keep_blank_values=False):
            if k not in RESERVED:
                p.append((k, v))
        return p

    def _get(self, c, config, secrets, params) -> dict:
        base = base_url(self.cfg(config, "base_url"), DEFAULT_BASE, vendor=self.vendor)
        data = self.http(secrets).json(c, "GET", f"{base}/tickets-api/tickets", params=params, headers={
            "Authorization": f"Bearer {secrets.get('api_key', '')}", "Accept": "application/json"})
        if not isinstance(data, dict) or not isinstance(data.get("tickets", []), list):
            raise ConnectorError(f"Resposta inesperada do {self.vendor} (sem lista 'tickets').")
        return data

    @staticmethod
    def _ts_key(t: dict) -> tuple:
        tk = t.get("ticket") if isinstance(t.get("ticket"), dict) else {}
        ts = tk.get("last-update.date") or tk.get("creation.date")
        key = str(tk.get("ticketKey") or t.get("key") or dumps(t)[:200])
        return ts, f"{key}|{ts}"

    def test(self, config, secrets, client=None) -> str:
        self.validate(config, secrets)
        with client_scope(client) as c:
            data = self._get(c, config, secrets, self._params(config, None, 1, 1))
        total = (data.get("pageable") or {}).get("total", "?")
        return f"Conexão OK com {self.vendor}: API Key aceita; {total} ticket(s) visíveis para esta chave."

    def pull(self, config, secrets, cursor, client=None) -> PullResult:
        self.validate(config, secrets)
        now = utcnow()
        wm = Watermark.load(cursor or {}, self.first_start(config, now))
        since = wm.since_ms
        lines: list[str] = []
        more = False
        page = 1
        with client_scope(client) as c:
            while True:
                data = self._get(c, config, secrets, self._params(config, since, page, PAGE))
                tickets = data.get("tickets") or []
                for t in tickets:
                    ts, key = self._ts_key(t)
                    if wm.offer(ts, key):
                        lines.append(dumps(t))
                        if len(lines) >= MAX_OBJECTS:
                            more = True
                            break
                total = (data.get("pageable") or {}).get("total")
                if more or len(tickets) < PAGE or (isinstance(total, int) and page * PAGE >= total):
                    break
                page += 1
                if page > MAX_OBJECTS // PAGE + 20:  # proteção contra paginação que não avança
                    more = True
                    break
        # ordenado por last-update asc: um corte por limite é retomado a partir do novo watermark
        return PullResult(lines, wm.finish(complete=not more, end=now), more, f"{len(lines)} ticket(s)")
