"""WithSecure Elements — Security Events API (pull).

Auth: OAuth2 client credentials (POST /as/token.oauth2, Basic client_id:secret, scope connect.api.read).
Coleta: POST /security-events/v1/security-events (form-urlencoded), persistenceTimestampStart + order=asc,
limit=200, paginação por `anchor`/`nextAnchor`. Janela máxima da API: 30 dias.
"""
from __future__ import annotations

from datetime import timedelta

import httpx

from .base import (MAX_OBJECTS, Connector, ConnectorError, Field, PullResult, Watermark, base_url, client_scope,
                   csv_list, dumps, from_ms, iso, register, utcnow)

DEFAULT_BASE = "https://api.connect.withsecure.com"
ENGINE_GROUPS = ["epp", "edr", "ecp", "xm"]
PAGE = 200
MAX_SPAN = timedelta(days=30) - timedelta(minutes=5)


@register
class WithSecureElements(Connector):
    slug = "withsecure-elements"
    name = "WithSecure Elements (Security Events API)"
    vendor = "WithSecure Elements"
    parser_slug = "withsecure-elements-api-event"
    default_interval_s = 300
    fields = [
        Field("base_url", "URL da API", "url", required=False, default=DEFAULT_BASE,
              help="Normalmente https://api.connect.withsecure.com (padrão). Altere só se a WithSecure indicar outro host."),
        Field("client_id", "Client ID",
              help="Elements Security Center → Organization settings → API clients → Add new (somente leitura)."),
        Field("organization_id", "Organization ID (opcional)", required=False,
              help="UUID da organização. Vazio = organização padrão do API client (para parceiros, inclui as filhas)."),
        Field("engine_groups", "Grupos de engine", "text", required=False, default="epp,edr,ecp,xm",
              help="Lista separada por vírgula entre epp, edr, ecp, xm."),
        Field("lookback_minutes", "Retroativo na 1ª coleta (min)", "number", required=False, default="60",
              help="Na primeira execução, busca eventos dos últimos N minutos."),
    ]
    secret_fields = [
        Field("client_secret", "Client Secret", "secret", help="Exibido uma única vez ao criar o API client."),
    ]

    # ------------------------------------------------------------------------------------------------------------
    def _base(self, config):
        return base_url(self.cfg(config, "base_url"), DEFAULT_BASE, vendor=self.vendor)

    def _token(self, c: httpx.Client, base: str, config: dict, secrets: dict) -> str:
        http = self.http(secrets)
        resp = http.request(c, "POST", f"{base}/as/token.oauth2",
                            auth=(self.cfg(config, "client_id"), str(secrets.get("client_secret", ""))),
                            data={"grant_type": "client_credentials", "scope": "connect.api.read"},
                            headers={"Accept": "application/json"}, ok=(400,))
        if resp.status_code == 400:  # RFC 6749: invalid_client / invalid_scope chegam como 400
            try:
                err = resp.json().get("error", "")
            except ValueError:
                err = ""
            raise ConnectorError(f"Credenciais recusadas pelo {self.vendor} (HTTP 400{', ' + err if err else ''}). "
                                 "Confira Client ID/Secret e se o API client tem escopo de leitura.")
        try:
            return resp.json()["access_token"]
        except (ValueError, KeyError, TypeError):
            raise ConnectorError(f"{self.vendor} não retornou access_token.") from None

    def _form(self, config, start, end, anchor=None, limit=PAGE):
        groups = [g for g in csv_list(self.cfg(config, "engine_groups")) if g in ENGINE_GROUPS] or ENGINE_GROUPS
        form: dict[str, str | list[str]] = {"persistenceTimestampStart": iso(start),
                                            "persistenceTimestampEnd": iso(end),
                                            "order": "asc", "limit": str(limit), "engineGroup": groups}
        org = self.cfg(config, "organization_id")
        if org:
            form["organizationId"] = org
        if anchor:
            form["anchor"] = anchor
        return form

    def _page(self, c, base, token, config, secrets, start, end, anchor=None, limit=PAGE) -> dict:
        data = self.http(secrets).json(c, "POST", f"{base}/security-events/v1/security-events",
                                       data=self._form(config, start, end, anchor, limit),
                                       headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
        if not isinstance(data, dict) or not isinstance(data.get("items", []), list):
            raise ConnectorError(f"Resposta inesperada do {self.vendor} (sem lista 'items').")
        return data

    # ------------------------------------------------------------------------------------------------------------
    def test(self, config, secrets, client=None) -> str:
        self.validate(config, secrets)
        base = self._base(config)
        with client_scope(client) as c:
            token = self._token(c, base, config, secrets)
            now = utcnow()
            data = self._page(c, base, token, config, secrets, now - timedelta(hours=1), now, limit=1)
        n = len(data.get("items") or [])
        return (f"Conexão OK com {self.vendor}: token OAuth2 obtido e consulta de eventos respondida "
                f"({n} evento(s) na última hora na amostra de 1).")

    def pull(self, config, secrets, cursor, client=None) -> PullResult:
        self.validate(config, secrets)
        base = self._base(config)
        cursor = cursor or {}
        now = utcnow()
        wm = Watermark.load(cursor, self.first_start(config, now))
        start = from_ms(wm.since_ms)
        end = min(now, start + MAX_SPAN)
        lines: list[str] = []
        more = False
        with client_scope(client) as c:
            token = self._token(c, base, config, secrets)
            anchor = None
            while True:
                data = self._page(c, base, token, config, secrets, start, end, anchor)
                for item in data.get("items") or []:
                    key = str(item.get("id") or dumps(item)[:200])
                    if wm.offer(item.get("persistenceTimestamp") or item.get("serverTimestamp"), key):
                        lines.append(dumps(item))
                        if len(lines) >= MAX_OBJECTS:
                            more = True
                            break
                anchor = data.get("nextAnchor")
                if more or not anchor:
                    break
        complete = not more
        new_cursor = wm.finish(complete=complete, end=end)
        if complete and end < now - timedelta(minutes=5):
            more = True  # janela de 30 dias limitada: ainda há período a coletar
        return PullResult(lines, new_cursor, more, f"{len(lines)} evento(s) de {iso(start)} a {iso(end)}")
