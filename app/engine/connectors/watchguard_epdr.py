"""WatchGuard Endpoint Security (EPDR/EDR/EPP) — security events via WatchGuard Cloud API (pull).

Auth: POST https://api.<região>.cloud.watchguard.com/oauth/token (Basic AccessID:senha, grant client_credentials,
scope api-access) + cabeçalho WatchGuard-API-Key em toda chamada.
Coleta: GET .../api/v1/accounts/{accountId}/securityevents/{type}/export/1 (últimas 24h) para cada tipo (1–19).
A API não tem cursor nem filtro de tempo (máx. 3.000 registros por chamada), então o cursor guarda hashes curtos dos
eventos já enviados (com o instante em que foram vistos) e descarta repetidos.
"""
from __future__ import annotations

import hashlib
import json
from datetime import timedelta

from .base import (MAX_OBJECTS, Connector, ConnectorError, Field, PullResult, base_url, client_scope, csv_list, dumps,
                   parse_ts, register, utcnow)

REGIONS = [("usa", "Américas (usa)"), ("deu", "Europa (deu)"), ("jpn", "Ásia-Pacífico (jpn)")]
PRODUCTS = {
    "endpoint-security": "/rest/endpoint-security/management/api/v1",
    "aether": "/rest/aether-endpoint-security/aether-mgmt/api/v1",
}
EVENT_TYPES = {
    1: "Malware", 2: "PUPs", 3: "Blocked Programs", 4: "Exploits", 5: "Blocked by Advanced Security Policies",
    6: "Virus", 7: "Spyware", 8: "Hacking Tools and PUPs", 9: "Phishing", 10: "Suspicious", 11: "Dangerous Actions",
    12: "Tracking Cookies", 13: "Malware URLs", 14: "Other Security Event", 15: "Intrusion Attempts",
    16: "Blocked Connections", 17: "Blocked Devices", 18: "Indicators of Attack", 19: "Network Attack Protection",
}
API_CAP = 3000
SEEN_TTL = timedelta(hours=72)   # a exportação cobre 24h; guardamos 72h de margem
SEEN_MAX = 30000


def _parse_types(value: str) -> list[int]:
    out: list[int] = []
    for part in csv_list(value):
        if "-" in part:
            a, _, b = part.partition("-")
            if a.strip().isdigit() and b.strip().isdigit():
                out += list(range(int(a), int(b) + 1))
        elif part.isdigit():
            out.append(int(part))
    out = sorted({t for t in out if t in EVENT_TYPES})
    if not out:
        raise ConnectorError("Tipos de evento WatchGuard inválidos: use números de 1 a 19 (ex.: 1-19 ou 1,4,18).")
    return out


def _event_key(t: int, ev: dict) -> str:
    if ev.get("event_id") not in (None, ""):
        raw = f"{t}|{ev.get('event_id')}|{ev.get('device_id', '')}"
    else:
        raw = f"{t}|" + json.dumps(ev, sort_keys=True, ensure_ascii=False)
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


@register
class WatchGuardEPDR(Connector):
    slug = "watchguard-epdr"
    name = "WatchGuard Endpoint Security (EPDR) — API"
    vendor = "WatchGuard Cloud"
    parser_slug = "watchguard-epdr-api-json"
    default_interval_s = 600
    fields = [
        Field("region", "Região do WatchGuard Cloud", "select", default="usa", options=REGIONS,
              help="WatchGuard Cloud → Administration → Managed Access mostra a 'API base URL' da conta."),
        Field("base_url", "URL base da API (opcional)", "url", required=False,
              help="Sobrepõe a região (ex.: https://api.usa.cloud.watchguard.com)."),
        Field("account_id", "Account ID",
              help="Administration → Managed Access (ex.: WGC-1-123abc456 ou ACC-1234567)."),
        Field("access_id", "Access ID (somente leitura)",
              help="Administration → Managed Access → API: 'Read-only Access ID'."),
        Field("product", "Plataforma", "select", required=False, default="endpoint-security",
              options=[("endpoint-security", "WatchGuard Endpoint Security (EPDR/EDR/EPP)"),
                       ("aether", "Panda Aether (AD360/AD/EP)")]),
        Field("event_types", "Tipos de evento", required=False, default="1-19",
              help="Faixas/lista de 1 a 19 (1 Malware, 2 PUPs, 4 Exploits, 18 Indicators of Attack, …)."),
        Field("lookback_minutes", "Retroativo na 1ª coleta (min)", "number", required=False, default="60"),
    ]
    secret_fields = [
        Field("password", "Senha do Access ID", "secret", help="Senha definida para o Read-only Access ID."),
        Field("api_key", "API Key", "secret", help="Administration → Managed Access → API Key."),
    ]

    def _base(self, config) -> str:
        if self.cfg(config, "base_url"):
            return base_url(self.cfg(config, "base_url"), vendor=self.vendor)
        region = self.cfg(config, "region")
        if region not in dict(REGIONS):
            raise ConnectorError("Região do WatchGuard Cloud inválida.")
        return f"https://api.{region}.cloud.watchguard.com"

    def _token(self, c, base, config, secrets) -> str:
        resp = self.http(secrets).request(
            c, "POST", f"{base}/oauth/token", auth=(self.cfg(config, "access_id"), str(secrets.get("password", ""))),
            data={"grant_type": "client_credentials", "scope": "api-access"},
            headers={"Accept": "application/json"}, ok=(400,))
        if resp.status_code == 400:
            raise ConnectorError(f"Credenciais recusadas pelo {self.vendor} (HTTP 400). Confira Access ID e senha.")
        try:
            return resp.json()["access_token"]
        except (ValueError, KeyError, TypeError):
            raise ConnectorError(f"{self.vendor} não retornou access_token.") from None

    def _events(self, c, base, token, config, secrets, t: int) -> list[dict]:
        account = self.cfg(config, "account_id")
        if not account or "/" in account:
            raise ConnectorError("Account ID do WatchGuard inválido.")
        prefix = PRODUCTS.get(self.cfg(config, "product"), PRODUCTS["endpoint-security"])
        url = f"{base}{prefix}/accounts/{account}/securityevents/{t}/export/1"
        data = self.http(secrets).json(c, "GET", url, headers={
            "Authorization": f"Bearer {token}", "WatchGuard-API-Key": str(secrets.get("api_key", "")),
            "Accept": "application/json"})
        if isinstance(data, list):
            return [e for e in data if isinstance(e, dict)]
        if isinstance(data, dict) and isinstance(data.get("data"), list):
            return [e for e in data["data"] if isinstance(e, dict)]
        raise ConnectorError(f"Resposta inesperada do {self.vendor} (sem lista 'data') para o tipo {t}.")

    # ------------------------------------------------------------------------------------------------------------
    def test(self, config, secrets, client=None) -> str:
        self.validate(config, secrets)
        _parse_types(self.cfg(config, "event_types"))
        base = self._base(config)
        with client_scope(client) as c:
            token = self._token(c, base, config, secrets)
            n = len(self._events(c, base, token, config, secrets, 1))
        return f"Conexão OK com {self.vendor}: token obtido e API Key aceita; {n} evento(s) de malware nas últimas 24h."

    def pull(self, config, secrets, cursor, client=None) -> PullResult:
        self.validate(config, secrets)
        types = _parse_types(self.cfg(config, "event_types"))
        base = self._base(config)
        now = utcnow()
        now_s = int(now.timestamp())
        first_run = not cursor or "seen" not in cursor
        # 1ª execução: só envia o que estiver dentro do retroativo; se ela for fatiada (more=True), o piso segue no cursor
        floor = self.first_start(config, now) if first_run else parse_ts((cursor or {}).get("floor"))
        seen: dict[str, int] = {k: int(v) for k, v in ((cursor or {}).get("seen") or {}).items()
                                if now_s - int(v) < SEEN_TTL.total_seconds()}
        lines: list[str] = []
        more = False
        capped: list[int] = []
        with client_scope(client) as c:
            token = self._token(c, base, config, secrets)
            for t in types:
                events = self._events(c, base, token, config, secrets, t)
                if len(events) >= API_CAP:
                    capped.append(t)
                # mais antigos primeiro (a ordem da exportação não é documentada)
                events.sort(key=lambda e: (parse_ts(e.get("date")) or now).timestamp())
                for ev in events:
                    key = _event_key(t, ev)
                    if key in seen:
                        continue
                    if len(lines) >= MAX_OBJECTS:
                        more = True
                        break
                    seen[key] = now_s
                    if floor is not None:
                        dt = parse_ts(ev.get("date") or ev.get("security_event_date"))
                        if dt is not None and dt < floor:
                            continue  # 1ª execução: marca como visto, mas não envia o que é anterior ao retroativo
                    ev.setdefault("security_event_type", t)
                    ev.setdefault("security_event_type_name", EVENT_TYPES[t])
                    lines.append(dumps(ev))
                if more:
                    break
        if len(seen) > SEEN_MAX:
            seen = dict(sorted(seen.items(), key=lambda kv: kv[1])[-SEEN_MAX:])
        note = f"{len(lines)} evento(s)"
        if capped:
            note += (f"; limite de {API_CAP} registros/24h atingido nos tipos {capped} — eventos podem ter sido "
                     "perdidos; reduza o intervalo de coleta")
        new_cursor: dict = {"seen": seen}
        if more and floor is not None:
            new_cursor["floor"] = floor.isoformat()
        return PullResult(lines, new_cursor, more, note)
