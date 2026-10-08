"""Trend Vision One — Workbench alerts (e, opcionalmente, OAT detections) via API v3.0 (pull).

Auth: Authorization: Bearer <API key>. Base por região (api.xdr.trendmicro.com, api.eu..., etc.).
Workbench: GET /v3.0/workbench/alerts?startDateTime&endDateTime&dateTimeTarget&orderBy=<alvo> asc, paginação nextLink
(o cabeçalho TMV1-Filter é reenviado em cada nextLink). OAT: GET /v3.0/oat/detections com janela de ingestão.
Cursor separado por fluxo: {"workbench": {...}, "oat": {...}}.
"""
from __future__ import annotations

from datetime import timedelta
from urllib.parse import urlencode

from .base import (MAX_OBJECTS, Connector, ConnectorError, Field, PullResult, Watermark, base_url, client_scope,
                   dumps, from_ms, iso, register, same_origin, to_ms, utcnow)

REGIONS = [
    ("us", "Estados Unidos", "https://api.xdr.trendmicro.com"),
    ("eu", "União Europeia (Alemanha)", "https://api.eu.xdr.trendmicro.com"),
    ("sg", "Singapura", "https://api.sg.xdr.trendmicro.com"),
    ("jp", "Japão", "https://api.xdr.trendmicro.co.jp"),
    ("au", "Austrália", "https://api.au.xdr.trendmicro.com"),
    ("in", "Índia", "https://api.in.xdr.trendmicro.com"),
    ("mea", "Emirados Árabes (MEA)", "https://api.mea.xdr.trendmicro.com"),
    ("uk", "Reino Unido", "https://api.uk.xdr.trendmicro.com"),
    ("ca", "Canadá", "https://api.ca.xdr.trendmicro.com"),
    ("usgov", "US Government", "https://api.usgov.xdr.trendmicro.com"),
]
REGION_URL = {k: u for k, _, u in REGIONS}


@register
class TrendVisionOne(Connector):
    slug = "trend-vision-one"
    name = "Trend Vision One (Workbench / OAT)"
    vendor = "Trend Vision One"
    parser_slug = "trend-vision-one-api-alert"
    default_interval_s = 300
    fields = [
        Field("region", "Região do console", "select", default="us",
              options=[(k, f"{n} — {u.split('//')[1]}") for k, n, u in REGIONS],
              help="Região onde o console Vision One está hospedado (Administration → API Keys mostra a URL)."),
        Field("base_url", "URL base (opcional)", "url", required=False,
              help="Sobrepõe a região. Use só se a Trend indicar outro host."),
        Field("streams", "Dados coletados", "select", required=False, default="workbench",
              options=[("workbench", "Workbench alerts"), ("workbench_oat", "Workbench alerts + OAT detections")]),
        Field("date_target", "Critério de tempo (Workbench)", "select", required=False, default="createdDateTime",
              options=[("createdDateTime", "Alertas novos (createdDateTime)"),
                       ("updatedDateTime", "Novos e atualizados (updatedDateTime)")],
              help="Com 'atualizados', o mesmo alerta é reenviado quando muda de status."),
        Field("filter", "Filtro TMV1-Filter (opcional)", required=False,
              help="Sintaxe OData da Trend. Ex.: severity eq 'high' or severity eq 'critical'"),
        Field("lookback_minutes", "Retroativo na 1ª coleta (min)", "number", required=False, default="60"),
    ]
    secret_fields = [
        Field("api_token", "API Key (token)", "secret",
              help="Administration → API Keys → Add API key, com papel que permita ver Workbench (e OAT, se usado)."),
    ]

    def _base(self, config) -> str:
        if self.cfg(config, "base_url"):
            return base_url(self.cfg(config, "base_url"), vendor=self.vendor)
        region = self.cfg(config, "region")
        if region not in REGION_URL:
            raise ConnectorError("Região do Trend Vision One inválida.")
        return REGION_URL[region]

    def _headers(self, config, secrets, with_filter: bool) -> dict:
        h = {"Authorization": f"Bearer {secrets.get('api_token', '')}", "Accept": "application/json"}
        f = self.cfg(config, "filter")
        if with_filter and f:
            h["TMV1-Filter"] = f
        return h

    def _get(self, c, config, secrets, url, with_filter) -> dict:
        data = self.http(secrets).json(c, "GET", url, headers=self._headers(config, secrets, with_filter))
        if not isinstance(data, dict) or not isinstance(data.get("items", []), list):
            raise ConnectorError(f"Resposta inesperada do {self.vendor} (sem lista 'items').")
        return data

    # -- fluxos ---------------------------------------------------------------------------------------------------
    def _stream_specs(self, config, base, start, end):
        target = self.cfg(config, "date_target")
        if target not in ("createdDateTime", "updatedDateTime"):
            target = "createdDateTime"
        wb_q = {"startDateTime": iso(start, ms=False), "endDateTime": iso(end, ms=False),
                "dateTimeTarget": target, "orderBy": f"{target} asc"}

        def wb_key(it):
            k = str(it.get("id") or dumps(it)[:200])
            return f"{k}|{it.get('updatedDateTime', '')}" if target == "updatedDateTime" else k

        specs = {"workbench": (f"{base}/v3.0/workbench/alerts?{urlencode(wb_q)}", True,
                               lambda it: it.get(target) or it.get("createdDateTime"), wb_key)}
        if self.cfg(config, "streams") == "workbench_oat":
            oat_q = {"ingestedStartDateTime": iso(start, ms=False), "ingestedEndDateTime": iso(end, ms=False),
                     # sem janela de detecção a API assume a última 1h; ampliamos para não perder ingestão tardia
                     "detectedStartDateTime": iso(start - timedelta(days=7), ms=False),
                     "detectedEndDateTime": iso(end, ms=False), "top": "200"}
            specs["oat"] = (f"{base}/v3.0/oat/detections?{urlencode(oat_q)}", False,
                            lambda it: it.get("ingestedDateTime") or it.get("detectedDateTime"),
                            lambda it: str(it.get("uuid") or dumps(it)[:200]))
        return specs

    def _run_stream(self, c, config, secrets, base, name, scur, now, budget, lines) -> tuple[dict, bool]:
        """Lê um fluxo até esgotar ou atingir `budget`. Retorna (cursor do fluxo, more)."""
        wm = Watermark.load(scur, self.first_start(config, now))
        resume = scur.get("resume") or {}
        start = from_ms(wm.since_ms)
        end = from_ms(int(resume["end_ms"])) if resume.get("end_ms") else now
        url0, with_filter, ts_of, key_of = self._stream_specs(config, base, start, end)[name]
        url, skip = url0, 0
        if resume:
            if resume.get("url") and same_origin(resume["url"], base):
                url, skip = resume["url"], int(resume.get("skip") or 0)
            wm.since_ms = int(resume.get("max_ms") or wm.since_ms)
            wm.boundary = set(resume.get("max_boundary") or [])
        added = 0
        while url:
            data = self._get(c, config, secrets, url, with_filter)
            items = data.get("items") or []
            consumed = 0
            for it in items[skip:]:
                consumed += 1
                if wm.offer(ts_of(it), key_of(it)):
                    lines.append(dumps(it))
                    added += 1
                    if added >= budget:
                        break
            nxt = data.get("nextLink")
            if nxt and not same_origin(nxt, base):
                raise ConnectorError(f"{self.vendor} devolveu nextLink para outro host; coleta interrompida.")
            if added >= budget and (skip + consumed < len(items) or nxt):
                nxt_url, nxt_skip = (url, skip + consumed) if skip + consumed < len(items) else (nxt, 0)
                return ({"since": scur.get("since") or iso(start), "boundary": scur.get("boundary") or [],
                         "resume": {"end_ms": to_ms(end), "url": nxt_url, "skip": nxt_skip, "max_ms": wm.since_ms,
                                    "max_boundary": sorted(wm.boundary)[-500:]}}, True)
            skip = 0
            url = nxt
        return wm.finish(complete=True, end=end), False

    # ------------------------------------------------------------------------------------------------------------
    def test(self, config, secrets, client=None) -> str:
        self.validate(config, secrets)
        base = self._base(config)
        now = utcnow()
        q = {"startDateTime": iso(now - timedelta(days=1), ms=False), "endDateTime": iso(now, ms=False)}
        with client_scope(client) as c:
            data = self._get(c, config, secrets, f"{base}/v3.0/workbench/alerts?{urlencode(q)}", True)
            extra = ""
            if self.cfg(config, "streams") == "workbench_oat":
                q2 = {"detectedStartDateTime": iso(now - timedelta(hours=1), ms=False),
                      "detectedEndDateTime": iso(now, ms=False), "top": "50"}
                self._get(c, config, secrets, f"{base}/v3.0/oat/detections?{urlencode(q2)}", False)
                extra = " OAT detections acessível."
        total = data.get("totalCount", len(data.get("items") or []))
        return f"Conexão OK com {self.vendor}: token aceito; {total} alerta(s) Workbench nas últimas 24h.{extra}"

    def pull(self, config, secrets, cursor, client=None) -> PullResult:
        self.validate(config, secrets)
        base = self._base(config)
        cursor = dict(cursor or {})
        now = utcnow()
        lines: list[str] = []
        more = False
        notes = []
        streams = ["workbench"] + (["oat"] if self.cfg(config, "streams") == "workbench_oat" else [])
        with client_scope(client) as c:
            for name in streams:
                budget = MAX_OBJECTS - len(lines)
                if budget <= 0:
                    more = True
                    break
                n0 = len(lines)
                cursor[name], m = self._run_stream(c, config, secrets, base, name, cursor.get(name) or {}, now,
                                                   budget, lines)
                more = more or m
                notes.append(f"{name}: {len(lines) - n0}")
        return PullResult(lines, cursor, more, ", ".join(notes))
