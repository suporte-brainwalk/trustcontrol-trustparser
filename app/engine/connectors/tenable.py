"""Tenable — vulnerabilidades (pull).

Tenable Vulnerability Management (cloud.tenable.com): cabeçalho X-ApiKeys: accessKey=…;secretKey=…;
fluxo assíncrono POST /vulns/export (filters.since) → GET /vulns/export/{uuid}/status → GET …/chunks/{id}.
O job em andamento fica no cursor e é retomado nas chamadas seguintes; o watermark (`since`) só avança quando o job
termina e todos os chunks foram baixados.

Tenable Security Center (on-premises): cabeçalho x-apikey: accesskey=…; secretkey=…; POST /rest/analysis
(type vuln, tool vulndetails, sourceType cumulative) filtrando lastSeen por intervalo epoch, paginação start/endOffset.
"""
from __future__ import annotations

from datetime import timedelta

from .base import (MAX_OBJECTS, Connector, ConnectorError, Field, PullResult, base_url, client_scope, csv_list, dumps,
                   register, utcnow)

DEFAULT_VM = "https://cloud.tenable.com"
SEVERITIES = ["info", "low", "medium", "high", "critical"]
EXPORT_MAX_AGE = timedelta(hours=20)  # chunks expiram em ~24h
SC_PAGE = 1000


@register
class Tenable(Connector):
    slug = "tenable"
    name = "Tenable (vulnerabilidades)"
    vendor = "Tenable"
    parser_slug = "tenable-vuln-export"
    default_interval_s = 3600
    fields = [
        Field("platform", "Plataforma", "select", default="vm",
              options=[("vm", "Tenable Vulnerability Management (nuvem)"), ("sc", "Tenable Security Center (on-prem)")]),
        Field("base_url", "URL base", "url", required=False, default=DEFAULT_VM,
              help="VM: https://cloud.tenable.com (FedRAMP: https://fedcloud.tenable.com). "
                   "Security Center: https://<host-do-sc> (certificado TLS válido obrigatório)."),
        Field("severities", "Severidades", required=False, default="low,medium,high,critical",
              help="Lista entre info, low, medium, high, critical."),
        Field("num_assets", "Ativos por chunk (VM)", "number", required=False, default="500",
              help="50 a 5000. Valores menores geram chunks menores."),
        Field("lookback_minutes", "Retroativo na 1ª coleta (min)", "number", required=False, default="1440",
              help="Na primeira execução, busca vulnerabilidades vistas/alteradas nos últimos N minutos."),
    ]
    secret_fields = [
        Field("access_key", "Access Key", "secret", help="Settings → My Account → API Keys → Generate (VM) "
                                                        "ou Users → API Keys (Security Center)."),
        Field("secret_key", "Secret Key", "secret", help="Gerada junto com a Access Key."),
    ]

    # -- comum ----------------------------------------------------------------------------------------------------
    def _platform(self, config) -> str:
        p = self.cfg(config, "platform")
        if p not in ("vm", "sc"):
            raise ConnectorError("Plataforma Tenable inválida.")
        return p

    def _base(self, config) -> str:
        if self._platform(config) == "sc":
            raw = self.cfg(config, "base_url")
            if not raw or raw.rstrip("/") == DEFAULT_VM:
                raise ConnectorError("Informe a URL do Tenable Security Center.")
            return base_url(raw, vendor="Tenable Security Center").removesuffix("/rest")
        return base_url(self.cfg(config, "base_url"), DEFAULT_VM, vendor=self.vendor)

    def _headers(self, config, secrets) -> dict:
        ak, sk = secrets.get("access_key", ""), secrets.get("secret_key", "")
        if self._platform(config) == "sc":
            return {"x-apikey": f"accesskey={ak}; secretkey={sk};", "Accept": "application/json"}
        return {"X-ApiKeys": f"accessKey={ak};secretKey={sk}", "Accept": "application/json"}

    def _severities(self, config) -> list[str]:
        sev = [s.lower() for s in csv_list(self.cfg(config, "severities")) if s.lower() in SEVERITIES]
        return sev or SEVERITIES[1:]

    def _num_assets(self, config) -> int:
        try:
            return max(50, min(5000, int(self.cfg(config, "num_assets") or 500)))
        except ValueError:
            return 500

    # -- Vulnerability Management ---------------------------------------------------------------------------------
    def _vm_create(self, c, base, config, secrets, since: int) -> str:
        body = {"num_assets": self._num_assets(config), "include_unlicensed": False,
                "filters": {"since": since, "state": ["OPEN", "REOPENED", "FIXED"],
                            "severity": self._severities(config)}}
        resp = self.http(secrets).request(c, "POST", f"{base}/vulns/export", json=body,
                                          headers=self._headers(config, secrets), ok=(409,))
        if resp.status_code == 409:
            raise ConnectorError("O Tenable já tem uma exportação de vulnerabilidades em andamento para este usuário "
                                 "(HTTP 409). Use um usuário de API exclusivo para o Trust Parser ou aguarde.")
        try:
            return str(resp.json()["export_uuid"])
        except (ValueError, KeyError, TypeError):
            raise ConnectorError("Tenable não retornou export_uuid.") from None

    def _vm_pull(self, c, config, secrets, cursor) -> PullResult:
        base = self._base(config)
        http = self.http(secrets)
        h = self._headers(config, secrets)
        now = utcnow()
        now_s = int(now.timestamp())
        since = int(cursor.get("since") or self.first_start(config, now).timestamp())
        job = dict(cursor.get("job") or {})
        notes = []
        if job and now_s - int(job.get("created", 0)) > EXPORT_MAX_AGE.total_seconds():
            notes.append("exportação anterior expirou; reiniciando")
            job = {}
        if not job:
            job = {"uuid": self._vm_create(c, base, config, secrets, since), "created": now_s, "done": [],
                   "partial": None}
        uid = job["uuid"]
        st = http.json(c, "GET", f"{base}/vulns/export/{uid}/status", headers=h)
        status = str(st.get("status", "")).upper() if isinstance(st, dict) else ""
        if status in ("ERROR", "CANCELLED"):
            return PullResult([], {"since": since}, False, f"exportação {uid} terminou com status {status}; "
                                                              "será recriada no próximo ciclo")
        if status not in ("QUEUED", "PROCESSING", "FINISHED"):
            raise ConnectorError(f"Status de exportação inesperado do Tenable: {status or '?'}.")
        done = set(int(x) for x in job.get("done") or [])
        available = sorted(int(x) for x in (st.get("chunks_available") or []))
        lines: list[str] = []
        more = False
        for chunk in [ch for ch in available if ch not in done]:
            skip = 0
            if job.get("partial") and int(job["partial"][0]) == chunk:
                skip = int(job["partial"][1])
            data = http.json(c, "GET", f"{base}/vulns/export/{uid}/chunks/{chunk}", headers=h)
            if not isinstance(data, list):
                raise ConnectorError(f"Chunk {chunk} do Tenable não é uma lista JSON.")
            budget = MAX_OBJECTS - len(lines)
            part = data[skip:skip + budget]
            lines += [dumps(o) for o in part]
            if skip + len(part) < len(data):
                job["partial"] = [chunk, skip + len(part)]
                more = True
                break
            job["partial"] = None
            done.add(chunk)
            if len(lines) >= MAX_OBJECTS:
                more = True
                break
        job["done"] = sorted(done)
        pending = [ch for ch in available if ch not in done]
        if status == "FINISHED" and not pending:
            # job concluído: próximo export parte do instante em que este foi criado
            return PullResult(lines, {"since": int(job["created"])}, False,
                              "; ".join(notes + [f"{len(lines)} vulnerabilidade(s); exportação {uid} concluída"]))
        if pending:
            more = True
        notes.append(f"{len(lines)} vulnerabilidade(s); exportação {uid} {status.lower()} "
                     f"({len(done)}/{st.get('total_chunks', '?')} chunks)")
        return PullResult(lines, {"since": since, "job": job}, more, "; ".join(notes))

    # -- Security Center ------------------------------------------------------------------------------------------
    _SC_SEV = {"info": "0", "low": "1", "medium": "2", "high": "3", "critical": "4"}

    def _sc_query(self, config, start: int, end: int, offset: int, size: int) -> dict:
        sev = ",".join(self._SC_SEV[s] for s in self._severities(config))
        return {"type": "vuln", "sourceType": "cumulative",
                "query": {"tool": "vulndetails", "type": "vuln",
                          "filters": [{"filterName": "lastSeen", "operator": "=", "value": f"{start}-{end}"},
                                      {"filterName": "severity", "operator": "=", "value": sev}]},
                "sortField": "lastSeen", "sortDir": "ASC", "startOffset": offset, "endOffset": offset + size}

    def _sc_post(self, c, config, secrets, body) -> dict:
        base = self._base(config)
        data = self.http(secrets).json(c, "POST", f"{base}/rest/analysis", json=body,
                                       headers=self._headers(config, secrets))
        resp = data.get("response") if isinstance(data, dict) else None
        if not isinstance(resp, dict) or not isinstance(resp.get("results", []), list):
            msg = data.get("error_msg") if isinstance(data, dict) else ""
            raise ConnectorError("Resposta inesperada do Tenable Security Center" + (f": {msg}" if msg else "."))
        return resp

    def _sc_pull(self, c, config, secrets, cursor) -> PullResult:
        now = int(utcnow().timestamp())
        since = int(cursor.get("since") or self.first_start(config).timestamp())
        until = int(cursor.get("until") or now)
        offset = int(cursor.get("offset") or 0)
        lines: list[str] = []
        more = False
        while True:
            size = min(SC_PAGE, MAX_OBJECTS - len(lines))
            resp = self._sc_post(c, config, secrets, self._sc_query(config, since, until, offset, size))
            rows = resp.get("results") or []
            lines += [dumps(r) for r in rows]
            offset += len(rows)
            try:
                total = int(resp.get("totalRecords"))
            except (TypeError, ValueError):
                total = None
            if len(rows) < size or (total is not None and offset >= total):
                break
            if len(lines) >= MAX_OBJECTS:
                more = True
                break
        if more:
            return PullResult(lines, {"since": since, "until": until, "offset": offset}, True,
                              f"{len(lines)} vulnerabilidade(s); continua no próximo ciclo")
        return PullResult(lines, {"since": until + 1}, False, f"{len(lines)} vulnerabilidade(s)")

    # ------------------------------------------------------------------------------------------------------------
    def test(self, config, secrets, client=None) -> str:
        self.validate(config, secrets)
        base = self._base(config)
        with client_scope(client) as c:
            if self._platform(config) == "sc":
                data = self.http(secrets).json(c, "GET", f"{base}/rest/currentUser",
                                               headers=self._headers(config, secrets))
                user = ((data or {}).get("response") or {}).get("username", "?") if isinstance(data, dict) else "?"
                return f"Conexão OK com Tenable Security Center: chave aceita (usuário {user})."
            data = self.http(secrets).json(c, "GET", f"{base}/session", headers=self._headers(config, secrets))
            user = data.get("username", "?") if isinstance(data, dict) else "?"
        return f"Conexão OK com Tenable Vulnerability Management: chave aceita (usuário {user})."

    def pull(self, config, secrets, cursor, client=None) -> PullResult:
        self.validate(config, secrets)
        cursor = cursor or {}
        with client_scope(client) as c:
            if self._platform(config) == "sc":
                return self._sc_pull(c, config, secrets, cursor)
            return self._vm_pull(c, config, secrets, cursor)

