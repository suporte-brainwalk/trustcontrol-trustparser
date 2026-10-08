"""Consulta de dados do Trust Parser para o agente, pela API de leitura (v1), com a chave protegida da EVA.

O agente roda num sandbox sem rede até o Trust Parser e nunca vê a chave: ele só PEDE caminhos (ex.: "/sources?tenant_id=3");
este módulo (código determinístico do orquestrador) valida cada caminho contra uma lista fechada de rotas somente leitura,
faz o GET e devolve o JSON — truncado — para o agente usar na resposta. A API nunca devolve segredos (destinos e conectores
mostram só "cadastrado em/por"); mesmo assim, chaves com nome de segredo são removidas da resposta antes de chegar ao agente.

Manter a lista ALLOWED alinhada às rotas GET de app/api/routes/ (somente leitura).
"""
from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request

from . import config

log = logging.getLogger("eva.dataapi")
MAX_QUERIES = 6
MAX_CHARS = 12000
_ID = r"(?:/\d+)?"
_ROUTE = (r"/(?:me|health|stats/summary"
          r"|tenants(?:/\d+(?:/(?:sources|destinations|allowed-ips|people|uploads))?)?"
          r"|sources" + _ID + r"(?:/(?:metrics|unparsed))?"
          r"|allowed-ips" + _ID +
          r"|destinations" + _ID + r"(?:/(?:metrics|deliveries))?"
          r"|parsers" + _ID + r"(?:/versions(?:/\d+)?)?"
          r"|formats" + _ID +
          r"|studio/jobs" + _ID +
          r"|uploads" + _ID + r")")
ALLOWED = re.compile(r"^" + _ROUTE + r"(?:\?[A-Za-z0-9_=&%.:+,\-]{0,300})?$")
SECRET_KEY_RX = re.compile(r"(?i)(secret|senha|password|passwd|token|api_?key|credential|private_key|service_account|client_secret)")

HELP = """CONSULTA DE DADOS DO TRUST PARSER (somente leitura). Quando a resposta depender de fatos (se uma fonte está recebendo,
quantas linhas não foram reconhecidas, situação de um destino, quais IPs estão liberados, pessoas de um tenant, andamento de um
pedido ao Estúdio IA), NÃO suponha: peça os dados em "consultar_dados" (até 6 caminhos da API v1) e eu devolvo o resultado na
próxima mensagem. Caminhos válidos:
  /tenants · /tenants/ID · /tenants/ID/sources · /tenants/ID/destinations · /tenants/ID/allowed-ips · /tenants/ID/people
  /sources?tenant_id=ID · /sources/ID · /sources/ID/metrics · /sources/ID/unparsed
  /allowed-ips?tenant_id=ID · /destinations?tenant_id=ID · /destinations/ID · /destinations/ID/deliveries
  /parsers?kind=input · /parsers/ID · /parsers/ID/versions · /formats · /studio/jobs · /studio/jobs/ID
  /uploads?tenant_id=ID · /stats/summary · /me
Credenciais nunca aparecem (só "cadastrada em/por"). Listas vêm paginadas (next_cursor): use limit=200 e, se a resposta
depender do total, confira se next_cursor veio null. Use "consultar_dados" vazio quando já tiver o que precisa.
Nunca copie listas inteiras na resposta: resuma o que importa."""


def valid(path: str) -> bool:
    return isinstance(path, str) and bool(ALLOWED.match(path.strip())) and ".." not in path


def scrub(obj):
    """Remove campos com nome de segredo (defesa extra: a API já não devolve segredos)."""
    if isinstance(obj, dict):
        return {k: ("[omitido]" if SECRET_KEY_RX.search(str(k)) and not str(k).endswith(("_set_at", "_set_by")) else scrub(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [scrub(x) for x in obj]
    return obj


def consult(paths) -> dict:
    """Executa até MAX_QUERIES consultas válidas. Caminho inválido ou erro vira {"erro": ...} (nunca exceção)."""
    out: dict = {}
    if not config.API_KEY:
        return {p: {"erro": "acesso aos dados indisponível (chave da EVA não configurada)"} for p in (paths or [])[:MAX_QUERIES]}
    for p in [x.strip() for x in (paths or []) if isinstance(x, str)][:MAX_QUERIES]:
        if not valid(p):
            out[p] = {"erro": "caminho não permitido"}
            continue
        req = urllib.request.Request(config.API_BASE.rstrip("/") + p, headers={
            "Authorization": f"Bearer {config.API_KEY}", "Accept": "application/json", "X-Real-IP": "eva-orquestrador"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                data = scrub(json.loads(r.read().decode("utf-8", "replace")))
        except urllib.error.HTTPError as e:
            data = {"erro": f"HTTP {e.code}"}
        except Exception as e:  # noqa: BLE001
            data = {"erro": f"consulta indisponível ({type(e).__name__})"}
        txt = json.dumps(data, ensure_ascii=False)
        if len(txt) > MAX_CHARS:
            data = {"truncado": True, "inicio": txt[:MAX_CHARS]}
        out[p] = data
    log.info("consultas de dados: %s", list(out))
    return out
