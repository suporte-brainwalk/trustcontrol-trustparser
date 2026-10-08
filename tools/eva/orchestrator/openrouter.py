"""Chamadas diretas (não agênticas) do orquestrador ao OpenRouter: situação da chave e chat completions.

Toda chamada de modelo feita daqui exige provedores com retenção zero de dados: {"provider": {"zdr": true}}.
(O agente no sandbox usa o endpoint compatível /api/v1/messages; ali a restrição ZDR vem da trava da própria chave
no OpenRouter — ver docs/eva.md, "IA".)
"""
from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request

from . import config

log = logging.getLogger("eva.openrouter")


class OpenRouterError(RuntimeError):
    pass


def _req(method: str, path: str, body: dict | None = None, timeout: int = 30) -> dict:
    key = config.openrouter_key()
    if not key:
        raise OpenRouterError("chave da IA não configurada")
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(config.OPENROUTER_API.rstrip("/") + path, data=data, method=method, headers={
        "Authorization": f"Bearer {key}", "Content-Type": "application/json", "Accept": "application/json",
        "X-Title": "Trust Parser EVA", "HTTP-Referer": config.PORTAL_URL})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace") or "{}")
    except urllib.error.HTTPError as e:
        raise OpenRouterError(f"HTTP {e.code}") from None
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        raise OpenRouterError(type(e).__name__) from None


def key_status() -> dict:
    """{ok, limit_remaining, usage} da chave (GET /key — não consome tokens). ok=False se a chave falhar."""
    try:
        d = (_req("GET", "/key", timeout=15) or {}).get("data") or {}
    except OpenRouterError as e:
        return {"ok": False, "erro": str(e)}
    return {"ok": True, "limit_remaining": d.get("limit_remaining"), "usage": d.get("usage"), "limit": d.get("limit")}


def chat_payload(system: str, user: str, *, schema: dict | None = None, max_tokens: int = 2000) -> dict:
    body = {"model": config.ai_model(), "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "max_tokens": max_tokens, "temperature": 0.3,
            "provider": {"zdr": True, "data_collection": "deny", "allow_fallbacks": True}}
    if schema:
        body["response_format"] = {"type": "json_schema", "json_schema": {"name": "resposta", "strict": False, "schema": schema}}
    return body


def chat_json(system: str, user: str, *, schema: dict | None = None, max_tokens: int = 2000) -> tuple[dict, float]:
    """Resposta JSON de uma chamada simples (sem ferramentas). Devolve (objeto, custo_usd)."""
    out = _req("POST", "/chat/completions", chat_payload(system, user, schema=schema, max_tokens=max_tokens), timeout=180)
    try:
        txt = out["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError, TypeError):
        raise OpenRouterError("resposta sem conteúdo") from None
    txt = txt.strip()
    if txt.startswith("```"):
        txt = txt.strip("`")
        txt = txt[txt.find("{"):]
    try:
        obj = json.loads(txt[txt.find("{"): txt.rfind("}") + 1])
    except ValueError:
        raise OpenRouterError("resposta não é JSON") from None
    cost = float(((out.get("usage") or {}).get("cost")) or 0)
    return obj, cost
