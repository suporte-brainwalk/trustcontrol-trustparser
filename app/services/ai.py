"""Chamadas à IA (OpenRouter), só para o Estúdio: gerar/ajustar specs. Somente provedores com retenção zero (ZDR).
Teto de gasto local (AI_BUDGET_USD) além do limite configurado na própria chave."""
from __future__ import annotations

import json
import logging
import re
import time

import httpx
from flask import current_app

from . import settings

log = logging.getLogger(__name__)
URL = "https://openrouter.ai/api/v1/chat/completions"


class AIError(Exception):
    pass


def budget_left() -> float:
    return float(current_app.config.get("AI_BUDGET_USD") or 0) - float(settings.get("ai_spend_usd") or 0)


def chat(messages: list[dict], *, max_tokens: int = 32000, temperature: float = 0.1, json_mode: bool = True) -> tuple[str, dict]:
    """Devolve (texto, uso={cost, prompt_tokens, completion_tokens, model}). Gasto acumulado em settings.ai_spend_usd."""
    key = current_app.config.get("OPENROUTER_API_KEY")
    if not key or not current_app.config.get("AI_ENABLED", True):
        raise AIError("IA não configurada neste servidor.")
    if budget_left() <= 0:
        raise AIError("Teto de gasto de IA atingido (AI_BUDGET_USD). Ajuste o limite para continuar.")
    model = current_app.config.get("AI_PRIMARY_MODEL")
    body = {"model": model, "messages": messages, "max_tokens": max_tokens, "temperature": temperature,
            "provider": {"zdr": True, "data_collection": "deny"}, "usage": {"include": True},
            "reasoning": {"max_tokens": 6000}}  # raciocínio limitado: sobra espaço para o JSON completo
    if json_mode:
        body["response_format"] = {"type": "json_object"}
    # Streaming (SSE): gerações longas (ex.: parser CBN) passam de 10 min e, sem stream, o gateway devolve 504.
    body["stream"] = True
    last = None
    for attempt in range(3):
        try:
            status, err_text, data = _stream(body, key)
        except httpx.HTTPError as e:
            last = f"falha de conexão com o serviço de IA: {e}"
            time.sleep(3 * (attempt + 1))
            continue
        if status in (429, 500, 502, 503, 504):
            last = f"serviço de IA indisponível (HTTP {status})"
            time.sleep(5 * (attempt + 1))
            continue
        if status >= 400:
            raise AIError(f"serviço de IA recusou a chamada (HTTP {status}): {err_text[:300]}")
        usage = data.get("usage") or {}
        cost = float(usage.get("cost") or 0)
        settings.set_("ai_spend_usd", round(float(settings.get("ai_spend_usd") or 0) + cost, 6))
        if data.get("error"):
            last = f"serviço de IA interrompeu a resposta: {str(data['error'])[:200]}"
            time.sleep(5 * (attempt + 1))
            continue
        text = data.get("content") or ""
        if data.get("finish_reason") == "length" and attempt < 2:
            body["max_tokens"] = min(64000, int(body["max_tokens"] * 1.5))
            last = "resposta cortada pelo limite de tamanho"
            continue
        if not text.strip():
            last = "resposta vazia"
            if attempt < 2:
                continue
            break
        return text, {"cost": cost, "prompt_tokens": usage.get("prompt_tokens"), "completion_tokens": usage.get("completion_tokens"),
                      "model": data.get("model") or model}
    raise AIError(last or "serviço de IA indisponível")


def _stream(body: dict, key: str) -> tuple[int, str, dict]:
    """POST com stream=True; junta os pedaços. Devolve (status, texto_de_erro, {content, finish_reason, usage, model, error})."""
    t = current_app.config.get("AI_TIMEOUT", 300)
    out = {"content": "", "finish_reason": None, "usage": None, "model": None, "error": None}
    parts = []
    with httpx.stream("POST", URL, json=body, timeout=httpx.Timeout(t, connect=30),
                      headers={"Authorization": f"Bearer {key}", "HTTP-Referer": current_app.config["APP_BASE_URL"],
                               "X-Title": "Trust Parser"}) as r:
        if r.status_code >= 400:
            return r.status_code, r.read().decode("utf-8", "replace"), out
        for line in r.iter_lines():
            if not line.startswith("data:"):
                continue  # comentários ": OPENROUTER PROCESSING" mantêm a conexão viva
            payload = line[5:].strip()
            if payload == "[DONE]":
                break
            try:
                ev = json.loads(payload)
            except ValueError:
                continue
            if ev.get("error"):
                out["error"] = ev["error"]
            out["model"] = ev.get("model") or out["model"]
            if ev.get("usage"):
                out["usage"] = ev["usage"]
            for ch in ev.get("choices") or []:
                delta = ch.get("delta") or {}
                if delta.get("content"):
                    parts.append(delta["content"])
                if ch.get("finish_reason"):
                    out["finish_reason"] = ch["finish_reason"]
                    if ch["finish_reason"] == "error":
                        out["error"] = out["error"] or "finish_reason=error"
    out["content"] = "".join(parts)
    return r.status_code, "", out


def parse_json(text: str) -> dict:
    t = text.strip()
    m = re.search(r"```(?:json)?\s*(\{.*\})\s*```", t, re.S)
    if m:
        t = m.group(1)
    if not t.startswith("{"):
        i, j = t.find("{"), t.rfind("}")
        if i >= 0 and j > i:
            t = t[i:j + 1]
    try:
        return json.loads(t)
    except ValueError as e:
        raise AIError(f"a IA não devolveu JSON válido ({e})") from e
