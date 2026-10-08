"""Erros no formato RFC 9457 (application/problem+json)."""
from __future__ import annotations

import json
import uuid

from flask import Response, current_app, g

TITLES = {400: "Requisição inválida", 401: "Não autenticado", 403: "Acesso negado", 404: "Não encontrado",
          405: "Método não permitido", 406: "Formato não aceito", 409: "Conflito", 412: "Recurso alterado",
          413: "Corpo grande demais", 415: "Formato do corpo não aceito", 422: "Regra de negócio",
          429: "Limite de requisições excedido", 500: "Erro interno", 503: "Serviço indisponível"}
SLUG = {400: "bad-request", 401: "unauthorized", 403: "forbidden", 404: "not-found", 405: "method-not-allowed",
        406: "not-acceptable", 409: "conflict", 412: "precondition-failed", 413: "payload-too-large",
        415: "unsupported-media-type", 422: "unprocessable", 429: "rate-limited", 500: "internal-error", 503: "unavailable"}


class ApiError(Exception):
    def __init__(self, status: int, detail: str = "", headers: dict | None = None, errors: list | None = None):
        super().__init__(detail)
        self.status, self.detail, self.headers, self.errors = status, detail, headers or {}, errors


def problem(status: int, detail: str = "", headers: dict | None = None, errors: list | None = None) -> Response:
    base = current_app.config.get("APP_BASE_URL", "")
    body = {"type": f"{base}/api/errors/{SLUG.get(status, 'error')}", "title": TITLES.get(status, "Erro"), "status": status,
            "detail": detail or TITLES.get(status, ""), "request_id": g.get("request_id") or uuid.uuid4().hex}
    if errors:
        body["errors"] = errors
    r = Response(json.dumps(body, ensure_ascii=False), status=status, mimetype="application/problem+json")
    for k, v in (headers or {}).items():
        r.headers[k] = v
    return r
