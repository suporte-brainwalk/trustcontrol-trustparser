"""API do Trust Parser (v1): /api/v1. Leitura e administração (escrita), autenticadas por chaves gerenciadas no portal.

A sessão do navegador nunca autoriza nada aqui: só o cabeçalho Authorization: Bearer (sem cookie, sem CSRF)."""
from __future__ import annotations

import uuid

from flask import g, request

from .errors import ApiError, problem
from .registry import ROUTES, bp  # noqa: F401  (ROUTES é usado pelo gerador OpenAPI)
from . import routes  # noqa: F401,E402  (registra as rotas no blueprint)


@bp.before_request
def _start():
    g.request_id = uuid.uuid4().hex
    g.api_key = None
    g.rate_headers = {}
    g.dry_run = False


@bp.after_request
def _finish(resp):
    resp.headers["X-Request-ID"] = g.get("request_id", "")
    for k, v in (g.get("rate_headers") or {}).items():
        resp.headers.setdefault(k, v)
    resp.headers["Cache-Control"] = "no-store"
    resp.headers.pop("Set-Cookie", None) if g.get("api_key") is not None else None
    k = g.get("api_key")
    if k is not None:
        from ..db import Session
        from ..security import client_ip
        from ..services import api_keys
        try:
            route = request.url_rule.rule if request.url_rule else request.path
            if request.method != "GET":  # escrita gravada com o método (conta como alteração); simulação marcada à parte
                route = f"{'DRY ' if g.get('dry_run') else ''}{request.method} {route}"
            api_keys.record_use(k, client_ip(), route, resp.status_code)
            Session.commit()
        except Exception:  # noqa: BLE001 — registro de uso nunca derruba a resposta
            Session.rollback()
    return resp


WRITE_REFUSALS = (403, 409, 412, 422)


@bp.errorhandler(ApiError)
def _api_error(e: ApiError):
    k = g.get("api_key")
    if k is not None and request.method != "GET" and e.status in WRITE_REFUSALS:
        _audit_refusal(k, e)
    return problem(e.status, e.detail, e.headers, e.errors)


def _audit_refusal(k, e: ApiError):
    """Escrita recusada (sem permissão, conflito, regra, ETag): fica na auditoria para mostrar tentativas indevidas."""
    from ..db import Session
    from ..security import client_ip
    from ..services import audit
    from .registry import actor_label
    try:
        Session.rollback()
        audit.log("api.escrita_recusada", f"{request.method} {request.path}"[:300], actor_label=actor_label(k), tenant_id=k.tenant_id,
                  details={"status": e.status, "motivo": (e.detail or "")[:300], "request_id": g.get("request_id", "")}, ip=client_ip())
        Session.commit()
    except Exception:  # noqa: BLE001 — auditoria da recusa nunca derruba a resposta
        Session.rollback()


def is_api_request() -> bool:
    return request.path.startswith("/api/")


def init_api(app, csrf):
    from .docs import docs_bp
    csrf.exempt(bp)
    app.register_blueprint(bp)
    app.register_blueprint(docs_bp)
