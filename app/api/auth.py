"""Autenticação da API: Bearer → chave (HMAC) → validade/revogação/IP → limite por chave. Permissão e escopo nas rotas."""
from __future__ import annotations

import time

from flask import g, request
from limits import RateLimitItemPerMinute

from ..security import client_ip
from ..services import api_keys, audit
from ..web.limiter import limiter
from .errors import ApiError


def bearer() -> str:
    h = request.headers.get("Authorization", "")
    return h[7:].strip() if h[:7].lower() == "bearer " else ""


def authenticate():
    """Define g.api_key ou levanta ApiError (401/403/429). Toda negação vai para a auditoria, sem o segredo."""
    token, ip = bearer(), client_ip()
    v = api_keys.verify(token, ip)
    if v.reason:
        if not token:  # sem cabeçalho: responde 401 sem auditar (evita encher a auditoria com varreduras automáticas)
            raise ApiError(401, "Chave de API ausente, inválida, revogada ou expirada.", {"WWW-Authenticate": 'Bearer realm="trustparser"'})
        prefix = v.key.prefix if v.key is not None else (token.split("_")[2][:8] if token.startswith("tpk_live_") and token.count("_") >= 3 else "")
        audit.log("api.negado", f"tpk_live_{prefix}…" if prefix else "(sem chave válida)", actor_label="api",
                  tenant_id=v.key.tenant_id if v.key is not None else None,
                  details={"motivo": v.reason, "rota": request.path[:120]}, ip=ip)
        from ..db import Session
        Session.commit()
        hdr = {"WWW-Authenticate": 'Bearer realm="trustparser"'} if v.status == 401 else {}
        raise ApiError(v.status, "Chave de API ausente, inválida, revogada ou expirada." if v.status == 401 else v.reason, hdr)
    k = v.key
    item = RateLimitItemPerMinute(k.rate_per_min)
    allowed = limiter.limiter.hit(item, "api", str(k.id))
    stats = limiter.limiter.get_window_stats(item, "api", str(k.id))
    g.rate_headers = {"RateLimit-Limit": str(k.rate_per_min), "RateLimit-Remaining": str(max(0, stats.remaining)),
                      "RateLimit-Reset": str(max(0, int(stats.reset_time - time.time())))}
    g.api_key = k
    if not allowed:
        raise ApiError(429, f"Limite de {k.rate_per_min} requisições por minuto desta chave excedido.",
                       {**g.rate_headers, "Retry-After": g.rate_headers["RateLimit-Reset"]})


def require(permission: str | None):
    k = g.api_key
    if permission and permission not in (k.permissions or []):
        raise ApiError(403, f"A chave não tem a permissão {permission}.")


def tenant_scope() -> int | None:
    """Tenant da chave (None = global)."""
    return g.api_key.tenant_id


def check_tenant(tenant_id: int):
    """Chave de tenant só acessa o próprio tenant; os demais respondem 404 (não revela existência)."""
    scope = tenant_scope()
    if scope is not None and scope != tenant_id:
        raise ApiError(404, "Recurso não encontrado.")
