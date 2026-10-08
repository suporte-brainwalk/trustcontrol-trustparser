"""Utilitários: saúde, dados da própria chave e a especificação OpenAPI."""
from __future__ import annotations

from flask import g
from flask_login import current_user

from ...db import Session
from ...models import Tenant
from ..auth import authenticate
from ..registry import api_get, bp, json_response
from ..schemas import Health, Me, TenantRef


@api_get("/health", summary="Disponibilidade da API", response=Health, auth=False, tags=["Utilitários"])
def health():
    """Responde `ok` quando a API está no ar. Não exige chave e não expõe detalhes internos."""
    return Health()


@api_get("/me", summary="Dados da chave usada na chamada", response=Me, tags=["Utilitários"])
def me():
    """Nome, escopo, permissões, limite e validade da chave que fez a requisição."""
    k = g.api_key
    t = Session.get(Tenant, k.tenant_id) if k.tenant_id else None
    return Me(name=k.name, prefix=f"tpk_live_{k.prefix}", scope="tenant" if t else "global",
              tenant=TenantRef(id=t.id, name=t.name) if t else None, permissions=list(k.permissions or []),
              rate_per_min=k.rate_per_min, allowed_ips=list(k.allowed_ips or []), expires_at=k.expires_at)


@bp.get("/openapi.json")
def openapi_json():
    """Especificação OpenAPI 3.1. Acesso: administrador logado no portal ou chave de API válida."""
    if not (current_user.is_authenticated and getattr(current_user, "role", "") == "admin"):
        authenticate()
    from ..openapi import build_spec
    return json_response(build_spec())
