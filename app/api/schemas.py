"""Esquemas (Pydantic v2) de parâmetros e respostas da API v1. Deles sai o JSON Schema publicado no OpenAPI."""
from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field




class Out(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Query(BaseModel):
    model_config = ConfigDict(extra="forbid")


class In(BaseModel):
    """Corpo de requisição de escrita: campos desconhecidos são recusados (evita erro silencioso de digitação)."""
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


Short = Annotated[str, Field(max_length=120)]
Term = Annotated[str, Field(max_length=200)]


class PageQuery(Query):
    limit: int = Field(50, ge=1, le=200, description="Itens por página (máx. 200).")
    cursor: str | None = Field(None, max_length=500, description="Valor de `next_cursor` da página anterior.")


class Problem(Out):
    """Erro no formato RFC 9457."""
    type: str
    title: str
    status: int
    detail: str
    request_id: str
    errors: list[dict] | None = None


class Health(Out):
    status: Literal["ok"] = "ok"


class TenantRef(Out):
    id: int
    name: str


class Me(Out):
    """A chave que fez a chamada."""
    name: str = Field(description="Sistema consumidor.")
    prefix: str = Field(description="Parte pública da chave (tpk_live_<prefixo>…).")
    scope: Literal["global", "tenant"]
    tenant: TenantRef | None = None
    permissions: list[str]
    rate_per_min: int
    allowed_ips: list[str]
    expires_at: datetime


# ---------------------------------------------------------------- referências
