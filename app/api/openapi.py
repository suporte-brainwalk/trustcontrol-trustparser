"""Gera a especificação OpenAPI 3.1 a partir do registro de rotas e dos esquemas Pydantic."""
from __future__ import annotations

from flask import current_app
from pydantic.json_schema import models_json_schema

from ..services.api_keys import PERMISSIONS
from .registry import ROUTES
from .schemas import Problem

REF = "#/components/schemas/{model}"
SUPPORT_EMAIL = "jarbas@trustcontrol.nuvem.tec.br"  # suporte por e-mail: dúvidas e pedidos vão para o Jarbas
ERRORS = {400: "Parâmetros inválidos", 401: "Chave ausente, inválida, revogada ou expirada",
          403: "Permissão insuficiente ou IP não autorizado", 404: "Não encontrado (inclui recurso de outro tenant)",
          429: "Limite de requisições da chave excedido"}
WRITE_ERRORS = {400: "Corpo ou parâmetros inválidos", 401: ERRORS[401], 403: "Permissão insuficiente, IP não autorizado ou fora do tenant da chave",
                404: ERRORS[404], 409: "Conflito com o estado atual (nome duplicado, item em uso…)",
                412: "If-Match diferente do ETag atual: o recurso mudou desde a sua leitura",
                415: "Corpo precisa ser application/json", 422: "Regra de negócio (mensagem igual à da tela do portal)",
                429: "Limite de requisições ou de alterações por minuto da chave"}
DESCRIPTION = """API do **Trust Parser** (Trust Parser): leitura e administração.

**Autenticação:** cabeçalho `Authorization: Bearer tpk_live_…` com uma chave criada em *Administração → API* no portal.
Cada chave tem **escopo** (global ou um tenant) e **permissões** por tipo de dado; recursos de outro tenant respondem `404`.

**Paginação:** listas devolvem `{"data": [...], "next_cursor": ...}`; envie `cursor=<next_cursor>` para a próxima página
(`limit` até 200). **Sincronização incremental:** `updated_since` (ISO-8601).

**Cache:** respostas trazem `ETag`; envie `If-None-Match` para receber `304` quando nada mudou.

**Limites:** por chave (`RateLimit-*` nas respostas; `429` com `Retry-After`). **Erros:** `application/problem+json` (RFC 9457).

**Administração (escrita):** `POST`, `PATCH` e `DELETE` com as mesmas regras da tela do portal. Exigem uma permissão
`…:gerenciar` (ou `jarbas:…`), chave com lista de IPs de origem e respeitam **10 alterações por minuto por chave**.
- `?dry_run=true` valida e mostra o resultado **sem gravar nada e sem enviar e-mail**;
- `Idempotency-Key` (POST): repetir a mesma chamada devolve o mesmo resultado, sem duplicar (24 h);
- `If-Match: <ETag do GET>` (PATCH/DELETE): devolve `412` se alguém alterou o recurso nesse meio-tempo;
- toda alteração entra na Auditoria do portal com a chave como autora.

Acesso somente a partir do Brasil. Datas em UTC (ISO-8601). Títulos de vulnerabilidades no idioma original do fabricante."""


def _query_params(model) -> list[dict]:
    if model is None:
        return []
    sch = model.model_json_schema(ref_template=REF)
    req = set(sch.get("required", []))
    out = []
    for name, prop in sch.get("properties", {}).items():
        desc = prop.pop("description", "")
        prop.pop("title", None)
        out.append({"name": name, "in": "query", "required": name in req, "description": desc, "schema": prop})
    return out


def _problem(desc: str) -> dict:
    return {"description": desc, "content": {"application/problem+json": {"schema": {"$ref": REF.format(model="Problem")}}}}


def _path_params(r) -> list[dict]:
    out = []
    for p in r.path_params:
        sch = {"type": "string", "format": "email"} if r.path_types.get(p) == "string" else {"type": "integer", "minimum": 1}
        out.append({"name": p, "in": "path", "required": True, "schema": sch})
    return out


def _read_op(r) -> dict:
    ok_schema = {"$ref": REF.format(model=r.response.__name__)} if r.response else {"type": "object"}
    if r.many:
        ok_schema = {"type": "object", "required": ["data", "next_cursor"], "properties": {
            "data": {"type": "array", "items": ok_schema},
            "next_cursor": {"type": ["string", "null"], "description": "Cursor da próxima página; null na última."}}}
    responses = {"200": {"description": "Sucesso", "content": {"application/json": {"schema": ok_schema}}}}
    if r.auth:
        responses["304"] = {"description": "Não modificado (If-None-Match igual ao ETag)"}
        for code, desc in ERRORS.items():
            if code == 400 and not r.query:
                continue
            if code == 404 and not r.path_params:
                continue
            responses[str(code)] = _problem(desc)
    return {"parameters": _path_params(r) + _query_params(r.query), "responses": responses}


def _write_op(r) -> dict:
    params = _path_params(r) + [{"name": "dry_run", "in": "query", "required": False, "schema": {"type": "boolean", "default": False},
                                 "description": "true = só valida e mostra o resultado; nada é gravado nem enviado."}]
    if r.idempotent:
        params.append({"name": "Idempotency-Key", "in": "header", "required": False, "schema": {"type": "string", "maxLength": 200},
                       "description": "Identificador único da operação: repetir com a mesma chave devolve o mesmo resultado (24 h)."})
    if r.if_match:
        params.append({"name": "If-Match", "in": "header", "required": False, "schema": {"type": "string"},
                       "description": "ETag lido no GET do recurso; se mudou, a resposta é 412 e nada é alterado."})
    if r.status == 204 or r.response is None:
        responses = {str(r.status if r.status != 200 else 204): {"description": "Feito (sem corpo)"}}
    else:
        responses = {str(r.status): {"description": "Criado" if r.status == 201 else ("Aceito" if r.status == 202 else "Alterado"),
                                     "content": {"application/json": {"schema": {"$ref": REF.format(model=r.response.__name__)}}}}}
    for code, desc in WRITE_ERRORS.items():
        if code == 404 and not r.path_params:
            continue
        if code == 412 and not r.if_match:
            continue
        if code == 415 and r.body is None:
            continue
        responses[str(code)] = _problem(desc)
    op = {"parameters": params, "responses": responses}
    if r.body is not None:
        op["requestBody"] = {"required": True, "content": {"application/json": {"schema": {"$ref": REF.format(model=r.body.__name__)}}}}
    return op


def build_spec() -> dict:
    models = [(Problem, "serialization")]
    for r in ROUTES:
        if r.response is not None:
            models.append((r.response, "serialization"))
        if r.body is not None:
            models.append((r.body, "validation"))
    models = sorted(set(models), key=lambda m: (m[0].__name__, m[1]))
    _, top = models_json_schema(models, ref_template=REF)
    schemas = top.get("$defs", {})
    paths: dict = {}
    for r in sorted(ROUTES, key=lambda x: (x.path, x.method)):
        op = {"operationId": r.endpoint, "summary": r.summary, "description": r.description, "tags": list(r.tags) or ["Geral"],
              **(_read_op(r) if r.method == "GET" else _write_op(r))}
        if r.permission:
            op["x-permission"] = r.permission
            op["description"] = (op["description"] + f"\n\n**Permissão exigida:** `{r.permission}` — {PERMISSIONS[r.permission]}.").strip()
        if not r.auth:
            op["security"] = []
        paths.setdefault(r.path, {})[r.method.lower()] = op
    base = current_app.config.get("APP_BASE_URL", "").rstrip("/")
    return {
        "openapi": "3.1.0",
        "info": {"title": "Trust Parser API", "version": "1.1.0", "description": DESCRIPTION,
                 "contact": {"name": "Suporte Trust Parser (Jarbas)", "email": SUPPORT_EMAIL}},
        "servers": [{"url": f"{base}/api/v1"}],
        "security": [{"bearerAuth": []}],
        "tags": [{"name": t} for t in sorted({t for r in ROUTES for t in (r.tags or ("Geral",))})],
        "paths": paths,
        "components": {"schemas": schemas,
                       "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "tpk_live_<prefixo>_<segredo>",
                                                          "description": "Chave criada em Administração → API."}}},
    }
