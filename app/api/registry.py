"""Registro das rotas da API: cada rota declara permissão, parâmetros e esquema de resposta.

Do mesmo registro saem a validação dos parâmetros, a serialização (Pydantic), o ETag e a especificação OpenAPI 3.1 —
a documentação nunca diverge da implementação.

Escrita (api_write): autenticação → permissão → If-Match (412) → corpo JSON validado → Idempotency-Key (POST) →
limite de alterações da chave → serviço (a mesma regra da tela) → simulação (dry_run: desfaz tudo) ou auditoria +
commit + envios pós-commit (convites).
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Callable

from flask import Blueprint, Response, g, request
from limits import RateLimitItemPerMinute
from pydantic import BaseModel, ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from .auth import authenticate, require
from .errors import ApiError

bp = Blueprint("api", __name__, url_prefix="/api/v1")


@dataclass
class RouteSpec:
    path: str
    endpoint: str
    summary: str
    description: str
    permission: str | None
    query: type[BaseModel] | None
    response: type[BaseModel] | None
    many: bool
    tags: tuple
    auth: bool
    path_params: list = field(default_factory=list)
    method: str = "GET"
    body: type[BaseModel] | None = None
    status: int = 200
    if_match: bool = False
    idempotent: bool = False
    path_types: dict = field(default_factory=dict)
    errors: tuple = ()


ROUTES: list[RouteSpec] = []


class Page:
    """Resultado paginado devolvido pelas rotas de lista."""
    def __init__(self, data, next_cursor=None):
        self.data, self.next_cursor = data, next_cursor


def _dump(obj):
    return obj.model_dump(mode="json") if isinstance(obj, BaseModel) else obj


def _encode(payload) -> str:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str)


def etag_of(payload) -> str:
    return hashlib.sha256(_encode(payload).encode()).hexdigest()[:32]


def json_response(payload, status=200, etag=True) -> Response:
    body = _encode(payload)
    r = Response(body, status=status, mimetype="application/json")
    if etag and status in (200, 201):
        tag = hashlib.sha256(body.encode()).hexdigest()[:32]
        if request.method == "GET" and request.if_none_match and request.if_none_match.contains(tag):
            r = Response(status=304)
        r.set_etag(tag)
    return r


def _parse_query(model: type[BaseModel]):
    raw = {}
    for k in request.args:
        vals = request.args.getlist(k)
        raw[k] = vals if len(vals) > 1 else vals[0]
    try:
        return model.model_validate(raw)
    except ValidationError as e:
        errs = [{"param": ".".join(str(x) for x in err["loc"]) or "?", "problem": err["msg"]} for err in e.errors()]
        raise ApiError(400, "Parâmetros inválidos.", errors=errs) from e


def _rule(path: str, path_types: dict) -> str:
    return re.sub(r"\{(\w+)\}", lambda m: f"<{m.group(1)}>" if path_types.get(m.group(1)) == "string" else f"<int:{m.group(1)}>", path)


def api_get(path: str, *, summary: str, response: type[BaseModel] | None = None, permission: str | None = None,
            query: type[BaseModel] | None = None, many: bool = False, tags=(), description: str = "", auth: bool = True,
            path_types: dict | None = None):
    path_types = path_types or {}

    def deco(fn):
        params = re.findall(r"\{(\w+)\}", path)
        rule = _rule(path, path_types)

        def view(**kw):
            if auth:
                authenticate()
                require(permission)
            args = [_parse_query(query)] if query else []
            result = fn(*args, **kw)
            if isinstance(result, Response):
                return result
            if many:
                payload = {"data": [_dump(x) for x in result.data], "next_cursor": result.next_cursor}
            else:
                payload = _dump(result)
            return json_response(payload)

        view.__name__ = fn.__name__
        bp.add_url_rule(rule, endpoint=fn.__name__, view_func=view, methods=["GET"])
        ROUTES.append(RouteSpec(path=path, endpoint=fn.__name__, summary=summary, description=description or (fn.__doc__ or "").strip(),
                                permission=permission, query=query, response=response, many=many, tags=tuple(tags), auth=auth,
                                path_params=params, path_types=path_types))
        return fn
    return deco


# ------------------------------------------------------------------------------------------------ escrita
@dataclass
class Written:
    """Resultado de uma rota de escrita: o Outcome do serviço e como montar a representação final (a mesma do GET)."""
    outcome: object
    build: Callable | None = None
    status: int | None = None
    location: str | None = None


IDEM_RE = re.compile(r"^[\x21-\x7e]{1,200}$")
IDEM_TTL = timedelta(hours=24)


def _flag(v) -> bool:
    return str(v or "").strip().lower() in ("1", "true", "sim", "yes")


def _parse_body(model: type[BaseModel]):
    raw = request.get_data(cache=True)
    if not raw.strip():
        data = {}
    else:
        if request.mimetype != "application/json":
            raise ApiError(415, "Envie o corpo em JSON (Content-Type: application/json).")
        try:
            data = json.loads(raw)
        except ValueError as e:
            raise ApiError(400, "JSON inválido no corpo da requisição.") from e
    try:
        return model.model_validate(data)
    except ValidationError as e:
        errs = [{"param": ".".join(str(x) for x in err["loc"]) or "(corpo)", "problem": err["msg"]} for err in e.errors()]
        raise ApiError(400, "Corpo da requisição inválido.", errors=errs) from e


def actor_label(k) -> str:
    return f"api:tpk_live_{k.prefix}… ({k.owner_email or k.name})"[:254]


def write_limit():
    """Alterações por minuto por chave (além do limite geral de requisições). Simulações não contam."""
    from ..services.api_keys import WRITE_RATE_PER_MIN
    from ..web.limiter import limiter
    k = g.api_key
    item = RateLimitItemPerMinute(WRITE_RATE_PER_MIN)
    if not limiter.limiter.hit(item, "api-write", str(k.id)):
        stats = limiter.limiter.get_window_stats(item, "api-write", str(k.id))
        wait = str(max(1, int(stats.reset_time - time.time())))
        raise ApiError(429, f"Limite de {WRITE_RATE_PER_MIN} alterações por minuto desta chave excedido.", {"Retry-After": wait})


def _replay(row) -> Response:
    r = Response(row.response or "", status=row.status, mimetype="application/json" if row.response else None)
    if row.location:
        r.headers["Location"] = row.location
    if row.response and row.status in (200, 201):
        r.set_etag(hashlib.sha256(row.response.encode()).hexdigest()[:32])
    r.headers["Idempotent-Replayed"] = "true"
    return r


def api_write(method: str, path: str, *, summary: str, permission: str, body: type[BaseModel] | None = None,
              response: type[BaseModel] | None = None, status: int = 200, current: Callable | None = None, tags=(),
              description: str = "", path_types: dict | None = None, counts: bool = True, errors: tuple = (),
              max_body: int | None = None):
    """Rota de escrita. `current(**path)` devolve a representação atual (para If-Match/412); a função da rota recebe
    (corpo, **path) e devolve Written."""
    path_types = path_types or {}

    def deco(fn):
        params = re.findall(r"\{(\w+)\}", path)
        rule = _rule(path, path_types)

        def view(**kw):
            from ..db import Session
            from ..models import ApiIdempotency
            from ..security import client_ip
            from ..services import audit
            from ..services.changes import ServiceError
            from ..db import utcnow
            if max_body:  # conversa com o Jarbas aceita imagens; o resto da API segue com o limite padrão
                request.max_content_length = max_body
            authenticate()
            require(permission)
            extra = sorted(set(request.args) - {"dry_run"})
            if extra:
                raise ApiError(400, "Parâmetros inválidos.", errors=[{"param": x, "problem": "parâmetro desconhecido"} for x in extra])
            dry = _flag(request.args.get("dry_run"))
            g.dry_run = dry
            k = g.api_key
            if current is not None and request.if_match:
                tag = etag_of(_dump(current(**kw)))
                if not (request.if_match.star_tag or request.if_match.contains(tag)):
                    raise ApiError(412, "O recurso foi alterado desde a sua leitura (ETag diferente). Leia de novo e repita.",
                                   {"ETag": f'"{tag}"'})
            data = _parse_body(body) if body is not None else None
            idem = request.headers.get("Idempotency-Key") if method == "POST" else None
            body_sha = ""
            if idem is not None:
                if not IDEM_RE.match(idem):
                    raise ApiError(400, "Idempotency-Key inválida (1 a 200 caracteres visíveis).")
                body_sha = hashlib.sha256(request.method.encode() + request.path.encode() + b"\n" + request.get_data(cache=True)).hexdigest()
                row = Session.execute(select(ApiIdempotency).where(ApiIdempotency.key_id == k.id, ApiIdempotency.idem_key == idem,
                                                                   ApiIdempotency.created_at > utcnow() - IDEM_TTL)).scalar_one_or_none()
                if row is not None:
                    if row.body_sha != body_sha:
                        raise ApiError(422, "Esta Idempotency-Key já foi usada com outra requisição. Use uma chave nova.")
                    return _replay(row)
            if counts and not dry:
                write_limit()
            try:
                res = fn(data, **kw) if body is not None else fn(**kw)
                Session.flush()
            except ServiceError as e:
                Session.rollback()
                raise ApiError(e.status, str(e)) from e
            except IntegrityError as e:
                Session.rollback()
                raise ApiError(409, "Conflito com dados existentes (registro duplicado).") from e
            if isinstance(res, Response):
                return res
            Session.expire_all()
            payload = _dump(res.build()) if res.build is not None else None
            code = res.status or status
            out = res.outcome
            if dry:
                Session.rollback()
            else:
                label, ip = actor_label(k), client_ip()
                for action, target, details in (out.audit if out is not None else []):
                    audit.log(action, target, actor_label=label, tenant_id=out.tenant_id,
                              details={**details, "via": "api", "request_id": g.request_id}, ip=ip)
                if idem is not None:
                    Session.add(ApiIdempotency(key_id=k.id, idem_key=idem, method=method, path=request.path[:300], body_sha=body_sha,
                                               status=code, response=_encode(payload) if payload is not None else "",
                                               location=(res.location or "")[:300]))
                try:
                    Session.commit()
                except IntegrityError as e:  # mesma Idempotency-Key em paralelo: a outra chamada venceu
                    Session.rollback()
                    raise ApiError(409, "Requisição repetida em andamento com a mesma Idempotency-Key.") from e
                if out is not None and (out.invites or out.after_commit):
                    from ..services import emails
                    for u, token in out.invites:
                        emails.send_magic_link(u, token, "invite")
                    for cb in out.after_commit:
                        cb()
                    Session.commit()
            r = Response(status=204) if payload is None else json_response(payload, code)
            if res.location:
                r.headers["Location"] = res.location
            if dry:
                r.headers["X-Dry-Run"] = "true"
            if out is not None and getattr(out, "warning", ""):
                r.headers["X-Warning"] = out.warning.encode("ascii", "xmlcharrefreplace").decode()
            return r

        view.__name__ = fn.__name__
        bp.add_url_rule(rule, endpoint=fn.__name__, view_func=view, methods=[method])
        ROUTES.append(RouteSpec(path=path, endpoint=fn.__name__, summary=summary, description=description or (fn.__doc__ or "").strip(),
                                permission=permission, query=None, response=response, many=False, tags=tuple(tags), auth=True,
                                path_params=params, method=method, body=body, status=status, if_match=current is not None,
                                idempotent=method == "POST", path_types=path_types, errors=tuple(errors)))
        return fn
    return deco
