"""Chaves da API (v1): geração, verificação, revogação, rotação, uso, avisos de vencimento e política de escrita.

O segredo é exibido uma única vez. No banco ficam só o prefixo público e o HMAC-SHA256 do segredo com o pepper do servidor;
um vazamento do banco não permite usar as chaves.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import secrets
from dataclasses import dataclass
from datetime import timedelta

from flask import current_app
from sqlalchemy import select, text

from ..db import Session, utcnow
from ..models import ApiKey, Tenant

PREFIX = "tpk_live_"
TOKEN_RE = re.compile(r"^tpk_live_([0-9a-f]{8})_([A-Za-z0-9_-]{40,64})$")
READ_PERMISSIONS = {
    "tenants:ler": "Tenants (clientes)",
    "fontes:ler": "Fontes, IPs liberados e conectores (sem segredos)",
    "destinos:ler": "Destinos de saída (sem segredos)",
    "parsers:ler": "Parsers de entrada e formatos de saída (versões e testes)",
    "eventos:ler": "Eventos do buffer, não reconhecidos e downloads — dados de log dos clientes",
    "uploads:ler": "Uploads e resultados",
    "pessoas:ler": "Pessoas dos clientes — dados pessoais",
    "indicadores:ler": "Indicadores do painel (EPS, cobertura, entregas)",
    "estudio:ler": "Pedidos do Estúdio IA",
}
WRITE_PERMISSIONS = {
    "tenants:gerenciar": "Gerenciar tenants (criar, editar, suspender)",
    "fontes:gerenciar": "Gerenciar fontes, IPs liberados no firewall e conectores de API (inclui segredos)",
    "destinos:gerenciar": "Gerenciar destinos de saída (inclui credenciais)",
    "parsers:gerenciar": "Publicar, reverter e desativar parsers e formatos",
    "uploads:enviar": "Enviar arquivos para parsing",
    "pessoas:gerenciar": "Gerenciar pessoas dos tenants — dados pessoais e convites",
    "estudio:pedir": "Pedir novos parsers/formatos ao Estúdio IA",
}
EVA_PERMISSIONS = {
    "eva:ler": "EVA — situação, conversas e lista de autorizados",
    "eva:conversar": "Conversar com a EVA (pedidos como por e-mail)",
    "eva:gerenciar": "EVA — lista de autorizados (membros) e situação das conversas",
}
PERMISSIONS = {**READ_PERMISSIONS, **EVA_PERMISSIONS, **WRITE_PERMISSIONS}
# quem gerencia também lê a mesma área
IMPLIES = {"tenants:gerenciar": "tenants:ler", "fontes:gerenciar": "fontes:ler", "destinos:gerenciar": "destinos:ler",
           "parsers:gerenciar": "parsers:ler", "uploads:enviar": "uploads:ler", "pessoas:gerenciar": "pessoas:ler",
           "estudio:pedir": "estudio:ler", "eva:gerenciar": "eva:ler"}
# permissões que alteram dados ou acionam a EVA: exigem IPs de origem e MFA de quem cria
WRITE_LIKE = set(WRITE_PERMISSIONS) | {"eva:conversar", "eva:gerenciar"}
# chave de tenant não pode administrar o que é global (parsers, Estúdio, tenants, EVA)
GLOBAL_ONLY = {"tenants:gerenciar", "parsers:gerenciar", "estudio:pedir"} | set(EVA_PERMISSIONS)
WRITE_RATE_PER_MIN = 10
DEFAULT_DAYS, MAX_DAYS = 365, 730
DEFAULT_RATE = 600
ROTATION_GRACE_DAYS = 7


class ApiKeyError(ValueError):
    pass


def _pepper() -> bytes:
    p = current_app.config.get("API_KEY_PEPPER") or ""
    if not p:  # derivado do SECRET_KEY: estável enquanto o SECRET_KEY não mudar
        p = hmac.new(current_app.config["SECRET_KEY"].encode(), b"trustparser-api-key-pepper", hashlib.sha256).hexdigest()
    return p.encode()


def _hmac(secret: str) -> str:
    return hmac.new(_pepper(), secret.encode(), hashlib.sha256).hexdigest()


def _norm_ips(values) -> list[str]:
    out = []
    for v in values or []:
        v = (v or "").strip()
        if not v:
            continue
        try:
            out.append(str(ipaddress.ip_network(v, strict=False)))
        except ValueError as e:
            raise ApiKeyError(f"IP ou faixa inválida: {v}") from e
    return sorted(set(out))


def _norm_perms(values) -> list[str]:
    perms = {p for p in (values or []) if p}
    perms |= {IMPLIES[p] for p in perms if p in IMPLIES}
    perms = sorted(perms)
    bad = [p for p in perms if p not in PERMISSIONS]
    if bad:
        raise ApiKeyError(f"permissão desconhecida: {', '.join(bad)}")
    if not perms:
        raise ApiKeyError("escolha ao menos uma permissão")
    return perms


def create(*, name: str, owner_email: str = "", tenant_id: int | None = None, permissions=(), allowed_ips=(),
           rate_per_min: int = DEFAULT_RATE, days: int = DEFAULT_DAYS, created_by: str = "") -> tuple[ApiKey, str]:
    """Cria a chave e devolve (registro, segredo completo). O segredo não é recuperável depois."""
    name = (name or "").strip()[:120]
    if not name:
        raise ApiKeyError("informe o nome do sistema que vai usar a chave")
    if tenant_id is not None and Session.get(Tenant, tenant_id) is None:
        raise ApiKeyError("tenant não encontrado")
    try:
        days, rate = int(days), int(rate_per_min)
    except (TypeError, ValueError) as e:
        raise ApiKeyError("validade e limite devem ser números") from e
    if not 1 <= days <= MAX_DAYS:
        raise ApiKeyError(f"validade deve ficar entre 1 e {MAX_DAYS} dias")
    if not 1 <= rate <= 100000:
        raise ApiKeyError("limite por minuto deve ficar entre 1 e 100000")
    perms, ips = _norm_perms(permissions), _norm_ips(allowed_ips)
    check_policy(perms, tenant_id, ips, owner_email)
    for _ in range(5):
        prefix = secrets.token_hex(4)
        if Session.execute(select(ApiKey.id).where(ApiKey.prefix == prefix)).first() is None:
            break
    secret = secrets.token_urlsafe(32)  # 256 bits
    k = ApiKey(prefix=prefix, secret_hmac=_hmac(secret), name=name, owner_email=(owner_email or "").strip().lower()[:254],
               tenant_id=tenant_id, permissions=perms, allowed_ips=ips, rate_per_min=rate,
               expires_at=utcnow() + timedelta(days=days), created_by=created_by)
    Session.add(k)
    Session.flush()
    return k, f"{PREFIX}{prefix}_{secret}"


def is_write(perms) -> bool:
    return bool(set(perms or []) & WRITE_LIKE)


def eva_role(email: str) -> str | None:
    """Papel ativo na lista de autorizados da EVA ('owner' | 'member') ou None."""
    from ..models import EvaWhitelist
    email = (email or "").strip().lower()
    if not email:
        return None
    w = Session.get(EvaWhitelist, email)
    return w.role if w is not None and w.active else None


def check_policy(perms: list[str], tenant_id: int | None, ips: list[str], owner_email: str = ""):
    """Regras das chaves com escrita e da EVA (só quem está na lista de autorizados)."""
    scoped = sorted(set(perms) & GLOBAL_ONLY)
    if tenant_id is not None and scoped:
        raise ApiKeyError(f"chave de um tenant não pode ter {', '.join(scoped)} (só chave global)")
    if is_write(perms) and not ips:
        raise ApiKeyError("chave com permissão de escrita exige a lista de IPs de origem")
    role = eva_role(owner_email)
    if "eva:gerenciar" in perms and role != "owner":
        raise ApiKeyError("eva:gerenciar só para chave cujo responsável seja dono na lista de autorizados da EVA")
    if "eva:conversar" in perms and role is None:
        raise ApiKeyError("eva:conversar só para chave cujo responsável esteja ativo na lista de autorizados da EVA")


@dataclass
class Verification:
    key: ApiKey | None
    reason: str = ""  # vazio = válida
    status: int = 200


def verify(token: str, ip: str = "") -> Verification:
    """Verifica o token (formato, HMAC em tempo constante, revogação, validade, IP). Não checa permissão nem escopo."""
    m = TOKEN_RE.match((token or "").strip())
    if not m:
        return Verification(None, "chave ausente ou malformada", 401)
    k = Session.execute(select(ApiKey).where(ApiKey.prefix == m.group(1))).scalar_one_or_none()
    expected = k.secret_hmac if k is not None else "0" * 64
    if not hmac.compare_digest(expected, _hmac(m.group(2))) or k is None:
        return Verification(None, "chave inválida", 401)
    if k.revoked_at is not None:
        return Verification(k, "chave revogada", 401)
    if k.expires_at <= utcnow():
        return Verification(k, "chave expirada", 401)
    if k.allowed_ips and not ip_allowed(ip, k.allowed_ips):
        return Verification(k, "IP de origem não autorizado para esta chave", 403)
    return Verification(k)


def ip_allowed(ip: str, allowed: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(n, strict=False) for n in allowed)


SYSTEM_EXPIRY_YEARS = 75  # chave de sistema: validade efetivamente permanente (renovada só pela rotação de emergência)
EVA_LABEL = "EVA · suporte e manutenção por e-mail (leitura de dados)"


def revoke(k: ApiKey, by: str):
    if k.protected:
        raise ApiKeyError(f"a chave “{k.system_label or k.name}” é protegida pelo sistema e não pode ser revogada")
    if k.revoked_at is None:
        k.revoked_at, k.revoked_by = utcnow(), by


def rotate(k: ApiKey, by: str) -> tuple[ApiKey, str]:
    """Nova chave com os mesmos atributos; a antiga passa a vencer em ROTATION_GRACE_DAYS (ou antes, se já venceria)."""
    if k.protected:
        raise ApiKeyError(f"a chave “{k.system_label or k.name}” é protegida; a rotação só é feita no servidor, em emergência")
    if not k.active:
        raise ApiKeyError("só é possível rotacionar uma chave ativa")
    days = max(1, (k.expires_at - k.created_at).days)
    new, secret = create(name=k.name, owner_email=k.owner_email, tenant_id=k.tenant_id, permissions=k.permissions,
                         allowed_ips=k.allowed_ips, rate_per_min=k.rate_per_min, days=min(days, MAX_DAYS), created_by=by)
    k.expires_at = min(k.expires_at, utcnow() + timedelta(days=ROTATION_GRACE_DAYS))
    k.replaced_by = new.id
    return new, secret


def record_use(k: ApiKey, ip: str, route: str, status: int):
    """Uso agregado por dia/rota/status e último uso (gravado no máximo 1x por minuto por chave)."""
    now = utcnow()
    day = now.replace(hour=0, minute=0, second=0, microsecond=0)
    Session.execute(text("""insert into api_usage_daily (key_id, day, route, status, count) values (:k, :d, :r, :s, 1)
                            on conflict (key_id, day, route, status) do update set count = api_usage_daily.count + 1"""),
                    {"k": k.id, "d": day, "r": (route or "?")[:120], "s": int(status)})
    if k.last_used_at is None or (now - k.last_used_at) > timedelta(seconds=60) or k.last_used_ip != (ip or "")[:64]:
        k.last_used_at, k.last_used_ip = now, (ip or "")[:64]


def usage_30d() -> dict[int, dict]:
    """Uso por chave nos últimos 30 dias. Alterações = chamadas de escrita bem-sucedidas (rota gravada com o método)."""
    rows = Session.execute(text("""select key_id, sum(count) total, sum(count) filter (where status >= 400) erros,
                                          sum(count) filter (where status < 400 and route ~ '^(POST|PATCH|DELETE) ') alteracoes
                                   from api_usage_daily where day > now() - interval '30 days' group by key_id""")).all()
    return {r.key_id: {"total": int(r.total or 0), "erros": int(r.erros or 0), "alteracoes": int(r.alteracoes or 0)} for r in rows}


def notify_expiring():
    """Avisa o responsável da chave e a equipe de alertas 30 e 7 dias antes do vencimento (1 aviso por marco)."""
    from . import emails
    now = utcnow()
    sent = 0
    for k in Session.execute(select(ApiKey).where(ApiKey.revoked_at.is_(None), ApiKey.expires_at > now,
                                                  ApiKey.expires_at <= now + timedelta(days=30),
                                                  ApiKey.replaced_by.is_(None))).scalars():
        days_left = (k.expires_at - now).days
        mark = 7 if days_left <= 7 else 30
        to = list(dict.fromkeys([e for e in [k.owner_email] if e] + emails.admin_emails()))
        sent += emails.send_system(to, f"[Trust Parser] Chave de API vence em {days_left} dia(s) · {k.name}", "email/api_key_expiring.html",
                                   f"apikey:{k.id}:{mark}", key=k, days_left=days_left, base_url=emails.base_url())
    Session.commit()
    return sent


def ensure_eva_key(rotate: bool = False) -> tuple[ApiKey, str | None]:
    """Chave protegida da EVA: leitura de todos os dados, escopo global, sem vencimento prático, sem revogação.
    Cria se não existir (devolve o segredo). Com rotate=True (emergência no servidor), troca o segredo da mesma chave."""
    k = Session.execute(select(ApiKey).where(ApiKey.protected.is_(True), ApiKey.system_label == EVA_LABEL)).scalar_one_or_none()
    if k is not None and not rotate:
        return k, None
    secret = secrets.token_urlsafe(32)
    if k is None:
        k, secret = create(name="EVA (agente de suporte)", owner_email="eva-trustparser@trustcontrol.nuvem.tec.br",
                           permissions=list(READ_PERMISSIONS), rate_per_min=600, days=1, created_by="sistema")
        k.expires_at = utcnow() + timedelta(days=365 * SYSTEM_EXPIRY_YEARS)
        k.protected, k.system_label = True, EVA_LABEL
        Session.flush()
        return k, secret
    Session.execute(text("set local trustparser.allow_protected_key = 'on'"))
    k.secret_hmac = _hmac(secret)
    k.expires_at = utcnow() + timedelta(days=365 * SYSTEM_EXPIRY_YEARS)
    Session.flush()
    return k, f"{PREFIX}{k.prefix}_{secret}"
