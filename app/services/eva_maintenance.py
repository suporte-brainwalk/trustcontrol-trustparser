"""Manutenção controlada pela EVA — o que um administrador faz pelo painel do Trust Parser: tenants, fontes, IPs liberados
para o syslog, destinos, pessoas dos tenants e pedidos ao Estúdio IA.

Ponto ÚNICO de entrada da EVA nos serviços do Trust Parser (a tela e a API chamam os mesmos serviços, então a regra é uma só).
O orquestrador (tools/eva) chama este módulo dentro do container da aplicação:

    docker exec -i parser-app python -m app.services.eva_maintenance --modo testar|aplicar|desfazer --solicitante <e-mail>
    stdin:  {"operacoes": [...]}  (testar/aplicar)   ou   {"resultados": [...]}  (desfazer: o que "aplicar" devolveu)
    stdout: última linha = {"resultados": [{tipo, ok, erro, resumo, aviso, ids, antes}, ...]}  ou  {"erro": "..."}

Regras (determinísticas, aplicadas aqui e não pela IA):
- tudo ou nada: "testar" simula tudo e desfaz; "aplicar" só grava se TODAS as operações passarem;
- nunca exclui tenant, fonte, destino ou IP (só inclui, edita, ativa/desativa, suspende); remover só pessoa de um tenant;
- nunca lê nem grava credenciais: operação com campo/valor com cara de segredo é recusada inteira;
- IP liberado: só IPv4 único ou faixa até /24 (mais estreito que o limite da tela) e nunca "confirmar faixa larga";
- parser/formato novo ou ajuste: só PEDIDO ao Estúdio IA (fica em rascunho; publicar é decisão de um administrador);
- administradores, configurações, chaves de API, MFA e firewall do servidor ficam fora;
- cada operação grava um retrato "antes" para poder ser desfeita e fica na auditoria (autor "EVA (agente por e-mail)").

Interface esperada dos serviços (o que não existir ainda vira erro claro "ainda não disponível", nunca uma exceção solta):
  tenants.create_tenant(*, name, segment="", internal=False) -> Outcome(obj=Tenant)
  tenants.update_tenant(t, **{name, segment, internal, status}) -> Outcome
  sources.create_source(tenant, *, name, transport, parser_id, match_hostname, unparsed_policy, note, connector,
                        connector_config, interval_s, silence_alert_minutes, by[, defer_secrets]) -> Outcome(obj=Source)
  sources.update_source(s, *, by, **campos) -> Outcome
  sources.add_allowed_ip(tenant, *, cidr, protocols, description, source_id, expires_at, by) -> Outcome(obj=AllowedIP)
  sources.update_allowed_ip(a, *, active) -> Outcome
  destinations.create_destination(tenant, *, name, kind, format, config, filters, include_unparsed, active, by[, defer_secrets])
  destinations.update_destination(d, *, by, **campos) -> Outcome ;  destinations.test_destination(d) -> (ok, msg)
  studio.request_job(*, kind, title, vendor, product, request, samples, docs_urls, parser_id, by) -> Outcome(obj=StudioJob)
      (enquanto app/services/studio.py não existir: app.engine.studio.create_job, mesma assinatura com by=)
  studio.cancel_job(job, by) -> Outcome   (opcional; sem ele, o desfazer cancela direto se o pedido ainda está na fila)
  people.add(t, *, name, email, access) / people.remove(t, email) / people.resend_invite(t, email) -> Outcome
"""
from __future__ import annotations

import inspect
import ipaddress
import json
import re
from datetime import datetime, timezone

from sqlalchemy import func, select

from ..db import Session
from ..models import AllowedIP, Destination, Parser, Source, StudioJob, Tenant, User
from . import audit
from .changes import Outcome, ServiceError

ACTOR = "EVA (agente por e-mail)"
MAX_OPS = 20
EVA_MIN_PREFIX = 24  # a EVA só libera IP único ou faixa até /24 (a tela aceita até /16; mais largo exige um administrador)
OPS = {"tenant_adicionar", "tenant_editar", "tenant_suspender", "tenant_reativar",
       "fonte_adicionar", "fonte_editar", "fonte_ativar", "fonte_desativar",
       "ip_adicionar", "ip_desativar", "ip_reativar",
       "destino_adicionar", "destino_editar", "destino_ativar", "destino_desativar", "destino_testar",
       "estudio_pedir",
       "pessoa_convidar", "pessoa_reenviar_convite", "pessoa_remover"}
SECRET_KEY_RX = re.compile(r"(?i)(secret|segredo|senha|password|passwd|pwd|token|api_?key|apikey|credential|credencia|private|"
                           r"service_account|auth_value|authorization|bearer|cookie|client_secret|certificado_cliente|pfx|p12)")
SECRET_VALUE_RX = re.compile(r"(?i)(-----BEGIN [A-Z ]*PRIVATE KEY|\"private_key\"\s*:|sk-or-v1-|sk-ant-|tpk_live_|ghp_[A-Za-z0-9]{20,}|"
                             r"xox[bp]-|AKIA[0-9A-Z]{16}|eyJhbGciOi|bearer\s+[A-Za-z0-9._-]{16,})")
PERFIS = ("manager", "reader")


class MaintError(ValueError):
    pass


class NotAvailable(MaintError):
    """Serviço ainda não implementado no Trust Parser (a EVA explica e nada é alterado)."""


# ------------------------------------------------------------------------------------------------ validações puras (testadas)
def secret_fields(obj, path: str = "") -> list[str]:
    """Caminhos de campos com nome ou valor de segredo em qualquer profundidade da operação."""
    hits: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{path}.{k}" if path else str(k)
            if SECRET_KEY_RX.search(str(k)) and v not in (None, "", [], {}):
                hits.append(p)
            hits += secret_fields(v, p)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            hits += secret_fields(v, f"{path}[{i}]")
    elif isinstance(obj, str) and SECRET_VALUE_RX.search(obj):
        hits.append(path or "(valor)")
    return hits


def check_cidr(v: str) -> str:
    """IPv4 único ou faixa até /24; nunca 0.0.0.0/0, privado, reservado ou multicast (o syslog chega pela internet)."""
    v = (v or "").strip()
    try:
        net = ipaddress.ip_network(v, strict=False)
    except ValueError:
        raise MaintError(f"IP ou faixa inválida: {v or '(vazio)'}") from None
    if net.version != 4:
        raise MaintError("o syslog recebe só IPv4")
    if net.prefixlen < EVA_MIN_PREFIX:
        raise MaintError(f"faixa {net} é larga demais para a EVA liberar (máximo /{EVA_MIN_PREFIX}); um administrador pode avaliar pela tela")
    if net.is_private or net.is_loopback or net.is_multicast or net.is_reserved or net.is_link_local or net.is_unspecified:
        raise MaintError(f"{net} não é um endereço público de origem")
    return str(net)


def parse_date_br(v) -> datetime | None:
    v = (v or "").strip() if isinstance(v, str) else ""
    if not v:
        return None
    try:
        d = datetime.strptime(v, "%d/%m/%Y")
    except ValueError:
        raise MaintError(f"data inválida (use DD/MM/AAAA): {v}") from None
    d = d.replace(hour=23, minute=59, tzinfo=timezone.utc)
    if d < datetime.now(timezone.utc):
        raise MaintError("a validade precisa ser uma data futura")
    return d


def validate_op(op) -> str:
    """Checagens que valem antes de tocar no banco. Devolve o tipo."""
    if not isinstance(op, dict):
        raise MaintError("operação inválida")
    tipo = op.get("tipo")
    if tipo not in OPS:
        raise MaintError(f"operação não permitida: {tipo}")
    hits = secret_fields({k: v for k, v in op.items() if k != "tipo"})
    if hits:
        raise MaintError("a EVA não lê nem grava credenciais (campos: " + ", ".join(hits[:5]) +
                         "); um administrador cadastra a credencial na tela, com o botão Testar")
    return tipo


# ------------------------------------------------------------------------------------------------ auxiliares
def _txt(v, n=160) -> str:
    return re.sub(r"\s+", " ", str(v or "")).strip()[:n]


def _supports(fn, param: str) -> bool:
    try:
        return param in inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False


def _call(fn, *args, **kw):
    """Chama o serviço só com os parâmetros que ele aceita (a interface dos serviços ainda está mudando)."""
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return fn(*args, **kw)
    if any(p.kind == p.VAR_KEYWORD for p in params.values()):
        return fn(*args, **kw)
    return fn(*args, **{k: v for k, v in kw.items() if k in params})


def _svc(module: str, name: str):
    """Função de serviço ou NotAvailable (TODO do time: implementar em app/services/<module>.py)."""
    import importlib
    try:
        mod = importlib.import_module(f"app.services.{module}")
    except ImportError:
        mod = None
    fn = getattr(mod, name, None) if mod else None
    if fn is None and module == "studio" and name == "request_job":
        from ..engine import studio as engine_studio  # enquanto app/services/studio.py não existe
        create = getattr(engine_studio, "create_job", None)
        if create is not None:
            def fn(**kw):
                job = create(**kw)
                return Outcome(message=f"Pedido nº {job.id} enviado ao Estúdio IA.", obj=job,
                               audit=[("studio.requested", job.title, {"kind": job.kind, "job": job.id})])
    if fn is None:
        raise NotAvailable(f"esta operação ainda não está disponível no Trust Parser ({module}.{name})")
    return fn


def _tenant(name) -> Tenant:
    n = _txt(name)
    t = Session.execute(select(Tenant).where(func.lower(Tenant.name) == n.lower())).scalar_one_or_none() if n else None
    if t is None:
        raise MaintError(f"tenant “{n or '—'}” não existe")
    return t


def _source(t: Tenant, op) -> Source:
    if op.get("fonte_id"):
        s = Session.get(Source, int(op["fonte_id"]))
    else:
        n = _txt(op.get("fonte") or op.get("nome"))
        s = Session.execute(select(Source).where(Source.tenant_id == t.id, func.lower(Source.name) == n.lower())).scalar_one_or_none()
    if s is None or s.tenant_id != t.id:
        raise MaintError(f"fonte não encontrada no tenant {t.name}")
    return s


def _destination(t: Tenant, op) -> Destination:
    if op.get("destino_id"):
        d = Session.get(Destination, int(op["destino_id"]))
    else:
        n = _txt(op.get("destino") or op.get("nome"))
        d = Session.execute(select(Destination).where(Destination.tenant_id == t.id, func.lower(Destination.name) == n.lower())).scalar_one_or_none()
    if d is None or d.tenant_id != t.id:
        raise MaintError(f"destino não encontrado no tenant {t.name}")
    return d


def _allowed_ip(t: Tenant, cidr: str) -> AllowedIP:
    net = str(ipaddress.ip_network((cidr or "").strip(), strict=False)) if cidr else ""
    a = Session.execute(select(AllowedIP).where(AllowedIP.tenant_id == t.id, AllowedIP.cidr == net).order_by(AllowedIP.id)).scalars().first()
    if a is None:
        raise MaintError(f"IP {cidr} não está cadastrado no tenant {t.name}")
    return a


def _parser_id(slug, kind="input") -> int | None:
    slug = _txt(slug, 80).lower()
    if not slug:
        return None
    p = Session.execute(select(Parser).where(func.lower(Parser.slug) == slug, Parser.kind == kind)).scalar_one_or_none()
    if p is None:
        raise MaintError(f"parser “{slug}” não existe")
    return p.id


def _snap_tenant(t: Tenant) -> dict:
    return dict(name=t.name, segment=t.segment, internal=t.internal, status=t.status)


def _snap_source(s: Source) -> dict:
    return dict(name=s.name, transport=s.transport, parser_id=s.parser_id, match_hostname=s.match_hostname,
                unparsed_policy=s.unparsed_policy, note=s.note, active=s.active, silence_alert_minutes=s.silence_alert_minutes)


def _snap_destination(d: Destination) -> dict:
    return dict(name=d.name, format=d.format, config={k: v for k, v in (d.config or {}).items() if k != "ca_pem"},
                filters=d.filters or {}, include_unparsed=d.include_unparsed, active=d.active, batch_size=d.batch_size)


def _requires_secret(kind: str) -> bool:
    try:
        from ..engine import senders
        return any(f.required for f in senders.KINDS[kind]["secrets"])
    except Exception:  # noqa: BLE001
        return True


def _credentials_error(e: Exception) -> MaintError:
    return MaintError(f"{e} — a EVA não cadastra credenciais; um administrador precisa fazer este cadastro pela tela "
                      "(ou o Trust Parser precisa permitir cadastro com credencial pendente)")


def _bool(v):
    return None if v is None else bool(v)


# ------------------------------------------------------------------------------------------------ execução
def _apply_one(op: dict, requester: str, mode: str) -> tuple[dict, Outcome | None]:
    tipo = validate_op(op)
    res = {"tipo": tipo, "ok": True, "erro": "", "resumo": "", "aviso": "", "ids": {}, "antes": {}}
    by = f"EVA ({requester})"[:254]
    out: Outcome | None = None

    # ---- tenants
    if tipo == "tenant_adicionar":
        out = _call(_svc("tenants", "create_tenant"), name=_txt(op.get("tenant")), segment=_txt(op.get("segmento"), 60),
                    internal=bool(op.get("interno")))
        res["ids"] = {"tenant_id": out.obj.id}
    elif tipo in ("tenant_editar", "tenant_suspender", "tenant_reativar"):
        t = _tenant(op.get("tenant"))
        res["antes"], res["ids"] = _snap_tenant(t), {"tenant_id": t.id}
        fields = {"tenant_suspender": {"status": "suspended"}, "tenant_reativar": {"status": "active"}}.get(tipo) or \
            {k: v for k, v in (("name", _txt(op.get("novo_nome")) or None), ("segment", op.get("segmento")),
                               ("internal", _bool(op.get("interno")))) if v is not None}
        if not fields:
            raise MaintError("nada a alterar no tenant")
        out = _call(_svc("tenants", "update_tenant"), t, **fields)

    # ---- fontes
    elif tipo == "fonte_adicionar":
        t = _tenant(op.get("tenant"))
        fn = _svc("sources", "create_source")
        kw = dict(name=_txt(op.get("nome") or op.get("fonte")), transport=op.get("transporte") or "syslog",
                  parser_id=_parser_id(op.get("parser")), match_hostname=(op.get("hostname_regex") or "").strip()[:200],
                  unparsed_policy=op.get("nao_reconhecidas") or "keep", note=(op.get("observacao") or "")[:2000],
                  connector=_txt(op.get("conector"), 40), connector_config=op.get("conector_config") or {},
                  interval_s=op.get("intervalo_s"), silence_alert_minutes=op.get("alerta_silencio_min") or 0, by=by)
        if kw["transport"] == "api" and _supports(fn, "defer_secrets"):
            kw["defer_secrets"] = True
        try:
            out = _call(fn, t, **kw)
        except ServiceError as e:
            if "credenc" in str(e).lower():
                raise _credentials_error(e) from None
            raise
        res["ids"] = {"tenant_id": t.id, "fonte_id": out.obj.id}
        if kw["transport"] == "api":
            res["aviso"] = "conector criado sem credencial: um administrador precisa cadastrá-la na tela e testar"
    elif tipo in ("fonte_editar", "fonte_ativar", "fonte_desativar"):
        t = _tenant(op.get("tenant"))
        s = _source(t, op)
        res["antes"], res["ids"] = _snap_source(s), {"tenant_id": t.id, "fonte_id": s.id}
        if tipo == "fonte_ativar":
            fields = {"active": True}
        elif tipo == "fonte_desativar":
            fields = {"active": False}
        else:
            fields = {}
            if op.get("novo_nome"):
                fields["name"] = _txt(op["novo_nome"])
            if "parser" in op:
                fields["parser_id"] = _parser_id(op.get("parser"))
            for src, dst in (("hostname_regex", "match_hostname"), ("nao_reconhecidas", "unparsed_policy"), ("observacao", "note"),
                             ("alerta_silencio_min", "silence_alert_minutes"), ("transporte", "transport")):
                if op.get(src) is not None and op.get(src) != "":
                    fields[dst] = op[src]
            if op.get("conector_config"):
                fields["connector_config"] = op["conector_config"]
            if op.get("intervalo_s"):
                fields["interval_s"] = op["intervalo_s"]
            if not fields:
                raise MaintError("nada a alterar na fonte")
        out = _call(_svc("sources", "update_source"), s, by=by, **fields)

    # ---- IPs liberados (firewall do syslog aplicado no host pelo parser-fw-sync, com as travas dele)
    elif tipo == "ip_adicionar":
        t = _tenant(op.get("tenant"))
        cidr = check_cidr(op.get("cidr"))
        sid = _source(t, op).id if (op.get("fonte") or op.get("fonte_id")) else None
        protos = [p for p in (op.get("protocolos") or ["tls"]) if p in ("tls", "tcp", "udp")] or ["tls"]
        out = _call(_svc("sources", "add_allowed_ip"), t, cidr=cidr, protocols=protos, description=_txt(op.get("descricao"), 200),
                    source_id=sid, expires_at=parse_date_br(op.get("validade")), allow_wide=False, by=by)
        res["ids"] = {"tenant_id": t.id, "ip_id": out.obj.id, "cidr": out.obj.cidr}
    elif tipo in ("ip_desativar", "ip_reativar"):
        t = _tenant(op.get("tenant"))
        a = _allowed_ip(t, op.get("cidr"))
        res["antes"], res["ids"] = {"active": a.active}, {"tenant_id": t.id, "ip_id": a.id, "cidr": a.cidr}
        if tipo == "ip_reativar":
            check_cidr(a.cidr)  # reativar faixa larga cadastrada por administrador continua sendo decisão dele
        out = _call(_svc("sources", "update_allowed_ip"), a, active=(tipo == "ip_reativar"))

    # ---- destinos (sem credenciais)
    elif tipo == "destino_adicionar":
        t = _tenant(op.get("tenant"))
        kind = _txt(op.get("tipo_destino"), 20)
        needs_secret = _requires_secret(kind)
        fn = _svc("destinations", "create_destination")
        kw = dict(name=_txt(op.get("nome") or op.get("destino")), kind=kind, format=_txt(op.get("formato"), 80) or None,
                  config=op.get("config") or {}, filters=op.get("filtros") or None,
                  include_unparsed=bool(op.get("incluir_nao_reconhecidas")), active=not needs_secret, by=by)
        if needs_secret and _supports(fn, "defer_secrets"):
            kw["defer_secrets"] = True
        try:
            out = _call(fn, t, **kw)
        except ServiceError as e:
            if "credenc" in str(e).lower():
                raise _credentials_error(e) from None
            raise
        res["ids"] = {"tenant_id": t.id, "destino_id": out.obj.id}
        if needs_secret:
            res["aviso"] = "destino criado inativo e sem credencial: um administrador cadastra a credencial na tela, testa e ativa"
        if op.get("lote"):
            _call(_svc("destinations", "update_destination"), out.obj, by=by, batch_size=int(op["lote"]))
    elif tipo in ("destino_editar", "destino_ativar", "destino_desativar"):
        t = _tenant(op.get("tenant"))
        d = _destination(t, op)
        res["antes"], res["ids"] = _snap_destination(d), {"tenant_id": t.id, "destino_id": d.id}
        if tipo == "destino_ativar":
            if d.secret_enc is None and _requires_secret(d.kind):
                raise MaintError(f"o destino {d.name} ainda não tem credencial cadastrada; um administrador precisa cadastrá-la na tela")
            fields = {"active": True}
        elif tipo == "destino_desativar":
            fields = {"active": False}
        else:
            fields = {k: v for k, v in (("name", _txt(op.get("novo_nome")) or None), ("format", _txt(op.get("formato"), 80) or None),
                                        ("config", op.get("config") or None), ("filters", op.get("filtros") or None),
                                        ("include_unparsed", _bool(op.get("incluir_nao_reconhecidas"))),
                                        ("batch_size", op.get("lote") or None)) if v is not None}
            if not fields:
                raise MaintError("nada a alterar no destino")
        out = _call(_svc("destinations", "update_destination"), d, by=by, **fields)
    elif tipo == "destino_testar":
        t = _tenant(op.get("tenant"))
        d = _destination(t, op)
        res["ids"] = {"tenant_id": t.id, "destino_id": d.id}
        if mode == "aplicar":  # na simulação só confere que o destino existe (o teste envia um evento de verdade)
            ok, msg = _svc("destinations", "test_destination")(d)
            res["resumo"] = f"teste de conexão {'ok' if ok else 'falhou'}: {msg}"[:300]
            if not ok:
                res["aviso"] = res["resumo"]
        out = Outcome(message=res["resumo"] or "teste de conexão previsto", audit=[("eva.destino_testado", d.name, {"destino": d.id})]
                      if mode == "aplicar" else [])

    # ---- Estúdio IA (só pedido; publicar é decisão de um administrador)
    elif tipo == "estudio_pedir":
        kind = op.get("tipo_estudio") or "input"
        pid = _parser_id(op.get("parser"), "input" if kind != "output" else "output") if kind == "fix" or op.get("parser") else None
        samples = "\n".join(str(op.get("amostras") or "").splitlines()[:200])
        out = _call(_svc("studio", "request_job"), kind=kind, title=_txt(op.get("titulo"), 200), vendor=_txt(op.get("fabricante"), 80),
                    product=_txt(op.get("produto"), 120), request=(op.get("pedido") or "")[:5000], samples=samples, docs="",
                    docs_urls=[u for u in (op.get("docs_urls") or []) if isinstance(u, str)][:5], mask=True, parser_id=pid, by=by)
        res["ids"] = {"job_id": out.obj.id}
        res["aviso"] = "o resultado volta como versão em rascunho; um administrador revisa, aprova e publica"

    # ---- pessoas do tenant (gestor/leitor; administradores ficam fora)
    elif tipo == "pessoa_convidar":
        t = _tenant(op.get("tenant"))
        perfil = op.get("perfil") if op.get("perfil") in PERFIS else "reader"
        email = _txt(op.get("email"), 254).lower()
        out = _call(_svc("people", "add"), t, name=_txt(op.get("nome")) or email.split("@")[0], email=email, access=perfil,
                    receives=False)
        res["ids"] = {"tenant_id": t.id, "email": email, "perfil": perfil, "nome": _txt(op.get("nome"))}
    elif tipo in ("pessoa_reenviar_convite", "pessoa_remover"):
        t = _tenant(op.get("tenant"))
        email = _txt(op.get("email"), 254).lower()
        u = Session.execute(select(User).where(User.email == email)).scalar_one_or_none()
        if u is not None and u.role == "admin":
            raise MaintError("administradores do portal não são alterados pela EVA")
        res["ids"] = {"tenant_id": t.id, "email": email}
        if u is not None and u.tenant_id == t.id:
            res["antes"] = {"perfil": u.role, "nome": u.name, "status": u.status}
        fn = _svc("people", "resend_invite" if tipo == "pessoa_reenviar_convite" else "remove")
        out = _call(fn, t, email)
    if out is not None and not res["resumo"]:
        res["resumo"] = (out.message or "")[:300]
        if out.warning:
            res["aviso"] = (res["aviso"] + " " + out.warning).strip()
    return res, out


def run(ops: list[dict], requester: str, *, mode: str) -> tuple[list[dict], list[Outcome]]:
    """Simula (testar) ou aplica (aplicar) a lista inteira. Cada operação roda num savepoint: um erro não impede de validar
    as demais. Só "aplicar" com TODAS ok faz commit (o chamador dispara convites e avisos depois)."""
    if mode not in ("testar", "aplicar"):
        raise MaintError("modo inválido")
    if not ops:
        raise MaintError("nenhuma operação")
    if len(ops) > MAX_OPS:
        raise MaintError(f"no máximo {MAX_OPS} operações por pedido")
    results, outcomes = [], []
    for op in ops:
        sp = Session.begin_nested()
        try:
            res, out = _apply_one(op, requester, mode)
            Session.flush()
            sp.commit()
            if out is not None:
                outcomes.append(out)
        except (ServiceError, MaintError) as e:
            sp.rollback()
            res = {"tipo": (op or {}).get("tipo") if isinstance(op, dict) else None, "ok": False, "erro": str(e)[:300]}
        except Exception as e:  # noqa: BLE001 — erro inesperado vira resultado (tudo ou nada)
            sp.rollback()
            res = {"tipo": (op or {}).get("tipo") if isinstance(op, dict) else None, "ok": False,
                   "erro": f"{type(e).__name__}: {str(e)[:200]}"}
        results.append(res)
    if mode == "testar" or not all(r.get("ok") for r in results):
        Session.rollback()
        return results, []
    for out in outcomes:
        for action, target, details in out.audit or []:
            audit.log(action, str(target), actor_label=ACTOR, tenant_id=out.tenant_id,
                      details={**(details or {}), "por": requester, "via": "EVA"})
    audit.log("eva.manutencao_aplicada", requester, actor_label=ACTOR, details={"operacoes": [r["tipo"] for r in results]})
    Session.commit()
    return results, outcomes


def undo(results: list[dict], requester: str) -> tuple[list[dict], list[Outcome]]:
    """Desfaz operações aplicadas (em ordem inversa), sem excluir: o que foi incluído é desativado/suspenso; o que foi editado
    volta ao retrato; convite pendente é retirado; pessoa removida é convidada de novo; pedido ao Estúdio na fila é cancelado."""
    by = f"EVA ({requester})"[:254]
    out_items, outcomes = [], []
    for r in reversed([x for x in (results or []) if isinstance(x, dict) and x.get("ok")]):
        tipo, ids, before = r.get("tipo"), r.get("ids") or {}, r.get("antes") or {}
        item = {"tipo": tipo, "ok": True, "erro": "", "resumo": ""}
        sp = Session.begin_nested()
        try:
            out = None
            if tipo == "tenant_adicionar":
                out = _call(_svc("tenants", "update_tenant"), Session.get(Tenant, ids["tenant_id"]), status="suspended")
            elif tipo in ("tenant_editar", "tenant_suspender", "tenant_reativar"):
                out = _call(_svc("tenants", "update_tenant"), Session.get(Tenant, ids["tenant_id"]), **before)
            elif tipo == "fonte_adicionar":
                out = _call(_svc("sources", "update_source"), Session.get(Source, ids["fonte_id"]), by=by, active=False)
            elif tipo in ("fonte_editar", "fonte_ativar", "fonte_desativar"):
                out = _call(_svc("sources", "update_source"), Session.get(Source, ids["fonte_id"]), by=by, **before)
            elif tipo == "ip_adicionar":
                out = _call(_svc("sources", "update_allowed_ip"), Session.get(AllowedIP, ids["ip_id"]), active=False)
            elif tipo in ("ip_desativar", "ip_reativar"):
                out = _call(_svc("sources", "update_allowed_ip"), Session.get(AllowedIP, ids["ip_id"]), active=before.get("active"))
            elif tipo == "destino_adicionar":
                out = _call(_svc("destinations", "update_destination"), Session.get(Destination, ids["destino_id"]), by=by, active=False)
            elif tipo in ("destino_editar", "destino_ativar", "destino_desativar"):
                out = _call(_svc("destinations", "update_destination"), Session.get(Destination, ids["destino_id"]), by=by, **before)
            elif tipo == "destino_testar" or tipo == "pessoa_reenviar_convite":
                item["resumo"] = "nada a desfazer"
            elif tipo == "estudio_pedir":
                job = Session.get(StudioJob, ids["job_id"])
                try:
                    out = _svc("studio", "cancel_job")(job, by)
                except NotAvailable:
                    if job is not None and job.status == "queued":
                        job.status, job.decided_by, job.decided_at = "rejected", by, datetime.now(timezone.utc)
                        item["resumo"] = f"pedido nº {job.id} ao Estúdio cancelado"
                    else:
                        item["resumo"] = "o Estúdio já trabalhou no pedido; a versão gerada continua em rascunho (não publicada)"
            elif tipo == "pessoa_convidar":
                t = Session.get(Tenant, ids["tenant_id"])
                u = Session.execute(select(User).where(User.email == ids["email"])).scalar_one_or_none()
                if u is not None and u.tenant_id == t.id and u.role != "admin":
                    if u.status == "invited":
                        out = _call(_svc("people", "remove"), t, ids["email"])
                    else:
                        u.status = "suspended"  # já ativou o acesso: suspende em vez de apagar o histórico
                        item["resumo"] = f"acesso de {u.email} suspenso"
            elif tipo == "pessoa_remover":
                if before.get("perfil") in PERFIS:
                    t = Session.get(Tenant, ids["tenant_id"])
                    out = _call(_svc("people", "add"), t, name=before.get("nome") or ids["email"].split("@")[0], email=ids["email"],
                                access=before["perfil"], receives=False)
            else:
                raise MaintError("operação desconhecida")
            Session.flush()
            sp.commit()
            if out is not None:
                outcomes.append(out)
                item["resumo"] = item["resumo"] or (out.message or "")[:300]
            audit.log("eva.manutencao_desfeita", str(tipo), actor_label=ACTOR, details={"por": requester, "ids": ids})
        except Exception as e:  # noqa: BLE001
            sp.rollback()
            item.update(ok=False, erro=f"{type(e).__name__}: {str(e)[:160]}")
        out_items.append(item)
    if out_items and all(i["ok"] for i in out_items):
        for out in outcomes:
            for action, target, details in out.audit or []:
                audit.log(action, str(target), actor_label=ACTOR, tenant_id=out.tenant_id, details={**(details or {}), "por": requester, "via": "EVA"})
        Session.commit()
        return out_items, outcomes
    Session.rollback()
    return out_items, []


def after_commit(outcomes: list[Outcome]):
    """Convites por e-mail e avisos que só saem depois do commit (o modo teste de e-mails do portal continua valendo)."""
    from . import emails
    for out in outcomes:
        for user, token in out.invites or []:
            try:
                emails.send_magic_link(user, token, "invite")
            except Exception:  # noqa: BLE001 — convite que falha não desfaz a manutenção (pode ser reenviado)
                import logging
                logging.getLogger(__name__).exception("convite de %s não enviado", getattr(user, "email", "?"))
        for fn in out.after_commit or []:
            try:
                fn()
            except Exception:  # noqa: BLE001
                import logging
                logging.getLogger(__name__).exception("aviso pós-manutenção falhou")
    Session.commit()


def _public(results: list[dict]) -> list[dict]:
    return json.loads(json.dumps(results, ensure_ascii=False, default=str))


def main(argv=None) -> int:
    import argparse
    import sys
    ap = argparse.ArgumentParser(description="Manutenção controlada pela EVA (JSON no stdin, JSON no stdout).")
    ap.add_argument("--modo", choices=["testar", "aplicar", "desfazer"], required=True)
    ap.add_argument("--solicitante", required=True)
    a = ap.parse_args(argv)
    payload = json.loads(sys.stdin.read() or "{}")
    from .. import create_app
    app = create_app()
    with app.app_context():
        try:
            if a.modo == "desfazer":
                res, outs = undo(payload.get("resultados") or [], a.solicitante)
            else:
                res, outs = run(payload.get("operacoes") or [], a.solicitante, mode=a.modo)
            if outs:
                with app.test_request_context(base_url=app.config.get("APP_BASE_URL") or None):
                    after_commit(outs)
            out = {"resultados": _public(res)}
        except MaintError as e:
            Session.rollback()
            out = {"erro": str(e)}
    print(json.dumps(out, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
