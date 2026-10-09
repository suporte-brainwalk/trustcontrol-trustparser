"""Estúdio IA: transforma amostras + documentação em parser (entrada) ou formato (saída) declarativo, testado.

Fluxo determinístico em volta da IA: monta o pedido (com o guia da linguagem e exemplos reais) → IA devolve spec + testes →
o motor valida, mede cobertura sobre as amostras e roda os testes → se falhar, devolve os erros à IA (até 3 rodadas) →
grava como RASCUNHO. Publicar é sempre decisão de um administrador.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import socket
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select

from ..db import Session, utcnow
from ..models import Parser, ParserVersion, StudioJob
from ..services import ai, catalog, ops_alerts
from . import dsl, formats
from .mask import Masker

log = logging.getLogger(__name__)
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
MAX_SAMPLE_LINES, MAX_SAMPLE_CHARS, MAX_DOCS_CHARS = 300, 150_000, 120_000
ROUNDS = 5


def _read(rel: str) -> str:
    try:
        with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
            return f.read()
    except OSError:
        return ""


def _examples() -> str:
    out = []
    for name in ("nginx_access_trust.json", "withsecure_elements.json"):
        doc = json.loads(_read(f"app/engine/builtin/{name}") or "{}")
        doc.pop("tests", None)
        out.append(json.dumps(doc, ensure_ascii=False))
    return "\n\n".join(out)


def fetch_url(url: str) -> str:
    """Baixa documentação pública (https, sem redes internas), texto puro, até 400 KB."""
    u = urlsplit(url.strip())
    if u.scheme != "https" or not u.hostname:
        raise ValueError("só https://")
    for info in socket.getaddrinfo(u.hostname, 443):
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise ValueError("endereço interno não permitido")
    with httpx.stream("GET", url, timeout=30, follow_redirects=False, headers={"User-Agent": "TrustParser/1.0"}) as r:
        r.raise_for_status()
        buf = b""
        for chunk in r.iter_bytes():
            buf += chunk
            if len(buf) > 400_000:
                break
        ctype = r.headers.get("content-type", "")
    text = buf.decode("utf-8", "replace")
    if "html" in ctype or text.lstrip().startswith("<"):
        try:
            from selectolax.parser import HTMLParser
            tree = HTMLParser(text)
            for n in tree.css("script,style,nav,footer,header"):
                n.decompose()
            text = tree.body.text(separator="\n") if tree.body else text
        except Exception:  # noqa: BLE001
            text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\n\s*\n+", "\n\n", text)[:150_000]


SYSTEM_INPUT = """Você é engenheiro(a) de parsers de logs de segurança do produto Trust Parser.
Gere um parser DECLARATIVO (JSON) na linguagem descrita no guia abaixo. Ele será executado por um motor determinístico;
você não executa nada. Regras:
- Use apenas operações, expressões, conversões e condições do guia.
- Mapeie para o modelo canônico (subconjunto OCSF) com a classe correta e o máximo de campos úteis; o resto vai para "unmapped".
- "detect" deve reconhecer só este formato (assinatura específica, nada genérico como ".*").
- Tolerar a linha pura e com cabeçalho syslog (use {"op":"syslog","optional":true}) quando fizer sentido.
- "require" com ao menos "time".
- Gere "tests" (5 a 12) com linhas reais das amostras e os valores esperados de campos-chave (time, class_uid, ips, usuário...).
- Valores esperados devem ser exatamente o que o motor produz (ex.: time em ISO UTC com milissegundos e "Z").
Responda SOMENTE com um objeto JSON: {"spec": {...}, "tests": [...], "notes": "observações curtas em pt-BR"}.
O objeto "spec" inclui slug, name, vendor, product, description (pt-BR), basis ("real" se houver amostras, senão "docs"), detect, steps, map, cases, unmapped, require."""

SYSTEM_OUTPUT = """Você é engenheiro(a) de integrações do produto Trust Parser. Gere um FORMATO DE SAÍDA declarativo (JSON) que converte
o evento canônico (subconjunto OCSF, descrito no guia) para o formato/destino pedido, conforme a documentação fornecida.
Use a seção 6 do guia (serializer + map com expressões sobre "e.<campo canônico>", "raw" e "ctx.tenant"). Não invente campos do
destino que não estejam na documentação. Responda SOMENTE com JSON: {"spec": {...}, "notes": "observações curtas em pt-BR"}.
O "spec" inclui slug, name, description (pt-BR), serializer e os demais campos do serializer."""


def _guide() -> str:
    return _read("docs/dsl.md")


def _input_prompt(job: StudioJob, samples: list[str], docs: str, current: dict | None) -> list[dict]:
    parts = [f"## Guia da linguagem\n{_guide()}", f"## Exemplos reais de parsers aprovados\n{_examples()}",
             f"## Pedido\nTecnologia: {job.vendor} {job.product}\nTítulo: {job.title}\nDetalhes: {job.request or '-'}"]
    if current:
        parts.append("## Parser atual (ajuste-o; mantenha o slug e o que já funciona)\n" + json.dumps(current, ensure_ascii=False))
    if docs:
        parts.append(f"## Documentação do fabricante\n{docs[:MAX_DOCS_CHARS]}")
    if samples:
        parts.append("## Amostras (uma por linha; dados sensíveis mascarados)\n" + "\n".join(samples))
    else:
        parts.append("## Amostras\nNão há amostras: baseie-se nos exemplos da documentação e use basis=docs.")
    return [{"role": "system", "content": SYSTEM_INPUT}, {"role": "user", "content": "\n\n".join(parts)}]


def _output_prompt(job: StudioJob, docs: str, events: list[dict]) -> list[dict]:
    parts = [f"## Guia da linguagem\n{_guide()}", f"## Pedido\nDestino/formato: {job.vendor} {job.product}\nTítulo: {job.title}\n"
             f"Detalhes: {job.request or '-'}", "## Eventos canônicos de exemplo\n" + "\n".join(json.dumps(e, ensure_ascii=False) for e in events[:8])]
    if docs:
        parts.append(f"## Documentação do destino\n{docs[:MAX_DOCS_CHARS]}")
    return [{"role": "system", "content": SYSTEM_OUTPUT}, {"role": "user", "content": "\n\n".join(parts)}]


def _sample_events(masker: Masker | None = None) -> list[dict]:
    """Exemplos de eventos canônicos para a IA desenhar uma saída. NUNCA vêm do buffer (dados de clientes): são gerados a
    partir das linhas de teste anonimizadas dos parsers embutidos — uma classe OCSF de cada."""
    seen, out = set(), []
    for doc in catalog.builtin_docs():
        spec, tests = catalog.split_spec(doc)
        for t in tests:
            try:
                ev = dsl.parse(spec, t.get("input", ""))
            except (dsl.ParseError, dsl.SpecError):
                continue
            k = ev.get("class_uid")
            if k not in seen:
                seen.add(k)
                out.append(ev)
    return out[:8] or [catalog._sample_event()]


def _log(job: StudioJob, msg: str):
    job.log = (job.log or []) + [{"at": utcnow().isoformat(timespec="seconds"), "msg": msg[:500]}]
    Session.commit()  # andamento visível na tela enquanto a IA trabalha


AUTO_RETRIES = 2
TRANSIENT = re.compile(r"indisponível|falha de conexão|interrompeu|resposta vazia|cortada")


def run_next() -> bool:
    job = Session.execute(select(StudioJob).where(StudioJob.status == "queued").order_by(StudioJob.id).limit(1)
                          .with_for_update(skip_locked=True)).scalar_one_or_none()
    if job is None:
        return False
    job.status, job.started_at = "running", utcnow()
    _log(job, "Iniciado")
    Session.commit()
    try:
        generate(job)
    except ai.AIError as e:
        Session.rollback()
        job = Session.get(StudioJob, job.id)
        tries = int((job.report or {}).get("auto_retries") or 0)
        if TRANSIENT.search(str(e)) and tries < AUTO_RETRIES:
            # falha passageira do provedor (504, conexão, resposta vazia): volta para a fila sem depender de ninguém
            job.status, job.started_at = "queued", None
            job.report = {**(job.report or {}), "auto_retries": tries + 1}
            _log(job, f"Falha temporária do serviço de IA ({e}); nova tentativa automática {tries + 1}/{AUTO_RETRIES}")
            Session.commit()
            return True
        job.status, job.error = "failed", str(e)[:1000]
        _log(job, f"Falhou: {e}")
    except Exception as e:  # noqa: BLE001
        log.exception("estúdio: falha no pedido %s", job.id)
        Session.rollback()
        job = Session.get(StudioJob, job.id)
        job.status, job.error = "failed", f"erro interno: {str(e)[:500]}"
        _log(job, "Falhou por erro interno")
    job.finished_at = utcnow()
    Session.commit()
    ops_alerts.studio_done(job)
    Session.commit()
    return True


def generate(job: StudioJob):
    masker = Masker([t for t in re.split(r"[,;\n]", (job.report or {}).get("mask_terms", "")) if t.strip()]) if job.mask_data else None
    lines = [ln for ln in (job.samples or "").splitlines() if ln.strip()][:MAX_SAMPLE_LINES * 3]
    if masker:
        lines = [masker.mask(ln) for ln in lines]
    prompt_lines, total = [], 0
    for ln in lines[:MAX_SAMPLE_LINES]:
        total += len(ln)
        if total > MAX_SAMPLE_CHARS:
            break
        prompt_lines.append(ln)
    docs = job.docs or ""
    for url in job.docs_urls or []:
        try:
            docs += f"\n\n# Fonte: {url}\n" + fetch_url(url)
            _log(job, f"Documentação lida: {url}")
        except Exception as e:  # noqa: BLE001
            _log(job, f"Não foi possível ler {url}: {e}")
    if masker and docs:
        docs = masker.mask(docs)
    usage_total = {"cost": 0.0, "calls": 0}
    if job.kind == "output":
        _generate_output(job, docs, usage_total)
        return
    if job.kind == "secops":
        _generate_secops(job, usage_total)
        return
    current = None
    if job.kind == "fix" and job.parser_id:
        p = Session.get(Parser, job.parser_id)
        cur = Session.get(ParserVersion, p.current_version_id) if p and p.current_version_id else None
        current = cur.spec if cur else None
    messages = _input_prompt(job, prompt_lines, docs, current)
    best = None
    for rnd in range(1, ROUNDS + 1):
        _log(job, f"Rodada {rnd}: pedindo o parser à IA…")
        text, usage = ai.chat(messages)
        usage_total["cost"] += usage["cost"]
        usage_total["calls"] += 1
        job.ai_model = usage.get("model", "")[:80]
        try:
            out = ai.parse_json(text)
            spec = out.get("spec") if isinstance(out.get("spec"), dict) else {}
            tests = out.get("tests") or (spec.get("tests") or [])
        except ai.AIError as e:
            _log(job, f"Rodada {rnd}: resposta inválida ({e})")
            messages += [{"role": "assistant", "content": text[:20000]}, {"role": "user", "content": f"Resposta inválida: {e}. Devolva só o JSON."}]
            continue
        if not isinstance(spec, dict) or not spec:
            _log(job, f"Rodada {rnd}: sem spec")
            continue
        spec.pop("tests", None)
        problems = dsl.validate_spec(spec)
        cov = catalog.coverage(spec, lines) if lines and not problems else {"total": len(lines), "parsed": 0, "pct": 0, "errors": [], "failed": []}
        rep = catalog.run_tests(spec, tests) if not problems else {"total": len(tests), "passed": 0, "failures": [{"name": "estrutura", "error": "; ".join(problems)}]}
        det_ok = all(dsl.matches(spec, ln) for ln in lines[:50]) if lines else True
        score = (cov.get("pct", 0) if lines else 100) + (100 if not rep["failures"] else 0) + (10 if det_ok else 0)
        _log(job, f"Rodada {rnd}: cobertura {cov.get('pct', 0)}%, testes {rep['passed']}/{rep['total']}, detecção {'ok' if det_ok else 'falhou'}")
        if best is None or score > best[0]:
            best = (score, spec, tests, cov, rep, out.get("notes", ""))
        if not problems and not rep["failures"] and det_ok and (not lines or cov["pct"] >= 100):
            break
        feedback = {"problemas_estrutura": problems, "linhas_que_falharam": cov.get("failed", [])[:8], "erros": cov.get("errors", [])[:5],
                    "testes_com_falha": rep["failures"][:8], "deteccao_ok": det_ok}
        messages += [{"role": "assistant", "content": text[:30000]},
                     {"role": "user", "content": "O motor executou seu spec. Corrija e devolva o JSON completo novamente.\n" +
                      json.dumps(feedback, ensure_ascii=False, default=str)[:30000]}]
    job.ai_calls, job.ai_cost_usd = usage_total["calls"], round(usage_total["cost"], 5)
    if best is None:
        raise ai.AIError("a IA não produziu um parser válido")
    _, spec, tests, cov, rep, notes = best
    tests = [t for t in tests if isinstance(t, dict)]
    rep = catalog.run_tests(spec, tests)
    if job.kind == "fix" and job.parser_id:
        p = Session.get(Parser, job.parser_id)
        spec["slug"] = p.slug
    else:
        slug = re.sub(r"[^a-z0-9-]+", "-", str(spec.get("slug") or f"{job.vendor}-{job.product}").lower()).strip("-")[:70] or f"parser-{job.id}"
        base, n = slug, 2
        while Session.execute(select(Parser.id).where(Parser.slug == slug)).first():
            slug = f"{base}-{n}"
            n += 1
        spec["slug"] = slug
        p = catalog.create_parser(kind="input", slug=slug, name=spec.get("name") or job.title, vendor=spec.get("vendor") or job.vendor,
                                  product=spec.get("product") or job.product, description=spec.get("description", ""),
                                  origin="studio", basis="real" if lines else "docs")
        job.parser_id = p.id
    v = catalog.add_version(p, spec, tests, by=f"Estúdio IA (pedido #{job.id})", notes=str(notes)[:2000], studio_job_id=job.id,
                            report={"tests": rep, "coverage": {k: cov.get(k) for k in ("total", "parsed", "unparsed", "pct", "cases", "errors")}})
    job.result_version_id = v.id
    job.report = {**(job.report or {}), "coverage": {k: cov.get(k) for k in ("total", "parsed", "unparsed", "pct", "cases", "errors", "examples", "failed")},
                  "tests": rep, "notes": str(notes)[:2000]}
    job.status = "done"
    _log(job, f"Concluído: versão {v.version} em rascunho (cobertura {cov.get('pct', 0)}%, testes {rep['passed']}/{rep['total']})")


def _generate_output(job: StudioJob, docs: str, usage_total: dict):
    events = _sample_events()
    messages = _output_prompt(job, docs, events)
    best = None
    for rnd in range(1, ROUNDS + 1):
        text, usage = ai.chat(messages)
        usage_total["cost"] += usage["cost"]
        usage_total["calls"] += 1
        job.ai_model = usage.get("model", "")[:80]
        try:
            out = ai.parse_json(text)
            spec = out.get("spec") or {}
        except ai.AIError as e:
            messages += [{"role": "assistant", "content": text[:20000]}, {"role": "user", "content": f"Resposta inválida: {e}. Devolva só o JSON."}]
            continue
        errors, rendered = [], []
        for ev in events:
            try:
                rendered.append(formats.to_line(formats.custom(spec, ev, "linha original", {"tenant": "exemplo"})))
            except Exception as e:  # noqa: BLE001
                errors.append(str(e)[:200])
        _log(job, f"Rodada {rnd}: {len(rendered)}/{len(events)} eventos convertidos")
        if best is None or len(rendered) > best[0]:
            best = (len(rendered), spec, rendered, errors, out.get("notes", ""))
        if not errors and rendered:
            break
        messages += [{"role": "assistant", "content": text[:30000]},
                     {"role": "user", "content": "Erros ao executar o formato: " + json.dumps(errors[:8], ensure_ascii=False) + ". Corrija e devolva o JSON."}]
    job.ai_calls, job.ai_cost_usd = usage_total["calls"], round(usage_total["cost"], 5)
    if best is None or not best[2]:
        raise ai.AIError("a IA não produziu um formato válido")
    _, spec, rendered, errors, notes = best
    slug = re.sub(r"[^a-z0-9_-]+", "-", str(spec.get("slug") or f"saida-{job.vendor}-{job.product}").lower()).strip("-")[:70] or f"saida-{job.id}"
    base, n = slug, 2
    while Session.execute(select(Parser.id).where(Parser.slug == slug)).first():
        slug = f"{base}-{n}"
        n += 1
    spec["slug"] = slug
    p = catalog.create_parser(kind="output", slug=slug, name=spec.get("name") or job.title, vendor=job.vendor, product=job.product,
                              description=spec.get("description", ""), origin="studio", basis="docs")
    job.parser_id = p.id
    v = catalog.add_version(p, spec, [], by=f"Estúdio IA (pedido #{job.id})", notes=str(notes)[:2000], studio_job_id=job.id,
                            report={"rendered": rendered[:8], "errors": errors[:8]})
    job.result_version_id = v.id
    job.report = {**(job.report or {}), "rendered": rendered[:8], "errors": errors[:8], "notes": str(notes)[:2000]}
    job.status = "done"
    _log(job, f"Concluído: formato {slug} versão {v.version} em rascunho")


def create_job(*, kind: str, title: str, vendor: str = "", product: str = "", request: str = "", samples: str = "", docs: str = "",
               docs_urls=None, mask: bool = True, mask_terms: str = "", parser_id=None, by: str = "") -> StudioJob:
    from ..services.changes import ServiceError
    if kind not in ("input", "output", "fix", "secops"):
        raise ServiceError("Tipo de pedido inválido.")
    title = (title or "").strip()[:200]
    if not title:
        raise ServiceError("Dê um título ao pedido.")
    if kind in ("fix", "secops") and not parser_id:
        raise ServiceError("Escolha o parser de entrada.")
    if kind in ("input", "fix") and not (samples.strip() or docs.strip() or docs_urls):
        raise ServiceError("Envie amostras de log e/ou a documentação do formato.")
    urls = [u.strip() for u in (docs_urls or []) if u and u.strip()][:5]
    for u in urls:
        if not u.startswith("https://"):
            raise ServiceError(f"Endereço de documentação precisa ser https://: {u[:80]}")
    job = StudioJob(kind=kind, title=title, vendor=(vendor or "")[:80], product=(product or "")[:120], request=(request or "")[:5000],
                    samples=samples[:2_000_000], docs=docs[:500_000], docs_urls=urls, mask_data=bool(mask),
                    parser_id=int(parser_id) if parser_id else None, requested_by=by, report={"mask_terms": mask_terms[:2000]})
    Session.add(job)
    Session.flush()
    return job


# ------------------------------------------------------------------------------------------------ parser para o Google SecOps (CBN)
SYSTEM_SECOPS = """Você é engenheiro(a) de parsers do Google SecOps (Chronicle). Escreva um PARSER PERSONALIZADO no padrão do SecOps
(CBN — sintaxe tipo Logstash: filter { grok/kv/json/date/mutate ... }) que produza, para cada linha de exemplo, o evento UDM esperado
(fornecido). Regras do CBN que você deve seguir:
- Comece com "filter {" e termine com "}". Inicialize com mutate { replace => { "campo" => "" } } todo campo usado depois em condições.
- grok: match => { "message" => [ "padrão" ] }, overwrite => [...], on_error => "flag". Barras invertidas dobradas dentro das aspas.
- Datas: date { match => ["campo", "formato Joda"] target => "event.idm.read_only_udm.metadata.event_timestamp" on_error => "x" }.
- Campos escalares: mutate { replace => { "event.idm.read_only_udm.<caminho>" => "%{campo}" } } (só se o campo não estiver vazio).
- Números: mutate { convert => { "campo" => "integer|uinteger" } } e depois rename para o caminho UDM.
- Campos repetidos (ip, intermediary, additional.fields): mutate { merge => { "event.idm.read_only_udm.principal.ip" => "campo" } };
  Noun repetido (intermediary): monte "obj.ip" e faça merge de "obj" em "event.idm.read_only_udm.intermediary".
- additional.fields: rótulo com .key e .value.string_value e merge.
- Sempre defina metadata.event_type, vendor_name, product_name. Termine com mutate { merge => { "@output" => "event" } }.
- Use if [campo] != "" { ... } para não gravar vazio. Linha que não casar: drop { tag => "TAG_MALFORMED_MESSAGE" }.
Responda SOMENTE JSON: {"cbn": "código completo", "log_type_sugerido": "tipo de log do SecOps (ex.: NGINX)", "notes": "observações em pt-BR"}."""


def _secops_checks(cbn: str) -> list[str]:
    probs = []
    t = cbn.strip()
    if not t.startswith(("filter", "#")) or "filter {" not in t:
        probs.append("o parser precisa começar com 'filter {'")
    if t.count("{") != t.count("}"):
        probs.append(f"chaves desbalanceadas ({t.count('{')} '{{' vs {t.count('}')} '}}')")
    if '"@output" => "event"' not in t:
        probs.append("falta o merge final de 'event' em '@output'")
    if "event.idm.read_only_udm.metadata.event_type" not in t:
        probs.append("falta definir metadata.event_type")
    for i, ln in enumerate(t.splitlines(), 1):
        if ln.lstrip().startswith("#"):
            continue
        if len(re.findall(r'(?<!\\)"', ln)) % 2:
            probs.append(f"linha {i}: aspas desbalanceadas")
            break
    return probs


def _generate_secops(job: StudioJob, usage_total: dict):
    src = Session.get(Parser, job.parser_id)
    if src is None or src.kind != "input" or not src.current_version_id:
        raise ai.AIError("parser de entrada inválido ou sem versão publicada")
    v = Session.get(ParserVersion, src.current_version_id)
    # exemplos = SOMENTE as linhas de teste do parser (anonimizadas/mascaradas) — nunca dados do buffer
    lines = [t.get("input", "") for t in (v.tests or []) if t.get("input")][:20]
    if not lines:
        raise ai.AIError("o parser não tem linhas de teste para servir de exemplo")
    examples = []
    for ln in lines:
        try:
            ev = dsl.parse(v.spec, ln)
            examples.append({"linha": ln, "udm_esperado": formats.to_udm(ev, ln, {})})
        except (dsl.ParseError, dsl.SpecError):
            continue
    ref = _read("deploy/secops/nginx-access-pipe.conf")
    msgs = [{"role": "system", "content": SYSTEM_SECOPS},
            {"role": "user", "content": f"## Exemplo de parser CBN aprovado (Nginx)\n{ref}\n\n## Parser do Trust Parser a converter (lógica de extração)\n"
                                        f"{json.dumps(v.spec, ensure_ascii=False)}\n\n## Linhas e UDM esperado\n"
                                        + "\n".join(json.dumps(e, ensure_ascii=False) for e in examples)
                                        + (f"\n\n## Observações do pedido\n{job.request}" if job.request else "")}]
    best = None
    for rnd in range(1, ROUNDS + 1):
        _log(job, f"Rodada {rnd}: gerando o parser CBN…")
        text, usage = ai.chat(msgs)
        usage_total["cost"] += usage["cost"]
        usage_total["calls"] += 1
        job.ai_model = usage.get("model", "")[:80]
        try:
            out = ai.parse_json(text)
        except ai.AIError as e:
            msgs += [{"role": "assistant", "content": text[:20000]}, {"role": "user", "content": f"Resposta inválida: {e}. Devolva só o JSON."}]
            continue
        cbn = str(out.get("cbn") or "")
        probs = _secops_checks(cbn)
        _log(job, f"Rodada {rnd}: verificações {'ok' if not probs else '; '.join(probs)}")
        if best is None or len(probs) < len(best[1]):
            best = (cbn, probs, out)
        if not probs:
            break
        msgs += [{"role": "assistant", "content": text[:30000]}, {"role": "user", "content": "Corrija e devolva o JSON completo: " + "; ".join(probs)}]
    job.ai_calls, job.ai_cost_usd = usage_total["calls"], round(usage_total["cost"], 5)
    if best is None or not best[0]:
        raise ai.AIError("a IA não produziu um parser CBN")
    cbn, probs, out = best
    slug = f"secops-{src.slug}"[:80]
    p = Session.execute(select(Parser).where(Parser.slug == slug)).scalar_one_or_none()
    if p is None:
        p = catalog.create_parser(kind="output", slug=slug, name=f"Google SecOps (CBN) · {src.name}"[:160], vendor="Google",
                                  product="SecOps", description=f"Parser personalizado do Google SecOps equivalente a “{src.name}”, "
                                  "para quando o SecOps recebe os logs direto (sem o Trust Parser).", origin="studio", basis=src.basis)
    header = (f"# Google SecOps (CBN) — gerado pelo Trust Parser a partir de {src.slug} v{v.version}. Tipo de log sugerido: "
              f"{out.get('log_type_sugerido') or '-'}.\n# Antes de ativar, use Validate/Preview no SecOps com linhas reais.\n")
    nv = catalog.add_version(p, {"cbn": header + cbn, "for_parser": src.slug, "for_version": v.version,
                                 "log_type": str(out.get("log_type_sugerido") or "")[:60]}, [], by=f"Estúdio IA (pedido #{job.id})",
                             notes=str(out.get("notes", ""))[:2000], studio_job_id=job.id, report={"checks": probs})
    job.parser_id, job.result_version_id = p.id, nv.id
    job.report = {**(job.report or {}), "checks": probs, "cbn_preview": (header + cbn)[:6000], "notes": str(out.get("notes", ""))[:2000],
                  "log_type": out.get("log_type_sugerido")}
    job.status = "done"
    _log(job, f"Concluído: parser CBN versão {nv.version} em rascunho")
