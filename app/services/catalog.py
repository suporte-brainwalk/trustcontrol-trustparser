"""Catálogo de parsers (entrada) e formatos (saída): sementes embutidas, versões, testes, publicação e autodetecção."""
from __future__ import annotations

import copy
import glob
import hashlib
import json
import os
import threading
import time
from collections import Counter

from sqlalchemy import func, select

from ..db import Session, utcnow
from ..engine import dsl, formats, paths
from ..models import Parser, ParserVersion
from .changes import Conflict, Outcome, ServiceError, clean

BUILTIN_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "engine", "builtin")
META_KEYS = ("slug", "name", "vendor", "product", "description", "basis", "priority", "tests")


def _hash(spec: dict) -> str:
    return hashlib.sha256(json.dumps(spec, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def split_spec(doc: dict) -> tuple[dict, list]:
    """Separa o spec executável dos testes (metadados ficam no spec para referência)."""
    d = copy.deepcopy(doc)
    tests = d.pop("tests", []) or []
    return d, tests


def builtin_docs() -> list[dict]:
    out = []
    for path in sorted(glob.glob(os.path.join(BUILTIN_DIR, "*.json"))):
        with open(path, encoding="utf-8") as f:
            out.append(json.load(f))
    return out


# ------------------------------------------------------------------------------------------------ testes e cobertura
def run_tests(spec: dict, tests: list) -> dict:
    """Roda os testes dourados: cada caso compara os campos esperados com o evento gerado."""
    res = {"total": len(tests), "passed": 0, "failures": []}
    problems = dsl.validate_spec(spec)
    if problems:
        res["failures"].append({"name": "estrutura", "error": "; ".join(problems)})
        return res
    for i, t in enumerate(tests):
        name = t.get("name") or f"caso {i + 1}"
        try:
            ev = dsl.parse(spec, t.get("input", ""))
        except (dsl.ParseError, dsl.SpecError) as e:
            if t.get("expect_error"):
                res["passed"] += 1
            else:
                res["failures"].append({"name": name, "error": str(e)[:300]})
            continue
        if t.get("expect_error"):
            res["failures"].append({"name": name, "error": "esperava falha, mas a linha foi aceita"})
            continue
        diffs = []
        for p, want in (t.get("expect") or {}).items():
            got = paths.get(ev, p)
            if got != want and str(got) != str(want):
                diffs.append({"campo": p, "esperado": want, "obtido": got})
        if diffs:
            res["failures"].append({"name": name, "diffs": diffs[:20]})
        else:
            res["passed"] += 1
    return res


def coverage(spec: dict, lines: list[str], keep: int = 3) -> dict:
    """Cobertura sobre amostras: quantas linhas viram evento, erros mais comuns e exemplos (entrada → saída)."""
    errors, cases = Counter(), Counter()
    examples, failed = [], []
    parsed = 0
    lines = [ln for ln in lines if ln.strip()]
    for ln in lines:
        try:
            ev = dsl.parse(spec, ln)
            parsed += 1
            c = paths.get(ev, "metadata.parser_case") or ev.get("class_name") or "-"
            cases[c] += 1
            if cases[c] <= 1 and len(examples) < 12:
                examples.append({"input": ln[:4000], "event": ev, "udm_type": formats.udm_event_type(ev)})
        except (dsl.ParseError, dsl.SpecError) as e:
            errors[str(e)[:200]] += 1
            if len(failed) < keep * 4:
                failed.append({"input": ln[:2000], "error": str(e)[:300]})
    return {"total": len(lines), "parsed": parsed, "unparsed": len(lines) - parsed,
            "pct": round(100.0 * parsed / len(lines), 2) if lines else 0.0, "cases": dict(cases.most_common()),
            "errors": [{"error": k, "count": v} for k, v in errors.most_common(10)], "examples": examples, "failed": failed}


# ------------------------------------------------------------------------------------------------ versões
def next_version(parser_id: int) -> int:
    return (Session.execute(select(func.max(ParserVersion.version)).where(ParserVersion.parser_id == parser_id)).scalar() or 0) + 1


def add_version(p: Parser, spec: dict, tests: list, *, by: str, notes: str = "", studio_job_id=None, report=None) -> ParserVersion:
    v = ParserVersion(parser_id=p.id, version=next_version(p.id), spec=spec, tests=tests or [], status="draft", notes=notes[:2000],
                      created_by=by, studio_job_id=studio_job_id, report=report or (run_tests(spec, tests) if p.kind == "input" else {}))
    Session.add(v)
    Session.flush()
    return v


def publish(v: ParserVersion, by: str) -> Outcome:
    p = Session.get(Parser, v.parser_id)
    if p.kind == "input":
        rep = run_tests(v.spec, v.tests)
        if rep["failures"]:
            raise ServiceError(f"A versão {v.version} tem {len(rep['failures'])} teste(s) com falha; corrija antes de publicar.")
        v.report = {**(v.report or {}), "tests": rep}
    elif v.spec.get("builtin") is None:
        errs = []
        try:
            formats.custom(v.spec, _sample_event(), "linha de teste", {"tenant": "teste"})
        except (dsl.SpecError, Exception) as e:  # noqa: BLE001
            errs.append(str(e))
        if errs:
            raise ServiceError(f"O formato não funciona com um evento de teste: {errs[0][:200]}")
    old = Session.get(ParserVersion, p.current_version_id) if p.current_version_id else None
    if old is not None and old.id != v.id:
        old.status = "superseded"
    v.status, v.published_by, v.published_at = "published", by, utcnow()
    p.current_version_id = v.id
    p.updated_at = utcnow()
    invalidate()
    return Outcome(message=f"Versão {v.version} de “{p.name}” publicada.", obj=v,
                   audit=[("parser.published", p.slug, {"version": v.version, "previous": old.version if old else None})])


def _sample_event() -> dict:
    return {"time": "2026-10-08T12:00:00.000Z", "class_uid": 4002, "class_name": "HTTP Activity", "severity_id": 1,
            "severity": "Informational", "message": "GET exemplo.com.br/ 200",
            "metadata": {"product": {"vendor_name": "Exemplo", "name": "Produto"}, "event_code": "200"},
            "src_endpoint": {"ip": "203.0.113.10"}, "http_request": {"http_method": "GET", "url": {"url_string": "https://exemplo.com.br/", "hostname": "exemplo.com.br"}},
            "http_response": {"code": 200}}


# ------------------------------------------------------------------------------------------------ sementes
def seed(by: str = "implantação") -> dict:
    """Garante os parsers embutidos (app/engine/builtin) e os formatos de saída nativos. Idempotente.
    Parser embutido alterado no código vira nova versão publicada (passa pelos testes); edições feitas na tela (origem
    studio/manual) nunca são sobrescritas."""
    created, updated = 0, 0
    for doc in builtin_docs():
        spec, tests = split_spec(doc)
        slug = doc["slug"]
        p = Session.execute(select(Parser).where(Parser.slug == slug)).scalar_one_or_none()
        if p is None:
            p = Parser(kind="input", slug=slug, name=doc.get("name", slug), vendor=doc.get("vendor", ""), product=doc.get("product", ""),
                       description=doc.get("description", ""), origin="builtin", basis=doc.get("basis", "real"),
                       priority=int(doc.get("priority", 100)))
            Session.add(p)
            Session.flush()
            v = add_version(p, spec, tests, by=by, notes="Versão embutida")
            publish(v, by)
            created += 1
            continue
        if p.origin != "builtin":
            continue
        cur = Session.get(ParserVersion, p.current_version_id) if p.current_version_id else None
        if cur is None or _hash(cur.spec) != _hash(spec) or _hash(cur.tests or []) != _hash(tests):
            p.name, p.vendor, p.product, p.description = doc.get("name", p.name), doc.get("vendor", ""), doc.get("product", ""), doc.get("description", "")
            p.basis, p.priority = doc.get("basis", p.basis), int(doc.get("priority", p.priority))
            v = add_version(p, spec, tests, by=by, notes="Atualização da versão embutida")
            try:
                publish(v, by)
                updated += 1
            except ServiceError:
                v.status = "rejected"
    for code, name in formats.BUILTIN.items():
        p = Session.execute(select(Parser).where(Parser.slug == code)).scalar_one_or_none()
        if p is None:
            p = Parser(kind="output", slug=code, name=name, origin="builtin", basis="docs" if code in ("udm", "wazuh_json", "leef") else "real",
                       description=f"Formato nativo do Trust Parser: {name}.")
            Session.add(p)
            Session.flush()
            v = add_version(p, {"builtin": code}, [], by=by, notes="Formato nativo")
            publish(v, by)
            created += 1
    invalidate()
    return {"created": created, "updated": updated}


# ------------------------------------------------------------------------------------------------ cache para o worker
_cache = {"at": 0.0, "inputs": [], "by_id": {}, "outputs": {}}
_lock = threading.Lock()
TTL = 20.0


def invalidate():
    with _lock:
        _cache["at"] = 0.0


def _load():
    with _lock:
        if time.monotonic() - _cache["at"] < TTL:
            return
        rows = Session.execute(select(Parser, ParserVersion).join(ParserVersion, ParserVersion.id == Parser.current_version_id)
                               .where(Parser.active.is_(True))).all()
        inputs, by_id, outputs = [], {}, {}
        for p, v in rows:
            item = {"parser_id": p.id, "version_id": v.id, "slug": p.slug, "name": p.name, "spec": v.spec, "priority": p.priority}
            if p.kind == "input":
                inputs.append(item)
                by_id[p.id] = item
            else:
                outputs[p.slug] = item
        inputs.sort(key=lambda x: (x["priority"], x["slug"]))
        _cache.update(at=time.monotonic(), inputs=inputs, by_id=by_id, outputs=outputs)


def active_inputs() -> list[dict]:
    _load()
    return _cache["inputs"]


def output_spec(code: str) -> dict | None:
    """Spec de um formato de saída criado no Estúdio (None para os nativos)."""
    _load()
    item = _cache["outputs"].get(code)
    if item is None or "builtin" in item["spec"]:
        return None
    return item["spec"]


def output_choices() -> list[tuple[str, str]]:
    _load()
    return [(slug, it["name"]) for slug, it in sorted(_cache["outputs"].items(), key=lambda x: (x[0] not in formats.BUILTIN, x[1]["name"]))]


def parse_line(raw: str, meta: dict | None = None, parser_id: int | None = None) -> tuple[dict, int]:
    """Evento canônico + id da versão usada. Com parser fixo usa só ele; sem, autodetecta (assinatura + parse ok)."""
    _load()
    if parser_id:
        item = _cache["by_id"].get(parser_id)
        if item is None:
            raise dsl.ParseError("parser da fonte está desativado ou sem versão publicada")
        ev = dsl.parse(item["spec"], raw, meta)
        _stamp(ev, item)
        return ev, item["version_id"]
    last_err = None
    for item in _cache["inputs"]:
        if dsl.matches(item["spec"], raw):
            try:
                ev = dsl.parse(item["spec"], raw, meta)
                _stamp(ev, item)
                return ev, item["version_id"]
            except dsl.ParseError as e:
                last_err = e
    raise last_err or dsl.ParseError("formato não reconhecido por nenhum parser ativo")


def _stamp(ev: dict, item: dict):
    md = ev.setdefault("metadata", {})
    md["parser"] = item["slug"]
    md["parser_version_id"] = item["version_id"]


def detect(raw: str) -> list[str]:
    _load()
    return [it["slug"] for it in _cache["inputs"] if dsl.matches(it["spec"], raw)]


# ------------------------------------------------------------------------------------------------ alterações administrativas
def get_parser(pid: int) -> Parser:
    p = Session.get(Parser, pid)
    if p is None:
        raise ServiceError("Parser não encontrado.", 404)
    return p


def set_active(p: Parser, active: bool) -> Outcome:
    p.active = bool(active)
    invalidate()
    return Outcome(message=f"“{p.name}” {'ativado' if active else 'desativado'}.", obj=p,
                   audit=[("parser.active" if active else "parser.inactive", p.slug, {})])


def rollback_to(p: Parser, version_id: int, by: str) -> Outcome:
    v = Session.get(ParserVersion, version_id)
    if v is None or v.parser_id != p.id:
        raise ServiceError("Versão não encontrada.", 404)
    out = publish(v, by)
    out.audit = [("parser.rollback", p.slug, {"to_version": v.version})]
    out.message = f"“{p.name}” voltou para a versão {v.version}."
    return out


def create_parser(*, kind: str, slug: str, name: str, vendor: str = "", product: str = "", description: str = "",
                  origin: str = "studio", basis: str = "docs") -> Parser:
    slug = clean(slug, 80).lower().replace(" ", "-")
    if not slug:
        raise ServiceError("Informe um identificador (slug).")
    if Session.execute(select(Parser.id).where(Parser.slug == slug)).first():
        raise Conflict(f"Já existe um parser com o identificador {slug}.")
    p = Parser(kind=kind, slug=slug, name=clean(name) or slug, vendor=clean(vendor, 80), product=clean(product, 120),
               description=(description or "")[:2000], origin=origin, basis=basis, priority=200)
    Session.add(p)
    Session.flush()
    return p
