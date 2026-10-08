"""Specs embutidos (app/engine/builtin/*.json): estrutura, testes próprios, autodetecção sem ambiguidade e saídas.

Roda sem banco: `python -m pytest tests/unit/test_builtin_specs.py -q -p no:cacheprovider --noconftest`.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.engine import dsl, formats, paths

BUILTIN = Path(__file__).resolve().parents[2] / "app" / "engine" / "builtin"
SPECS = {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in sorted(BUILTIN.glob("*.json"))}
CASES = [(stem, i) for stem, spec in SPECS.items() for i in range(len(spec.get("tests") or []))]
RENDER_FORMATS = ("udm", "cef", "leef", "wazuh_json", "csv")


def _case(stem: str, i: int) -> dict:
    return SPECS[stem]["tests"][i]


def _id(c):
    stem, i = c
    return f"{stem}[{i}]-{_case(stem, i).get('name', '')}"


def test_ha_specs():
    assert len(SPECS) >= 2


@pytest.mark.parametrize("stem", sorted(SPECS))
def test_estrutura(stem):
    spec = SPECS[stem]
    assert dsl.validate_spec(spec) == []
    for key in ("slug", "name", "vendor", "product", "description", "basis", "detect", "steps", "map"):
        assert spec.get(key), f"{stem}: falta '{key}'"
    assert spec["basis"] in ("real", "docs")
    tests = spec.get("tests") or []
    assert 3 <= len(tests) <= 8, f"{stem}: {len(tests)} testes (esperado 3–8)"
    for t in tests:
        assert t.get("name") and isinstance(t.get("input"), str)
        assert t.get("expect_error") or (isinstance(t.get("expect"), dict) and t["expect"])


def test_slugs_unicos():
    slugs = [s["slug"] for s in SPECS.values()]
    assert len(slugs) == len(set(slugs))


@pytest.mark.parametrize("c", CASES, ids=[_id(c) for c in CASES])
def test_caso(c):
    stem, i = c
    spec, case = SPECS[stem], _case(*c)
    if case.get("expect_error"):
        with pytest.raises(dsl.ParseError):
            dsl.parse(spec, case["input"])
        return
    ev = dsl.parse(spec, case["input"])
    diffs = {p: (paths.get(ev, p), want) for p, want in case["expect"].items() if paths.get(ev, p) != want}
    assert not diffs, f"{stem} / {case['name']}: (obtido, esperado) {diffs}"


@pytest.mark.parametrize("c", CASES, ids=[_id(c) for c in CASES])
def test_autodeteccao(c):
    stem, i = c
    raw = _case(*c)["input"]
    assert dsl.matches(SPECS[stem], raw), f"{stem}: detect não reconhece o próprio teste"
    others = [s for s, sp in SPECS.items() if s != stem and dsl.matches(sp, raw)]
    assert not others, f"{stem}: linha também reconhecida por {others}"


@pytest.mark.parametrize("c", CASES, ids=[_id(c) for c in CASES])
def test_saidas(c):
    stem, i = c
    case = _case(*c)
    if case.get("expect_error"):
        pytest.skip("caso de erro esperado")
    ev = dsl.parse(SPECS[stem], case["input"])
    ctx = {"tenant": "acme", "source": "teste", "parser": SPECS[stem]["slug"]}
    for fmt in RENDER_FORMATS:
        out = formats.render(fmt, ev, case["input"], ctx)
        assert out, f"{fmt} vazio"
        formats.to_line(out)
    udm = formats.render("udm", ev, case["input"], ctx)
    if ev.get("class_uid") not in (None, 0) and not case.get("udm_generic_ok"):
        assert udm["metadata"]["event_type"] != "GENERIC_EVENT", (
            f"{stem} / {case['name']}: UDM caiu para GENERIC_EVENT (tipo original "
            f"{udm.get('additional', {}).get('trustparser.udm_type_original')})")
