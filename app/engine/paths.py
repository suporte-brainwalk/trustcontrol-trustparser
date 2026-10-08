"""Acesso a caminhos pontuados ("a.b.c") em dicionários aninhados — usado pelo motor de parsing e pelos formatadores."""
from __future__ import annotations

_MISSING = object()


def get(d, path: str, default=None):
    if path in ("", "$"):
        return d
    cur = d
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part, _MISSING)
        elif isinstance(cur, list) and part.lstrip("-").isdigit():
            i = int(part)
            cur = cur[i] if -len(cur) <= i < len(cur) else _MISSING
        else:
            return default
        if cur is _MISSING:
            return default
    return cur


def set_(d: dict, path: str, value):
    parts = path.split(".")
    cur = d
    for part in parts[:-1]:
        nxt = cur.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[part] = nxt
        cur = nxt
    cur[parts[-1]] = value


def empty(v) -> bool:
    return v is None or v == "" or v == [] or v == {} or v == "-"


def prune(d):
    """Remove chaves vazias (None, "", "-", [], {}) recursivamente."""
    if isinstance(d, dict):
        out = {}
        for k, v in d.items():
            v = prune(v)
            if not empty(v):
                out[k] = v
        return out
    if isinstance(d, list):
        return [x for x in (prune(v) for v in d) if not empty(x)]
    return d


def flatten(d, prefix: str = "", out: dict | None = None) -> dict:
    out = {} if out is None else out
    if isinstance(d, dict):
        for k, v in d.items():
            flatten(v, f"{prefix}.{k}" if prefix else str(k), out)
    elif isinstance(d, list) and d and all(not isinstance(x, (dict, list)) for x in d):
        out[prefix] = ", ".join(str(x) for x in d)
    elif isinstance(d, list):
        for i, v in enumerate(d):
            flatten(v, f"{prefix}.{i}", out)
    else:
        out[prefix] = d
    return out
