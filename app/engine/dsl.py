"""Motor de parsing declarativo (determinístico).

Um parser é um JSON ("spec") com:
  detect   – condições sobre a linha bruta para reconhecer o formato (autodetecção);
  steps    – extrações em sequência (json, syslog, regex, split, kv, cef, leef, csv, winxml, url, list, mojibake, set);
  map      – campos do evento canônico (OCSF) a partir do que foi extraído;
  cases    – mapeamentos adicionais condicionais (por tipo de evento), aplicados por cima do map base;
  unmapped – blocos extraídos copiados para "unmapped" (nada se perde);
  require  – campos obrigatórios no evento final (senão a linha vai para "Não reconhecidos").

O mesmo spec + a mesma linha sempre geram o mesmo evento. A IA só escreve specs; quem executa é este motor.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from urllib.parse import urlsplit

from . import paths, syslog

MAX_LINE = 256 * 1024
RE_MOJIBAKE = re.compile("[ÂÃ][\u0080-¿]")


class ParseError(Exception):
    pass


class SpecError(ValueError):
    pass


@lru_cache(maxsize=2048)
def _re(pattern: str, flags: int = 0):
    try:
        return re.compile(pattern, flags)
    except re.error as e:
        raise SpecError(f"regex inválida: {pattern[:80]}… ({e})") from e


# ------------------------------------------------------------------------------------------------ conversões
def fix_mojibake(s):
    """Corrige UTF-8 lido como Latin-1 ("InformaÃ§Ãµes" → "Informações"). Não altera texto já correto."""
    if not isinstance(s, str) or not RE_MOJIBAKE.search(s):
        return s
    try:
        return s.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        try:
            return s.encode("cp1252").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            return s


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def to_time(v, kind: str = "auto", fmt: str = ""):
    if v is None or v == "" or v == "-":
        return None
    try:
        if kind == "epoch_ms":
            return _iso(datetime.fromtimestamp(int(float(v)) / 1000, tz=timezone.utc))
        if kind == "epoch_s":
            return _iso(datetime.fromtimestamp(float(v), tz=timezone.utc))
        if kind == "strptime":
            return _iso(datetime.strptime(str(v).strip(), fmt))
        s = str(v).strip()
        if re.fullmatch(r"\d{13}", s):
            return to_time(s, "epoch_ms")
        if re.fullmatch(r"\d{10}(\.\d+)?", s):
            return to_time(s, "epoch_s")
        s = s.replace("Z", "+00:00")
        m = re.match(r"^(.*\.\d{6})\d+(.*)$", s)  # nanossegundos (Windows) → microssegundos
        if m:
            s = m.group(1) + m.group(2)
        return _iso(datetime.fromisoformat(s))
    except (ValueError, OverflowError, OSError) as e:
        raise ParseError(f"data inválida: {str(v)[:60]}") from e


def _ip(v):
    if v is None:
        return None
    s = str(v).strip().strip("[]")
    s = s.split("/")[0]
    if s.count(":") == 1 and "." in s:  # 1.2.3.4:5678
        s = s.split(":")[0]
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return None


def convert(value, types):
    """Aplica uma ou mais conversões ("int", "ip", "epoch_ms", "strptime:%d/%b/%Y:%H:%M:%S %z", "split:,", ...)."""
    if isinstance(types, str):
        types = [types]
    for t in types or []:
        if value is None:
            return None
        name, _, arg = t.partition(":")
        if name == "str":
            value = str(value)
        elif name == "int":
            try:
                value = int(str(value).strip())
            except ValueError:
                return None
        elif name == "float":
            try:
                value = float(str(value).strip())
            except ValueError:
                return None
        elif name == "bool":
            value = str(value).strip().lower() in ("1", "true", "yes", "sim", "on")
        elif name == "lower":
            value = str(value).lower()
        elif name == "upper":
            value = str(value).upper()
        elif name == "strip":
            value = str(value).strip().strip('"').strip()
        elif name == "unquote":
            s = str(value).strip()
            value = s[1:-1] if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'" else s
        elif name == "nil":  # "-" / vazio → None
            value = None if str(value).strip() in ("", "-", "null", "None") else value
        elif name == "ip":
            value = _ip(value)
        elif name == "ips":
            seq = value if isinstance(value, list) else re.split(arg or r"[,\s]+", str(value))
            value = [x for x in (_ip(v) for v in seq) if x]
        elif name == "split":
            value = [x.strip() for x in str(value).split(arg or ",") if x.strip()]
        elif name == "first":
            value = value[0] if isinstance(value, list) and value else (None if isinstance(value, list) else value)
        elif name == "last":
            value = value[-1] if isinstance(value, list) and value else (None if isinstance(value, list) else value)
        elif name in ("epoch_ms", "epoch_s", "time"):
            value = to_time(value, "auto" if name == "time" else name)
        elif name == "strptime":
            value = to_time(value, "strptime", arg)
        elif name == "mojibake":
            value = fix_mojibake(value)
        elif name == "basename":
            value = re.split(r"[\\/]", str(value))[-1]
        elif name == "dirname":
            parts = re.split(r"([\\/])", str(value))
            value = "".join(parts[:-2]) if len(parts) > 2 else ""
        elif name == "domain":  # DOMINIO\usuario → DOMINIO
            value = str(value).split("\\")[0] if "\\" in str(value) else None
        elif name == "user":  # DOMINIO\usuario → usuario ; usuario@dominio → usuario
            s = str(value)
            value = s.split("\\")[-1].split("@")[0] if s else s
        elif name == "url_host":
            value = _url(value).get("hostname")
        elif name == "upper_first":
            s = str(value)
            value = s[:1].upper() + s[1:]
        elif name == "key":  # objeto → valor da chave literal (chaves com ponto, ex.: "open.date")
            value = value.get(arg) if isinstance(value, dict) else None
        elif name == "join":  # lista → texto (itens vazios e objetos são ignorados)
            if isinstance(value, list):
                value = (arg or ", ").join(str(x) for x in value if not paths.empty(x) and not isinstance(x, (dict, list))) or None
        elif name == "pick":  # lista de objetos → primeiro objeto com campo=valor ("pick:entityType=host")
            k, _, want = arg.partition("=")
            seq = value if isinstance(value, list) else [value]
            value = next((x for x in seq if isinstance(x, dict) and str(x.get(k)) == want), None)
        elif name == "hash_alg":  # hash hexadecimal → algoritmo pelo tamanho (32 MD5, 40 SHA-1, 64 SHA-256, 128 SHA-512)
            s = str(value).strip()
            value = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}.get(len(s)) if re.fullmatch(r"[0-9A-Fa-f]+", s) else None
        elif name == "replace":  # "replace:<antigo>:<novo>" (o primeiro ':' separa; ex.: "replace:#011:\t")
            old, _, new = arg.partition(":")
            value = str(value).replace(old, new) if old else value
        else:
            raise SpecError(f"conversão desconhecida: {t}")
    return value


def _url(v) -> dict:
    s = str(v or "").strip()
    if not s:
        return {}
    raw = s
    if not re.match(r"^[a-zA-Z][\w+.-]*://", s):
        s = ("http://" if not s.startswith("/") else "http://_") + s
    try:
        u = urlsplit(s)
    except ValueError:
        return {"url_string": raw}
    host = u.hostname if u.hostname and u.hostname != "_" else None
    out = {"url_string": raw, "hostname": host, "path": u.path or None, "query_string": u.query or None,
           "scheme": u.scheme if "://" in raw else None}
    try:
        out["port"] = u.port
    except ValueError:
        pass
    return {k: v for k, v in out.items() if v not in (None, "")}


# ------------------------------------------------------------------------------------------------ condições
def check(cond, ctx) -> bool:
    if cond is None or cond is True:
        return True
    if isinstance(cond, list):
        return all(check(c, ctx) for c in cond)
    if "all" in cond:
        return all(check(c, ctx) for c in cond["all"])
    if "any" in cond:
        return any(check(c, ctx) for c in cond["any"])
    if "not" in cond:
        return not check(cond["not"], ctx)
    v = paths.get(ctx, cond.get("path", "$raw"))
    if "exists" in cond:
        return (not paths.empty(v)) == bool(cond["exists"])
    if v is None:
        return False
    s = str(v)
    if "eq" in cond:
        return s == str(cond["eq"])
    if "ne" in cond:
        return s != str(cond["ne"])
    if "in" in cond:
        return s in [str(x) for x in cond["in"]]
    if "re" in cond:
        return _re(cond["re"], re.S).search(s) is not None
    if "startswith" in cond:
        return s.startswith(cond["startswith"])
    if "contains" in cond:
        return cond["contains"] in s
    raise SpecError(f"condição sem operador: {cond}")


# ------------------------------------------------------------------------------------------------ expressões
def evaluate(expr, ctx):
    if isinstance(expr, str):
        return paths.get(ctx, expr)
    if not isinstance(expr, dict):
        return expr
    if "const" in expr:
        v = expr["const"]
    elif "first" in expr:
        v = None
        for e in expr["first"]:
            v = evaluate(e, ctx)
            if not paths.empty(v):
                break
    elif "template" in expr:
        missing = []

        def sub(m):
            val = paths.get(ctx, m.group(1))
            if paths.empty(val):
                missing.append(m.group(1))
                return ""
            return str(val)
        v = re.sub(r"\{([\w.$-]+)\}", sub, expr["template"]).strip()
        if expr.get("strict") and missing:
            v = None
    elif "lookup" in expr:
        key = evaluate(expr["lookup"], ctx)
        table = expr.get("table", {})
        v = table.get(str(key), expr.get("default")) if key is not None else expr.get("default")
        if v is None and expr.get("default_from"):
            v = evaluate(expr["default_from"], ctx)
    elif "regex" in expr:
        src = evaluate(expr.get("path", "$raw"), ctx)
        m = _re(expr["regex"], re.S).search(str(src)) if src is not None else None
        v = (m.group(expr.get("group", 1)) if m else None)
    elif "url" in expr:
        v = _url(evaluate(expr["url"], ctx)) or None
    elif "path" in expr:
        v = paths.get(ctx, expr["path"])
    elif "object" in expr:
        v = {k: evaluate(e, ctx) for k, e in expr["object"].items()}
        v = {k: x for k, x in v.items() if not paths.empty(x)} or None
    elif "list" in expr:
        v = [x for x in (evaluate(e, ctx) for e in expr["list"]) if not paths.empty(x)] or None
    else:
        raise SpecError(f"expressão desconhecida: {list(expr)[:3]}")
    if "type" in expr and v is not None:
        v = convert(v, expr["type"])
    if paths.empty(v) and "default" in expr and "lookup" not in expr:
        v = expr["default"]
    return v


# ------------------------------------------------------------------------------------------------ extrações
def _kv_quoted(text: str, key_re: str = r"[A-Za-z_][\w.\-]*") -> dict:
    """key="valor" tolerante a aspas internas sem escape: o valor vai até a aspa que precede o próximo key=" ou o fim."""
    starts = [(m.start(1), m.group(1), m.end()) for m in _re(r'(?:^|\s)(' + key_re + r')="').finditer(text)]
    out = {}
    for i, (_, key, vstart) in enumerate(starts):
        vend = starts[i + 1][0] if i + 1 < len(starts) else len(text)
        chunk = text[vstart:vend].rstrip()
        if chunk.endswith('"]'):
            chunk = chunk[:-2] if i + 1 == len(starts) else chunk
        if chunk.endswith('"'):
            chunk = chunk[:-1]
        out[key] = chunk.replace('\\"', '"').replace("\\]", "]").replace("\\\\", "\\")
    return out


def _kv_simple(text: str, pair_sep: str, kv_sep: str) -> dict:
    out = {}
    rx = _re(r'([\w.\-@]+)' + re.escape(kv_sep) + r'("(?:[^"\\]|\\.)*"|\'[^\']*\'|[^' + re.escape(pair_sep) + r']*)')
    for k, v in rx.findall(text):
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1].replace('\\"', '"')
        out[k] = v
    return out


def _cef(text: str) -> dict:
    i = text.find("CEF:")
    if i < 0:
        raise ParseError("CEF: cabeçalho não encontrado")
    body = text[i + 4:]
    parts, cur, esc = [], "", False
    for idx, c in enumerate(body):
        if len(parts) == 7:
            ext = body[idx:]
            break
        if esc:
            cur += c
            esc = False
        elif c == "\\":
            esc = True
        elif c == "|":
            parts.append(cur)
            cur = ""
        else:
            cur += c
    else:
        ext = ""
        if len(parts) < 7:
            raise ParseError("CEF: cabeçalho incompleto")
    out = dict(zip(["version", "device_vendor", "device_product", "device_version", "signature_id", "name", "severity"], parts))
    keys = list(_re(r"(?:^|(?<=\s))([\w.\[\]-]+)=").finditer(ext))
    exts = {}
    for n, m in enumerate(keys):
        end = keys[n + 1].start() if n + 1 < len(keys) else len(ext)
        exts[m.group(1)] = ext[m.end():end].rstrip().replace("\\=", "=").replace("\\n", "\n").replace("\\\\", "\\")
    for k in [k for k in exts if k.endswith("Label")]:  # cs1Label=Foo cs1=bar → Foo=bar
        base = k[:-5]
        if base in exts:
            exts[exts[k]] = exts[base]
    out["ext"] = exts
    return out


def _leef(text: str) -> dict:
    i = text.find("LEEF:")
    if i < 0:
        raise ParseError("LEEF: cabeçalho não encontrado")
    body = text[i + 5:]
    head = body.split("|")
    ver = head[0]
    n = 5 if ver.startswith("1") else 6
    if len(head) < n:
        raise ParseError("LEEF: cabeçalho incompleto")
    out = dict(zip(["version", "vendor", "product", "product_version", "event_id"], head[:5]))
    delim = "\t"
    if n == 6:
        d = head[5]
        delim = bytes.fromhex(d[2:]).decode() if d.lower().startswith("0x") else (d or "\t")
    ext = "|".join(head[n:])
    out["ext"] = {k: v for k, _, v in (p.partition("=") for p in ext.split(delim) if "=" in p)}
    return out


def _winxml(text: str) -> dict:
    s = re.sub(r"\sxmlns='[^']*'|\sxmlns=\"[^\"]*\"", "", str(text or ""))
    try:
        root = ET.fromstring(s)
    except ET.ParseError as e:
        raise ParseError(f"XML inválido: {e}") from e
    out = {"System": {}, "EventData": {}}
    sysn = root.find("System")
    if sysn is not None:
        for ch in sysn:
            if ch.attrib and not (ch.text or "").strip():
                for k, v in ch.attrib.items():
                    out["System"][f"{ch.tag}{k}" if ch.tag not in ("Provider",) else f"Provider{k}"] = v
            else:
                out["System"][ch.tag] = (ch.text or "").strip()
    for sect in ("EventData", "UserData"):
        node = root.find(sect)
        if node is None:
            continue
        for i, d in enumerate(node.iter()):
            if d is node:
                continue
            name = d.attrib.get("Name") or (d.tag if d.tag != "Data" else f"Data{i}")
            if (d.text or "").strip():
                out["EventData"][name] = d.text.strip()
    return out


def run_step(step: dict, ctx: dict):
    op = step.get("op")
    if "when" in step and not check(step["when"], ctx):
        return
    src = evaluate(step.get("from", "$raw"), ctx) if op not in ("set", "mojibake") else None
    to = step.get("to", "")
    if op not in ("set", "mojibake") and src is None:
        if step.get("optional"):
            return
        raise ParseError(f"{op}: campo de origem vazio ({step.get('from', '$raw')})")
    try:
        if op == "json":
            s = src if isinstance(src, (dict, list)) else json.loads(str(src)[str(src).find("{"):] if step.get("seek") else str(src))
            res = s
        elif op == "syslog":
            res = syslog.parse(str(src))
            if res is None:
                if step.get("optional"):
                    res = {"msg": str(src)}
                else:
                    raise ParseError("syslog: cabeçalho não reconhecido")
        elif op == "regex":
            m = _re(step["pattern"], re.S).search(str(src))
            if not m:
                raise ParseError(f"regex não casou ({step.get('name') or step['pattern'][:40]})")
            res = {k: v for k, v in m.groupdict().items() if v is not None}
        elif op == "split":
            parts = str(src).rstrip("\r\n").split(step.get("sep", ","))
            if step.get("strip", True):
                parts = [p.strip() for p in parts]
            names = step.get("names", [])
            if step.get("min_fields") and len(parts) < step["min_fields"]:
                raise ParseError(f"split: {len(parts)} campos, esperado ≥ {step['min_fields']}")
            if step.get("exact") and len(parts) != len(names):
                raise ParseError(f"split: {len(parts)} campos, esperado {len(names)}")
            res = {n: (convert(p, "unquote") if step.get("unquote", True) else p) for n, p in zip(names, parts) if n}
            if len(parts) > len(names):
                res["_extra"] = parts[len(names):]
        elif op == "kv":
            mode = step.get("mode", "simple")
            if mode == "quoted":
                res = _kv_quoted(str(src))
            else:
                res = _kv_simple(str(src), step.get("pair_sep", " "), step.get("kv_sep", "="))
            if step.get("strip_prefix"):
                p = step["strip_prefix"]
                res = {(k[len(p):] if k.startswith(p) else k): v for k, v in res.items()}
        elif op == "cef":
            res = _cef(str(src))
        elif op == "leef":
            res = _leef(str(src))
        elif op == "csv":
            row = next(csv.reader(io.StringIO(str(src)), delimiter=step.get("delimiter", ",")))
            res = dict(zip(step.get("names", []), row))
        elif op == "winxml":
            res = _winxml(src)
        elif op == "url":
            res = _url(src)
        elif op == "list":
            res = convert(src, step.get("type", "split:,"))
        elif op == "set":
            res = evaluate(step.get("value"), ctx)
        elif op == "mojibake":
            for p in step.get("paths", []):
                base = paths.get(ctx, p)
                if isinstance(base, dict):
                    for k, v in list(base.items()):
                        base[k] = fix_mojibake(v)
                else:
                    paths.set_(ctx, p, fix_mojibake(base))
            return
        else:
            raise SpecError(f"operação desconhecida: {op}")
    except ParseError:
        if step.get("optional"):
            return
        raise
    except (ValueError, KeyError, IndexError, TypeError) as e:
        if step.get("optional"):
            return
        raise ParseError(f"{op}: {e}") from e
    if to:
        if step.get("merge") and isinstance(paths.get(ctx, to), dict) and isinstance(res, dict):
            paths.get(ctx, to).update(res)
        else:
            paths.set_(ctx, to, res)


# ------------------------------------------------------------------------------------------------ execução
SEVERITY_IDS = {"unknown": 0, "informational": 1, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5, "fatal": 6}
SEVERITY_NAMES = {0: "Unknown", 1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical", 6: "Fatal"}


def apply_map(mapping: dict, ctx: dict, event: dict):
    for target, expr in (mapping or {}).items():
        v = evaluate(expr, ctx)
        if not paths.empty(v):
            paths.set_(event, target, v)


def matches(spec: dict, raw: str) -> bool:
    det = spec.get("detect")
    if not det:
        return False
    try:
        return check(det, {"$raw": raw})
    except SpecError:
        return False


def parse(spec: dict, raw: str, meta: dict | None = None) -> dict:
    """Executa o spec sobre uma linha. Devolve o evento canônico (dict) ou levanta ParseError."""
    if raw is None:
        raise ParseError("linha vazia")
    if len(raw) > MAX_LINE:
        raise ParseError("linha maior que o limite (256 KB)")
    raw = raw.rstrip("\r\n")
    if not raw.strip():
        raise ParseError("linha vazia")
    ctx: dict = {"$raw": raw, "$meta": dict(meta or {})}
    for step in spec.get("steps", []):
        run_step(step, ctx)
    event: dict = {}
    apply_map(spec.get("map"), ctx, event)
    matched_case = None
    for case in spec.get("cases", []):
        if check(case.get("when"), ctx):
            for path in case.get("unset", []):
                parent, _, leaf = path.rpartition(".")
                holder = paths.get(event, parent) if parent else event
                if isinstance(holder, dict):
                    holder.pop(leaf, None)
            apply_map(case.get("map"), ctx, event)
            matched_case = case.get("name")
            if not case.get("continue"):
                break
    # campos não mapeados: tudo o que foi extraído dos blocos indicados (nada se perde)
    unm = {}
    for block in spec.get("unmapped", []):
        val = paths.get(ctx, block)
        if isinstance(val, dict):
            for k, v in val.items():
                if not paths.empty(v) and not isinstance(v, (dict, list)):
                    unm[k] = v
                elif isinstance(v, (dict, list)) and v:
                    unm[k] = v
    drop = set(spec.get("unmapped_drop", []))
    unm = {k: v for k, v in unm.items() if k not in drop}
    if unm:
        event.setdefault("unmapped", {}).update(unm)
    # normalizações comuns
    sev = event.get("severity")
    if "severity_id" not in event and isinstance(sev, str):
        event["severity_id"] = SEVERITY_IDS.get(sev.lower(), 0)
    if isinstance(event.get("severity_id"), int):
        event["severity"] = SEVERITY_NAMES.get(event["severity_id"], "Unknown")
    if "class_uid" in event and "activity_id" in event and "type_uid" not in event:
        try:
            event["type_uid"] = int(event["class_uid"]) * 100 + int(event["activity_id"])
        except (TypeError, ValueError):
            pass
    event = paths.prune(event)
    for req in spec.get("require", ["time"]):
        if paths.empty(paths.get(event, req)):
            raise ParseError(f"campo obrigatório ausente: {req}")
    if matched_case:
        event.setdefault("metadata", {})["parser_case"] = matched_case
    return event


def validate_spec(spec) -> list[str]:
    """Checagem estrutural do spec (antes de rodar os testes). Devolve a lista de problemas."""
    errs = []
    if not isinstance(spec, dict):
        return ["o spec precisa ser um objeto JSON"]
    for i, st in enumerate(spec.get("steps", [])):
        if not isinstance(st, dict) or "op" not in st:
            errs.append(f"steps[{i}]: falta 'op'")
            continue
        if st["op"] not in ("json", "syslog", "regex", "split", "kv", "cef", "leef", "csv", "winxml", "url", "list", "set", "mojibake"):
            errs.append(f"steps[{i}]: operação desconhecida '{st['op']}'")
        if st["op"] == "regex":
            try:
                re.compile(st.get("pattern", ""))
            except re.error as e:
                errs.append(f"steps[{i}]: regex inválida ({e})")
    if not isinstance(spec.get("map", {}), dict):
        errs.append("'map' precisa ser objeto")
    for i, c in enumerate(spec.get("cases", [])):
        if not isinstance(c, dict) or "when" not in c or "map" not in c:
            errs.append(f"cases[{i}]: precisa de 'when' e 'map'")
    return errs


def now_iso() -> str:
    return _iso(datetime.now(timezone.utc))


def shift_iso(iso: str, **kw) -> str:
    return _iso(datetime.fromisoformat(iso.replace("Z", "+00:00")) + timedelta(**kw))
