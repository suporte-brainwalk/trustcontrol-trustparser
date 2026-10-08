"""Cabeçalho syslog (RFC 5424 e RFC 3164/BSD) — separa PRI, data, host, app e mensagem, preservando a linha original."""
from __future__ import annotations

import re
from datetime import datetime, timezone

RE_5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ver>\d{1,2}) (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) (?P<msgid>\S+) "
    r"(?P<rest>.*)$", re.S)
RE_3164 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ts>[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+)\s+"
    r"(?:(?P<host>[\w.\-:]+)\s+)?(?P<tag>[^\s:\[]{1,64})(?:\[(?P<pid>[^\]]*)\])?:?\s?(?P<msg>.*)$", re.S)
RE_PRI_ONLY = re.compile(r"^<(?P<pri>\d{1,3})>(?P<msg>.*)$", re.S)
MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
SEVERITY = ["emergency", "alert", "critical", "error", "warning", "notice", "informational", "debug"]


def _sd_split(rest: str) -> tuple[str, str]:
    """Separa STRUCTURED-DATA ("-" ou [..][..]) da MSG no RFC 5424, respeitando aspas escapadas."""
    if rest.startswith("- ") or rest == "-":
        return "", rest[2:]
    if not rest.startswith("["):
        return "", rest
    i, depth, esc, inq = 0, 0, False, False
    while i < len(rest):
        c = rest[i]
        if esc:
            esc = False
        elif c == "\\":
            esc = True
        elif c == '"':
            inq = not inq
        elif not inq and c == "[":
            depth += 1
        elif not inq and c == "]":
            depth -= 1
            if depth == 0 and (i + 1 == len(rest) or rest[i + 1] != "["):
                return rest[:i + 1], rest[i + 2:] if i + 2 <= len(rest) else ""
        i += 1
    return "", rest


def _ts_3164(ts: str) -> str | None:
    try:
        if ts[:4].isdigit():
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()
        mon, day, hms = ts.split()
        now = datetime.now(timezone.utc)
        h, m, s = (int(x) for x in hms.split(":"))
        return datetime(now.year, MONTHS[mon], int(day), h, m, s, tzinfo=timezone.utc).isoformat()
    except (ValueError, KeyError):
        return None


def parse(line: str) -> dict | None:
    """Devolve {pri, facility, severity, timestamp, hostname, app, procid, msgid, sd, msg, format} ou None se não houver PRI."""
    line = line.rstrip("\r\n")
    m = RE_5424.match(line)
    if m and m.group("ver") == "1":
        sd, msg = _sd_split(m.group("rest"))
        pri = int(m.group("pri"))
        if msg.startswith("\ufeff"):
            msg = msg[1:]
        return dict(format="rfc5424", pri=pri, facility=pri // 8, severity=SEVERITY[pri % 8],
                    timestamp=None if m.group("ts") == "-" else m.group("ts"), hostname=_nil(m.group("host")),
                    app=_nil(m.group("app")), procid=_nil(m.group("procid")), msgid=_nil(m.group("msgid")), sd=sd, msg=msg)
    m = RE_3164.match(line)
    if m:
        pri = int(m.group("pri"))
        return dict(format="rfc3164", pri=pri, facility=pri // 8, severity=SEVERITY[pri % 8], timestamp=_ts_3164(m.group("ts")),
                    hostname=m.group("host") or "", app=m.group("tag") or "", procid=m.group("pid") or "", msgid="", sd="",
                    msg=m.group("msg"))
    m = RE_PRI_ONLY.match(line)
    if m:
        pri = int(m.group("pri"))
        return dict(format="pri", pri=pri, facility=pri // 8, severity=SEVERITY[pri % 8], timestamp=None, hostname="", app="",
                    procid="", msgid="", sd="", msg=m.group("msg"))
    return None


def _nil(v: str) -> str:
    return "" if v == "-" else v
