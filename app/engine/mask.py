"""Mascaramento de dados antes de enviar amostras à IA: IPs, e-mails, UUIDs, SIDs de domínio e termos informados.
Substituições consistentes (o mesmo valor vira sempre o mesmo marcador) e no mesmo formato, para a IA aprender a estrutura."""
from __future__ import annotations

import ipaddress
import re

RE_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
RE_IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}(?![\w:])")
RE_EMAIL = re.compile(r"\b[\w.+-]{1,64}@[\w-]+(?:\.[\w-]+)+\b")
RE_UUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
RE_SID = re.compile(r"\bS-1-5-21-\d+-\d+-\d+")


class Masker:
    def __init__(self, terms: list[str] | None = None):
        self.map: dict[str, str] = {}
        self.n = {"v4p": 0, "v4": 0, "v6": 0, "mail": 0, "uuid": 0, "sid": 0, "term": 0}
        self.terms = sorted({t.strip() for t in (terms or []) if len(t.strip()) >= 3}, key=len, reverse=True)

    def _v4(self, m):
        s = m.group(0)
        try:
            ip = ipaddress.ip_address(s)
        except ValueError:
            return s
        if s in self.map:
            return self.map[s]
        if ip.is_private:
            self.n["v4p"] += 1
            k = self.n["v4p"]
            new = f"10.{(k // 65536) % 256}.{(k // 256) % 256}.{k % 256 or 1}"
        elif ip.is_loopback or ip.is_unspecified:
            return s
        else:
            self.n["v4"] += 1
            k = self.n["v4"]
            new = f"198.18.{(k // 256) % 256}.{k % 256 or 1}"
        self.map[s] = new
        return new

    def _sub(self, kind, fmt):
        def f(m):
            s = m.group(0)
            if s not in self.map:
                self.n[kind] += 1
                self.map[s] = fmt(self.n[kind], s)
            return self.map[s]
        return f

    def mask(self, text: str) -> str:
        for t in self.terms:
            if t not in self.map:
                self.n["term"] += 1
                self.map[t] = f"OCULTO{self.n['term']}"
            text = re.sub(re.escape(t), self.map[t], text, flags=re.I)
        text = RE_EMAIL.sub(self._sub("mail", lambda n, s: f"usuario{n}@exemplo.com.br"), text)
        text = RE_UUID.sub(self._sub("uuid", lambda n, s: f"00000000-0000-4000-8000-{n:012d}"), text)
        text = RE_SID.sub(self._sub("sid", lambda n, s: f"S-1-5-21-1000000000-1000000000-{1000000000 + n}"), text)
        text = RE_IPV6.sub(self._sub("v6", lambda n, s: f"2001:db8::{n:x}"), text)
        text = RE_IPV4.sub(self._v4, text)
        return text
