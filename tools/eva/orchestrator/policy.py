"""Política determinística aplicada pelo orquestrador — independe do que a IA disser.

- check_diff: caminhos permitidos, padrões proibidos nas linhas adicionadas, exclusões, tamanho, segredos.
- scan_secrets: valores reais dos segredos (arquivos .env, token do Claude, senha da caixa).
- validate_reply: e-mail de resposta sem código/segredos e sem afirmar o que o pipeline não fez.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from .paths import ALLOWED_BINARY_EXT, can_write

MAX_DIFF_LINES = 4000

PY_FORBIDDEN = [
    (r"\bSession\.(add|add_all|delete|merge|flush|commit)\s*\(", "gravação no banco"),
    (r"\b(s|session|db\.Session)\.(add|delete|merge|commit|flush)\s*\(", "gravação no banco"),
    (r"(?<![\w.])(delete|insert|update)\s*\(\s*[A-Z]\w*", "comando de escrita no banco"),
    (r"\.execute\s*\(\s*text\s*\(", "SQL manual"),
    (r"(?i)\b(drop\s+(table|database|schema)|truncate\s+table|alter\s+table|delete\s+from|insert\s+into|update\s+\w+\s+set)\b", "SQL destrutivo"),
    (r"\b(subprocess|os\.system|os\.popen|pty|shutil\.rmtree|os\.remove|os\.unlink|\.unlink\s*\()", "comando de sistema/exclusão de arquivos"),
    (r"(?<![\w.])(eval|exec|compile)\s*\(|__import__|importlib", "execução dinâmica de código"),
    (r"\b(httpx|requests|urllib|smtplib|socket|ftplib|paramiko)\b", "acesso à rede"),
    (r"\bsettings\.set_\s*\(|\bos\.environ\b|getenv\s*\(", "configuração ou variáveis de ambiente"),
    (r"\bopen\s*\([^)]*['\"][wax+]", "escrita de arquivos"),
    (r"(?i)(secret_key|api_key|password|senha|token)\s*=", "credenciais"),
    (r"current_app\.config\s*\[", "configuração da aplicação"),
]
TEMPLATE_FORBIDDEN = [
    (r"(?i)<script(?![^>]*\bsrc\s*=\s*['\"]\{\{\s*url_for\(\s*['\"]static['\"])", "script inline ou externo em página/e-mail"),
    (r"\|\s*safe\b|autoescape\s+false|Markup\s*\(", "HTML sem escape"),
    (r"(?i)javascript:", "link javascript"),
    (r"(?i)\son[a-z]+\s*=", "evento JavaScript inline"),
    (r"__|\bconfig\b|\brequest\.environ|\bself\._|\bcycler\b|\blipsum\b|\bjoiner\b|\bnamespace\s*\(", "acesso interno do template"),
    (r"(?i)<(iframe|object|embed|base|meta\s+http-equiv)", "elemento proibido"),
    (r"(?i)(src|href|action)\s*=\s*['\"]?\s*(https?:)?//(?!fonts\.googleapis\.com|fonts\.gstatic\.com)", "recurso externo"),
]
JS_FORBIDDEN = [
    (r"\bfetch\s*\(|XMLHttpRequest|WebSocket|EventSource|sendBeacon", "chamada de rede no navegador"),
    (r"(?<![\w.])eval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*['\"]", "execução dinâmica"),
    (r"document\.cookie|localStorage\.setItem\s*\(\s*['\"](?!tc-)", "armazenamento sensível"),
    (r"(?i)https?://", "endereço externo"),
]
CSS_FORBIDDEN = [(r"(?i)@import|url\s*\(\s*['\"]?\s*(https?:)?//", "recurso externo no CSS"), (r"(?i)expression\s*\(|javascript:", "CSS executável")]
TEST_FORBIDDEN = [
    (r"(?i)pytest\.mark\.(skip|xfail)|pytest\.skip\s*\(|pytest\.xfail\s*\(", "teste desativado"),
    (r"\b(subprocess|os\.system|shutil\.rmtree|os\.remove)\b", "comando de sistema"),
    (r"\b(httpx|requests|urllib|smtplib|socket)\b", "acesso à rede"),
    (r"(?i)\b(drop\s+(table|database)|truncate|alter\s+table)\b", "SQL destrutivo"),
    (r"\bos\.environ\b|getenv\s*\(", "variáveis de ambiente"),
]


@dataclass
class Verdict:
    ok: bool
    violations: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)


def parse_patch(patch: str) -> dict[str, dict]:
    """Extrai, por arquivo, linhas adicionadas/removidas e status (A/M/D/R/binário) de um `git diff --cached`."""
    files: dict[str, dict] = {}
    cur = None
    for line in patch.splitlines():
        if line.startswith("diff --git "):
            m = re.match(r"diff --git a/(.+?) b/(.+)$", line)
            name = m.group(2) if m else line.split()[-1][2:]
            cur = files.setdefault(name, {"added": [], "removed": [], "status": "M", "binary": False, "old": m.group(1) if m else name})
        elif cur is None:
            continue
        elif line.startswith("new file mode"):
            cur["status"] = "A"
        elif line.startswith("deleted file mode"):
            cur["status"] = "D"
        elif line.startswith("rename from") or line.startswith("similarity index"):
            cur["status"] = "R"
        elif line.startswith("Binary files") or line.startswith("GIT binary patch"):
            cur["binary"] = True
        elif line.startswith("+++") or line.startswith("---"):
            continue
        elif line.startswith("+"):
            cur["added"].append(line[1:])
        elif line.startswith("-"):
            cur["removed"].append(line[1:])
    return files


def _rules_for(path: str):
    if path.startswith("tests/"):
        return PY_FORBIDDEN[4:8] + TEST_FORBIDDEN if path.endswith(".py") else []
    if path.endswith(".py"):
        return PY_FORBIDDEN
    if path.endswith((".html", ".jinja", ".j2", ".txt")):
        return TEMPLATE_FORBIDDEN
    if path.endswith(".js"):
        return JS_FORBIDDEN
    if path.endswith(".css"):
        return CSS_FORBIDDEN
    if path.endswith(".svg"):
        return TEMPLATE_FORBIDDEN
    return []


def check_diff(patch: str, secrets: list[str], *, allow_deletions_of: set[str] | None = None) -> Verdict:
    files = parse_patch(patch)
    v = Verdict(ok=True, files=sorted(files))
    if not files:
        return Verdict(ok=False, violations=["nenhuma alteração"], files=[])
    total = sum(len(f["added"]) + len(f["removed"]) for f in files.values())
    if total > MAX_DIFF_LINES:
        v.violations.append(f"alteração grande demais ({total} linhas)")
    for path, f in files.items():
        for p in {path, f["old"]}:
            ok, why = can_write(p)
            if not ok:
                v.violations.append(f"{p}: {why}")
        if f["status"] == "D" and path not in (allow_deletions_of or set()):
            v.violations.append(f"{path}: exclusão de arquivo não é permitida")
        ext = os.path.splitext(path)[1].lower()
        if f["binary"] and ext not in ALLOWED_BINARY_EXT:
            v.violations.append(f"{path}: tipo de arquivo binário não permitido")
        for rx, label in _rules_for(path):
            for line in f["added"]:
                if re.search(rx, line):
                    v.violations.append(f"{path}: {label} → {line.strip()[:120]}")
                    break
        if path.startswith("tests/") and path.endswith(".py"):
            removed_tests = sum(1 for ln in f["removed"] if re.match(r"\s*def test_", ln))
            added_tests = sum(1 for ln in f["added"] if re.match(r"\s*def test_", ln))
            if removed_tests > added_tests:
                v.violations.append(f"{path}: remove testes existentes")
    hit = scan_secrets(patch, secrets)
    if hit:
        v.violations.append(f"segredo detectado na alteração ({hit})")
    v.ok = not v.violations
    return v


SECRET_NAME_RX = re.compile(r"(?i)(key|secret|passw|pass$|pwd|token|api|credential|private)")


def load_secrets(env_files: list[str], extra: list[str] | None = None) -> list[str]:
    """Valores realmente secretos: variáveis com nome de segredo (KEY/SECRET/PASSWORD/TOKEN...) e a senha dentro de URLs."""
    vals = set(extra or [])
    for fp in env_files:
        try:
            lines = open(fp, encoding="utf-8", errors="ignore").read().splitlines()
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, val = line.split("=", 1)
            name, val = name.strip(), val.strip().strip('"').strip("'")
            m = re.search(r"://[^:/@]+:([^@]+)@", val)
            if m:
                vals.add(m.group(1))
                continue
            if SECRET_NAME_RX.search(name) and len(val) >= 8:
                vals.add(val)
    return sorted(v for v in vals if len(v) >= 8)


def scan_secrets(text: str, secrets: list[str]) -> str:
    for s in secrets:
        if s and s in text:
            return f"{s[:3]}…({len(s)} caracteres)"
    generic = [r"sk-ant-[A-Za-z0-9_-]{20,}", r"sk-or-v1-[a-f0-9]{20,}", r"-----BEGIN [A-Z ]*PRIVATE KEY", r"ghp_[A-Za-z0-9]{30,}",
               r"xox[bp]-[A-Za-z0-9-]{20,}", r"AKIA[0-9A-Z]{16}"]
    for rx in generic:
        if re.search(rx, text):
            return "padrão de chave"
    return ""


CODE_HINTS = [r"```", r"\bdef \w+\(", r"\bclass \w+[(:]", r"^\s*(import|from) \w+", r"\{%-?\s", r"\{\{", r"<\w+[^>]*>",
              r"\b(app|tests|migrations|deploy|tools)/[\w/.-]+", r"\b[\w-]+\.(py|html|js|css|sql|env|yml|yaml|json)\b",
              r"\bgit (diff|commit|push|revert)\b", r"\bdocker\b", r"\bpostgres(ql)?://"]
AI_VENDOR_NAMES = r"(?i)\b(claude|anthropic|opus|sonnet|haiku|openai|chatgpt|gpt-?\d|gemini|deepseek|openrouter|llama|mistral|qwen|copilot|llm|xiaomi|mimo|kimi|moonshot|grok|xai|ling|inclusionai)\b"
DEPLOY_CLAIMS = [r"(?i)j[aá] est[aá] no ar", r"(?i)\bpubliquei\b", r"(?i)est[aá] (no ar|em produ[cç][aã]o)", r"(?i)\bapliquei\b",
                 r"(?i)j[aá] pode (ver|conferir) no portal", r"(?i)\bdesfiz\b", r"(?i)voltei (a|o|como)"]


def validate_reply(parts: list[str], *, deployed: bool, secrets: list[str]) -> list[str]:
    """Problemas encontrados no texto da resposta (vazio = pode enviar)."""
    text = "\n".join(p for p in parts if p)
    problems = []
    hit = scan_secrets(text, secrets)
    if hit:
        problems.append("segredo no texto")
    for rx in CODE_HINTS:
        if re.search(rx, text, flags=re.M):
            problems.append(f"conteúdo técnico/código ({rx})")
            break
    if not deployed:
        for rx in DEPLOY_CLAIMS:
            if re.search(rx, text):
                problems.append("afirma que publicou/desfez, mas nada foi para o ar")
                break
    if re.search(AI_VENDOR_NAMES, text):
        problems.append("menciona fabricante/modelo de IA (deve dizer apenas IA)")
    if len(text) > 12000:
        problems.append("texto longo demais")
    return problems
