"""Regras de caminhos — fonte única, usada pelo orquestrador E pelo hook do Claude Code no sandbox.

Sem dependências externas (o hook roda com o python do sandbox).
"""
from __future__ import annotations

import fnmatch
import posixpath

# O que a EVA pode ALTERAR (escrita). Leitura: todo o repositório (exceto .git).
ALLOWED_WRITE = [
    "app/web/templates/*", "app/web/templates/**/*",
    "app/web/static/*", "app/web/static/**/*",
    "app/web/admin.py", "app/web/tenant.py",
    "app/services/queries.py",
    "tests/unit/*.py", "tests/integration/*.py", "tests/fixtures/*",
]

# Sempre proibido, mesmo que case com ALLOWED_WRITE (banco, segurança, configuração, segredos, motor de parsing,
# infraestrutura/firewall, a própria EVA e a sua lista de autorizados).
DENY_WRITE = [
    "app/models.py", "migrations/*", "migrations/**/*", "alembic.ini",
    "app/security.py", "app/web/auth.py", "app/services/auth.py", "app/web/limiter.py",
    "app/config.py", "app/services/settings.py", "app/services/mailer.py", "app/services/audit.py", "app/services/crypto.py",
    "app/cli.py", "app/worker.py", "app/db.py", "app/__init__.py",
    "app/engine/*", "app/engine/**/*", "app/ingest/*", "app/ingest/**/*", "app/collector/*", "app/collector/**/*",
    "app/services/eva_*", "app/web/eva.py", "app/web/templates/admin/eva.html", "app/web/templates/email/eva_*",
    "app/api/*", "app/api/**/*", "app/services/api_keys.py", "app/web/templates/admin/api_keys.html",
    "app/web/templates/email/api_key_expiring.html", "tests/api/*", "tests/api/**/*",
    "app/web/templates/api/*", "app/web/static/js/api-docs.js", "app/web/static/vendor/*", "app/web/static/vendor/**/*",
    "tests/conftest.py", "tests/e2e/*", "tests/e2e/**/*", "tests/live/*", "tests/mail/*",
    "tools/*", "tools/**/*", "deploy/*", "deploy/**/*",
    "Dockerfile", "docker-compose*", ".dockerignore", ".gitignore", "requirements*", "pytest.ini", ".github/*", ".github/**/*",
    ".env*", "*.env", "*.pem", "*.key", "*.p12", "*.pfx",
]

ALLOWED_BINARY_EXT = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg", ".ico", ".woff2"}
REPO_ROOT = "/work/repo"
REQUEST_ROOT = "/work/pedido"


def norm(rel: str) -> str | None:
    """Normaliza caminho relativo ao repositório; None se escapar da raiz."""
    rel = (rel or "").replace("\\", "/").strip()
    if rel.startswith(REPO_ROOT + "/"):
        rel = rel[len(REPO_ROOT) + 1:]
    if rel.startswith("/"):
        return None
    n = posixpath.normpath(rel)
    if n.startswith("..") or n == ".":
        return None
    return n


def _match(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, p) for p in patterns)


def can_write(rel: str) -> tuple[bool, str]:
    n = norm(rel)
    if n is None:
        return False, "fora do repositório"
    if n.startswith(".git/") or n == ".git":
        return False, "controle de versão"
    if _match(n, DENY_WRITE):
        return False, "área protegida (banco, segurança, configuração, segredos, motor de parsing, infraestrutura ou a própria EVA)"
    if not _match(n, ALLOWED_WRITE):
        return False, "fora das áreas liberadas (telas, estilos, textos, e-mails e lógica de exibição)"
    return True, ""


def can_read(abs_path: str) -> tuple[bool, str]:
    p = posixpath.normpath((abs_path or "").replace("\\", "/"))
    for root in (REPO_ROOT, REQUEST_ROOT):
        if p == root or p.startswith(root + "/"):
            if "/.git/" in p + "/" and root == REPO_ROOT and not p.endswith(".gitignore"):
                return False, "controle de versão"
            return True, ""
    return False, "fora do repositório e do pedido"
