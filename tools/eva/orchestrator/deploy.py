"""Publicação em produção com verificação pós-deploy e rollback automático (imagem anterior + git revert).

Trust Parser: uma imagem (`trustparser-app`, alvo `runtime` do Dockerfile) serve os dois serviços publicados a partir do
repositório — `parser-app` (web + worker) e `parser-ingest` (receptor syslog).
"""
from __future__ import annotations

import json
import logging
import re
import ssl
import subprocess
import time
import urllib.error
import urllib.request

from . import config

log = logging.getLogger("eva.deploy")
ROLLBACK_TAG = f"{config.APP_IMAGE}:eva-anterior"
PROD_HOST = re.sub(r"^https?://", "", config.PORTAL_URL).split("/")[0]


def sh(cmd, timeout=1800, check=True):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd[:4])}: {(r.stderr or r.stdout)[-600:]}")
    return r


def compose(*args, timeout=1800):
    return sh(["docker", "compose", "-f", config.COMPOSE_FILE, *args], timeout=timeout)


def healthz() -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    req = urllib.request.Request(f"https://{config.NGINX_HOST}/healthz", headers={"Host": PROD_HOST})
    with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
        return json.loads(r.read())


def container_state(name: str) -> str:
    """healthy | unhealthy | starting | running (sem healthcheck) | outro estado | '' (não existe)."""
    fmt = "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}"
    return sh(["docker", "inspect", "-f", fmt, name], check=False).stdout.strip()


def healthy_enough(app_state: str, ingest_state: str | None, h: dict) -> bool:
    """Regra única (testada): app saudável, healthz ok, worker batendo (se exigido) e receptor syslog no ar."""
    if app_state != "healthy" or h.get("status") != "ok":
        return False
    if config.REQUIRE_WORKER_HEARTBEAT:
        age = h.get("worker_heartbeat_age_s")
        if age is None or age >= 120:
            return False
    if ingest_state is not None and ingest_state not in ("healthy", "running"):
        return False
    return True


def wait_healthy(timeout=240) -> tuple[bool, str]:
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        st = container_state(config.APP_SERVICE)
        ing = container_state(config.INGEST_SERVICE) if config.INGEST_SERVICE else None
        try:
            h = healthz()
            if healthy_enough(st, ing, h):
                return True, "ok"
            last = f"app={st} ingest={ing} status={h.get('status')} worker={h.get('worker_heartbeat_age_s')}"
        except Exception as e:  # noqa: BLE001
            last = f"app={st} ingest={ing} healthz indisponível ({type(e).__name__})"
        time.sleep(5)
    return False, last


def publish() -> tuple[bool, str]:
    """Constrói e sobe a aplicação a partir do repositório de produção (já atualizado)."""
    if config.DRY_RUN_DEPLOY:
        return True, "simulado"
    sh(["docker", "tag", f"{config.APP_IMAGE}:latest", ROLLBACK_TAG])
    compose("build", config.APP_SERVICE)
    compose("up", "-d", *config.APP_SERVICES)
    return wait_healthy()


def rollback_image() -> tuple[bool, str]:
    if config.DRY_RUN_DEPLOY:
        return True, "simulado"
    sh(["docker", "tag", ROLLBACK_TAG, f"{config.APP_IMAGE}:latest"])
    compose("up", "-d", "--no-build", "--force-recreate", *config.APP_SERVICES)
    return wait_healthy()


def _flask_json(cmd: list[str], label: str, timeout: int) -> tuple[dict | None, str]:
    """Roda um comando `flask` no container publicado e lê a última linha JSON. Comando inexistente = (None, 'ausente')."""
    r = sh(["docker", "exec", config.APP_SERVICE, "flask", "--app", "app:create_app", *cmd], timeout=timeout, check=False)
    out = (r.stdout or "") + (r.stderr or "")
    if "No such command" in out:
        log.warning("verificação %s indisponível nesta versão (comando ausente)", label)
        return None, "ausente"
    line = next((ln for ln in reversed((r.stdout or "").splitlines()) if ln.strip().startswith("{")), "")
    try:
        return json.loads(line), ""
    except ValueError:
        return None, f"verificação {label} não respondeu ({out[-200:]})"


def smoke_production(extra_pages: list[str]) -> list[str]:
    """Verificação no ar SEM conta de usuário:
    1) telas renderizadas dentro do container publicado com identidade temporária em memória (`flask verificar-paginas`);
    2) API de leitura (`flask api-verificar`) e pelo domínio (saúde pública e recusa sem chave);
    3) tela pública de entrada aberta num navegador real pelo domínio (certificado, proxy, erros de JavaScript)."""
    if config.DRY_RUN_DEPLOY:
        return []
    problems = []
    extra = ",".join(p for p in extra_pages if p.startswith(("/admin", "/t")))
    data, err = _flask_json(["verificar-paginas", "--extra", extra], "das telas", 300)
    if err and err != "ausente":
        problems.append(err)
    elif data is not None:
        problems += data.get("problemas", [])
        if data.get("verificadas", 0) < 5:
            problems.append("poucas telas verificadas no ar")
    data, err = _flask_json(["api-verificar"], "da API", 180)
    if err and err != "ausente":
        problems.append(err)
    elif data is not None:
        problems += [f"API: {p}" for p in data.get("problemas", [])]
    for path, want in (("/api/v1/health", 200), ("/api/v1/me", 401)):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            req = urllib.request.Request(f"https://{config.NGINX_HOST}{path}", headers={"Host": PROD_HOST})
            try:
                code = urllib.request.urlopen(req, context=ctx, timeout=10).status
            except urllib.error.HTTPError as e:
                code = e.code
        except Exception as e:  # noqa: BLE001
            code = f"sem resposta ({type(e).__name__})"
        if code != want:
            problems.append(f"API pelo domínio: {path} respondeu {code} (esperado {want})")
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch(args=[f"--host-resolver-rules=MAP {PROD_HOST} {config.NGINX_HOST}"])
        page = browser.new_context(ignore_https_errors=True, locale="pt-BR").new_page()
        errs: list[str] = []
        page.on("console", lambda m: errs.append(m.text) if m.type == "error" else None)
        page.on("pageerror", lambda e: errs.append(str(e)))
        resp = page.goto(f"https://{PROD_HOST}/auth/login", wait_until="networkidle")
        if not resp or resp.status >= 400:
            problems.append(f"tela de entrada: HTTP {resp.status if resp else '—'}")
        elif not page.locator("input[name=email]").count():
            problems.append("tela de entrada sem o campo de e-mail")
        if [e for e in errs if "favicon" not in e]:
            problems.append(f"tela de entrada: erro no navegador: {errs[0][:120]}")
        browser.close()
    return problems
