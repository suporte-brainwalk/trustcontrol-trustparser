"""Verificação determinística antes de publicar: testes, instâncias temporárias (antes/depois), checagens e capturas."""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from . import config

log = logging.getLogger("eva.verify")
PYTEST_MARK = "not mail and not live and not perf"
ARTIFACT_RX = re.compile(r"(?i)&lt;Macro|Undefined|jinja2|Traceback")
# Telas verificadas em toda alteração (antes/depois). Página que já não existia antes (404 nas duas versões) não é regressão,
# então a lista pode citar telas que o Trust Parser ainda vai ganhar. Manter alinhada a app/web/admin.py e app/web/tenant.py.
ADMIN_PAGES = ["/admin/", "/admin/tenants", "/admin/tenants/{tenant}", "/admin/fontes", "/admin/fontes/{source}", "/admin/firewall",
               "/admin/destinos", "/admin/destinos/{destination}", "/admin/parsers", "/admin/estudio", "/admin/uploads",
               "/admin/nao-reconhecidos", "/admin/eva", "/admin/api", "/admin/auditoria", "/admin/configuracoes", "/admin/ajuda", "/auth/account"]
TENANT_PAGES = ["/t/", "/t/fontes", "/t/destinos", "/t/uploads", "/t/pessoas"]
EMAIL_PAGES: dict[str, str] = {}  # pré-visualizações de e-mail (chave -> caminho), quando o Trust Parser tiver
GMAIL_LIMIT = 102 * 1024
# instâncias e testes nunca usam IA, e-mail real nem a chave de IA de produção
SAFE_ENV = ["-e", "AI_ENABLED=0", "-e", "OPENROUTER_API_KEY=", "-e", "SMTP_HOST=smtp-desativado.invalid", "-e", "SCHEDULER_ENABLED=0"]


def sh(cmd: list[str], timeout=900, check=True) -> subprocess.CompletedProcess:
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd[:3])}: {(r.stderr or r.stdout)[-600:]}")
    return r


# ---------------- imagens
def build_image(tag: str, context: str) -> str:
    sh(["docker", "build", "-q", "--target", "test", "-t", tag, context], timeout=1800)
    return tag


def image_exists(tag: str) -> bool:
    return subprocess.run(["docker", "image", "inspect", tag], capture_output=True).returncode == 0


# ---------------- testes
@dataclass
class TestResult:
    ok: bool
    collected: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    failures: list[str] = field(default_factory=list)
    output_tail: str = ""


def count_tests(image: str) -> int:
    r = sh(["docker", "run", "--rm", "--env-file", config.APP_ENV_FILE, *SAFE_ENV, image, "pytest", "--collect-only", "-q", "-m", PYTEST_MARK, "-p", "no:cacheprovider"],
           timeout=300, check=False)
    m = re.search(r"(\d+)(?:/\d+)? tests? collected", r.stdout + r.stderr)
    return int(m.group(1)) if m else 0


def run_tests(image: str, out_dir: str) -> TestResult:
    os.makedirs(out_dir, exist_ok=True)
    subprocess.run(["chmod", "777", out_dir], check=False)
    r = sh(["docker", "run", "--rm", "--network", config.DOCKER_NETWORK, "--env-file", config.APP_ENV_FILE, *SAFE_ENV, "-e", f"PORTAL_TEST_DB={config.TEST_DB}",
            "-v", f"{out_dir}:/out", image, "pytest", "-m", PYTEST_MARK, "-p", "no:cacheprovider", "--junitxml=/out/junit.xml", "-q"],
           timeout=1800, check=False)
    res = TestResult(ok=False, output_tail=(r.stdout + r.stderr)[-3000:])
    try:
        root = ET.parse(os.path.join(out_dir, "junit.xml")).getroot()
        suites = [root] if root.tag == "testsuite" else list(root)
        for s in suites:
            res.collected += int(s.get("tests", 0))
            res.failed += int(s.get("failures", 0))
            res.errors += int(s.get("errors", 0))
            res.skipped += int(s.get("skipped", 0))
            for case in s.iter("testcase"):
                for bad in list(case.findall("failure")) + list(case.findall("error")):
                    msg = (bad.get("message") or "") + "\n" + (bad.text or "")[-1500:]
                    res.failures.append(f"{case.get('classname')}::{case.get('name')}\n{msg.strip()[:1800]}")
    except (OSError, ET.ParseError):
        res.failures.append("os testes não produziram relatório (falha ao iniciar)")
        return res
    res.ok = r.returncode == 0 and res.failed == 0 and res.errors == 0
    return res


# ---------------- instâncias temporárias
def recreate_db(name: str):
    url = make_url(config.DATABASE_URL)
    eng = create_engine(url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with eng.connect() as c:
        c.execute(text("select pg_terminate_backend(pid) from pg_stat_activity where datname = :d and pid <> pg_backend_pid()"), {"d": name})
        c.execute(text(f'drop database if exists "{name}"'))
        c.execute(text(f'create database "{name}"'))
    eng.dispose()


def db_url(name: str) -> str:
    return make_url(config.DATABASE_URL).set(database=name).render_as_string(hide_password=False)


def start_instance(name: str, image: str, dbname: str) -> dict:
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    recreate_db(dbname)
    boot = ("set -e; cd /app; alembic upgrade head; (flask --app app:create_app seed || true); "
            "PYTHONPATH=/app python /opt/cenario/scenario.py; "
            "exec gunicorn -b 0.0.0.0:8000 --threads 8 --timeout 120 'app:create_app()'")
    sh(["docker", "run", "-d", "--name", name, "--network", config.DOCKER_NETWORK, "--env-file", config.APP_ENV_FILE, *SAFE_ENV,
        "-e", f"DATABASE_URL={db_url(dbname)}", "-e", "SESSION_COOKIE_SECURE=0", "-e", f"APP_BASE_URL=http://{name}:8000",
        "-v", f"{os.path.join(config.APP_DIR, 'scenario')}:/opt/cenario:ro", image, "sh", "-c", boot], timeout=120)
    deadline = time.time() + 240
    while time.time() < deadline:
        r = subprocess.run(["docker", "exec", name, "python", "-c",
                            "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8000/healthz',timeout=3).status)"],
                           capture_output=True, text=True)
        if r.returncode == 0 and "200" in r.stdout:
            data = subprocess.run(["docker", "exec", name, "cat", "/tmp/cenario.json"], capture_output=True, text=True).stdout
            return {"name": name, "base": f"http://{name}:8000", "ids": json.loads(data)}
        state = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", name], capture_output=True, text=True).stdout.strip()
        if state != "true":
            logs = subprocess.run(["docker", "logs", "--tail", "40", name], capture_output=True, text=True)
            raise RuntimeError(f"instância {name} não subiu: {(logs.stdout + logs.stderr)[-800:]}")
        time.sleep(3)
    raise RuntimeError(f"instância {name} não respondeu a tempo")


def stop_instance(inst: dict | None):
    if inst:
        subprocess.run(["docker", "rm", "-f", inst["name"]], capture_output=True)


def login_link(inst: dict, email: str) -> str:
    out = sh(["docker", "exec", inst["name"], "flask", "--app", "app:create_app", "admin", "login-link", "--email", email], timeout=60).stdout
    return out.strip().splitlines()[-1]


def _fmt(path: str, ids: dict) -> str:
    return path.format(tenant=ids.get("tenant_id", 1), source=ids.get("source_id", 1), destination=ids.get("destination_id", 1),
                       parser=ids.get("parser_id", 1))


# ---------------- navegador
@dataclass
class VisualResult:
    ok: bool
    problems: list[str] = field(default_factory=list)
    shots: list[dict] = field(default_factory=list)  # {titulo, antes, depois}
    checked: int = 0


def _login(browser, inst, email):
    ctx = browser.new_context(locale="pt-BR", timezone_id="America/Sao_Paulo", viewport={"width": 1440, "height": 900})
    page = ctx.new_page()
    page.goto(login_link(inst, email))
    page.get_by_role("button", name=re.compile("Entrar")).click()
    page.wait_for_load_state("networkidle")
    return ctx, page


def _visit(page, url, errs):
    errs.clear()
    resp = page.goto(url, wait_until="networkidle")
    return resp.status if resp else 0


def visual_check(base: dict | None, cand: dict, pages: list[str], emails: list[str], out_dir: str) -> VisualResult:
    from playwright.sync_api import sync_playwright
    os.makedirs(out_dir, exist_ok=True)
    res = VisualResult(ok=True)
    ids = cand["ids"]
    admin_pages = [p for p in dict.fromkeys(ADMIN_PAGES + [p for p in pages if (p.startswith("/admin") or p.startswith("/auth")) and p != "/auth/login"])]
    tenant_pages = [p for p in dict.fromkeys(TENANT_PAGES + [p for p in pages if p.startswith("/t")])]
    email_pages = [EMAIL_PAGES[e] for e in emails if e in EMAIL_PAGES]
    shot_targets = [("anonimo", p) for p in pages if p == "/auth/login"] + \
                   [("admin", p) for p in pages if p.startswith(("/admin", "/auth")) and p != "/auth/login"] + [("gestor", p) for p in pages if p.startswith("/t")] + \
                   [("admin", EMAIL_PAGES[e]) for e in emails if e in EMAIL_PAGES]
    shot_targets = shot_targets[:5]
    with sync_playwright() as p:
        browser = p.chromium.launch()
        sessions = {}
        for who, email in (("admin", "verificador@exemplo.com.br"), ("gestor", "gestor.verificador@exemplo.com.br")):
            ctx, page = _login(browser, cand, email)
            errs: list[str] = []
            page.on("console", lambda m, e=errs: e.append(m.text) if m.type == "error" else None)
            page.on("pageerror", lambda ex, e=errs: e.append(str(ex)))
            sessions[who] = (ctx, page, errs)
        # telas públicas (login): contexto sem sessão, também verificadas nos dois temas e larguras
        anon_ctx = browser.new_context(locale="pt-BR", viewport={"width": 1440, "height": 900})
        anon_page = anon_ctx.new_page()
        anon_errs: list[str] = []
        anon_page.on("console", lambda m: anon_errs.append(m.text) if m.type == "error" else None)
        sessions["anonimo"] = (anon_ctx, anon_page, anon_errs)
        base_sessions = {}
        if base:
            for who, email in (("admin", "verificador@exemplo.com.br"), ("gestor", "gestor.verificador@exemplo.com.br")):
                base_sessions[who] = _login(browser, base, email)
            bctx = browser.new_context(locale="pt-BR", viewport={"width": 1440, "height": 900})
            base_sessions["anonimo"] = (bctx, bctx.new_page())
        # checagens completas no candidato
        for who, plist in (("admin", admin_pages + email_pages), ("gestor", tenant_pages), ("anonimo", ["/auth/login"])):
            ctx, page, errs = sessions[who]
            for theme in ("light", "dark"):
                for width in (1440, 390):
                    page.set_viewport_size({"width": width, "height": 900})
                    for raw_path in plist:
                        path = _fmt(raw_path, ids)
                        status = _visit(page, cand["base"] + path, errs)
                        page.evaluate(f"document.documentElement.setAttribute('data-theme','{theme}')")
                        res.checked += 1
                        is_email = raw_path in EMAIL_PAGES.values()
                        if status >= 400:
                            base_status = 0
                            if base:
                                bpage = base_sessions[who][1]
                                bresp = bpage.goto(base["base"] + _fmt(raw_path, base["ids"]))
                                base_status = bresp.status if bresp else 0
                            if not (base and base_status >= 400):  # página que já não existia antes não é regressão
                                res.problems.append(f"{path} [{theme} {width}px]: HTTP {status}")
                            continue
                        html = page.content()
                        if ARTIFACT_RX.search(html):
                            res.problems.append(f"{path}: conteúdo indevido na página (erro de template ou marca proibida)")
                        real_errs = [e for e in errs if "favicon" not in e]
                        if real_errs:
                            res.problems.append(f"{path} [{theme} {width}px]: erro no navegador: {real_errs[0][:160]}")
                        if not is_email:
                            overflow = page.evaluate("document.documentElement.scrollWidth - window.innerWidth")
                            if overflow > 1:
                                res.problems.append(f"{path} [{theme} {width}px]: rolagem horizontal de {overflow}px")
                        elif theme == "light" and width == 1440 and raw_path == EMAIL_PAGES["alerta"]:
                            size = len(html.encode())
                            if size > GMAIL_LIMIT:
                                res.problems.append(f"e-mail de alerta com {size // 1024} KB (limite do Gmail ~100 KB)")
        # capturas antes/depois (claro, 1440 px)
        for i, (who, raw_path) in enumerate(shot_targets):
            item = {"titulo": raw_path.split("?")[0], "antes": None, "depois": None}
            for label, inst, sess in (("antes", base, base_sessions.get(who) if base else None), ("depois", cand, sessions[who][:2])):
                if not inst or not sess:
                    continue
                page = sess[1]
                page.set_viewport_size({"width": 1440, "height": 900})
                resp = page.goto(inst["base"] + _fmt(raw_path, inst["ids"]), wait_until="networkidle")
                if not resp or resp.status >= 400:
                    continue
                page.evaluate("document.documentElement.setAttribute('data-theme','light')")
                fn = os.path.join(out_dir, f"captura-{i + 1}-{label}.png")
                page.screenshot(path=fn, full_page=True, clip=None)
                item[label] = fn
            if item["depois"]:
                res.shots.append(item)
        browser.close()
    res.problems = list(dict.fromkeys(res.problems))[:40]
    res.ok = not res.problems
    return res


def capture_pages(inst: dict, targets: list[tuple[str, str]], out_dir: str) -> list[str]:
    """Capturas simples (claro, 1440×900) de telas de exemplo para respostas de suporte. targets: [(admin|gestor, caminho)]."""
    from playwright.sync_api import sync_playwright
    os.makedirs(out_dir, exist_ok=True)
    files = []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        sessions = {}
        for i, (who, raw_path) in enumerate(targets):
            if who not in sessions:
                sessions[who] = _login(browser, inst, "verificador@exemplo.com.br" if who == "admin" else "gestor.verificador@exemplo.com.br")
            page = sessions[who][1]
            resp = page.goto(inst["base"] + _fmt(raw_path, inst["ids"]), wait_until="networkidle")
            if not resp or resp.status >= 400:
                continue
            page.evaluate("document.documentElement.setAttribute('data-theme','light')")
            fn = os.path.join(out_dir, f"tela-{i + 1}.png")
            page.screenshot(path=fn)
            files.append(fn)
        browser.close()
    return files


def shrink(path: str, width: int = 680, max_height: int = 1500) -> bytes:
    """Reduz a captura para caber no e-mail (largura 680 px, altura máx. 1500 px)."""
    from io import BytesIO

    from PIL import Image
    im = Image.open(path).convert("RGB")
    ratio = width / im.width
    im = im.resize((width, int(im.height * ratio)))
    if im.height > max_height:
        im = im.crop((0, 0, width, max_height))
    buf = BytesIO()
    im.save(buf, format="PNG", optimize=True)
    return buf.getvalue()
