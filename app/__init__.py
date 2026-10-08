"""Trust Parser — fábrica da aplicação Flask."""
from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from flask import Flask, jsonify, redirect, render_template, url_for
from flask_login import current_user
from flask_wtf.csrf import CSRFError, CSRFProtect
from sqlalchemy import text

from . import db
from .config import Config

from .security import init_security
from .services import mailer
from .web.limiter import limiter

csrf = CSRFProtect()
BRT = ZoneInfo("America/Sao_Paulo")


def fmt_dt(v, fmt="%d/%m/%Y %H:%M"):
    if not v:
        return "—"
    if isinstance(v, str):
        return v
    if v.tzinfo is None:
        v = v.replace(tzinfo=timezone.utc)
    return v.astimezone(BRT).strftime(fmt)


def _is_api() -> bool:
    from flask import request
    return request.path.startswith("/api/")


def _api_problem(code: int):
    from .api.errors import problem
    return problem(code)


def create_app(config_obj=Config) -> Flask:
    app = Flask(__name__, template_folder="web/templates", static_folder="web/static", static_url_path="/static")
    app.config.from_object(config_obj)
    if not app.config["SECRET_KEY"]:
        raise RuntimeError("SECRET_KEY não configurada")
    logging.basicConfig(level=logging.INFO, format='{"t":"%(asctime)s","lvl":"%(levelname)s","log":"%(name)s","msg":"%(message)s"}')
    logging.getLogger("httpx").setLevel(logging.WARNING)

    db.init_engine(app.config["DATABASE_URL"], pool_size=10, max_overflow=15)
    mailer.configure(app.config)
    csrf.init_app(app)
    limiter.init_app(app)
    init_security(app)

    from .web.auth import bp as auth_bp
    from .web.admin import bp as admin_bp
    from .web.tenant import bp as tenant_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(tenant_bp)
    try:  # EVA (suporte por IA): blueprint próprio
        from .web.eva import bp as eva_bp
        app.register_blueprint(eva_bp)
    except ImportError:
        pass
    from .api import init_api
    init_api(app, csrf)

    app.jinja_env.filters["dt"] = fmt_dt
    app.jinja_env.filters["d"] = lambda v: fmt_dt(v, "%d/%m/%Y")

    app.jinja_env.filters["safe_url"] = lambda u: u if isinstance(u, str) and re.match(r"^https?://", u.strip(), re.I) else "#"
    app.jinja_env.filters["safe_next"] = lambda u: u if isinstance(u, str) and u.startswith("/") and not u.startswith("//") and "\\" not in u else ""

    app.jinja_env.globals["now_year"] = lambda: datetime.now(BRT).year
    app.jinja_env.filters["num"] = lambda v: f"{int(v or 0):,}".replace(",", ".")
    app.jinja_env.filters["tojson_pretty"] = lambda v: json.dumps(v, ensure_ascii=False, indent=1, default=str)
    app.jinja_env.globals["has_endpoint"] = lambda name: name in app.view_functions

    @app.teardown_appcontext
    def _remove(exc=None):
        db.Session.remove()

    @app.get("/")
    def index():
        if not current_user.is_authenticated:
            return redirect(url_for("auth.login"))
        return redirect(url_for("admin.dashboard" if current_user.role == "admin" else "tenant.dashboard"))

    @app.get("/healthz")
    def healthz():
        try:
            db.Session.execute(text("select 1"))
            hb = db.Session.execute(text("select value, updated_at from settings where key='worker_heartbeat'")).first()
            worker_age = None
            if hb:
                worker_age = int((datetime.now(timezone.utc) - hb.updated_at).total_seconds())
            return jsonify(status="ok", db="ok", worker_heartbeat_age_s=worker_age)
        except Exception as e:  # noqa: BLE001
            return jsonify(status="error", error=str(e)[:200]), 503

    @app.errorhandler(CSRFError)
    def _csrf(e):
        return render_template("error.html", code=400, title="Sessão expirada",
                               message="O formulário expirou. Recarregue a página e tente novamente."), 400

    for code, title, msg in ((403, "Acesso negado", "Você não tem permissão para acessar esta página."),
                             (404, "Página não encontrada", "O endereço não existe ou não está disponível para você."),
                             (429, "Muitas tentativas", "Aguarde alguns minutos e tente novamente."),
                             (500, "Erro interno", "Algo deu errado. A equipe foi registrada para análise.")):
        app.register_error_handler(code, (lambda c, t, m: (lambda e: _api_problem(c) if _is_api() else (render_template("error.html", code=c, title=t, message=m), c)))(code, title, msg))
    app.register_error_handler(405, lambda e: _api_problem(405) if _is_api() else e)
    app.register_error_handler(413, lambda e: _api_problem(413) if _is_api() else e)

    from .cli import register_cli
    register_cli(app)
    return app
