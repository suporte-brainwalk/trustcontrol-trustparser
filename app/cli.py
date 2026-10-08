"""Comandos de linha (flask --app app:create_app <comando>)."""
from __future__ import annotations

import json
import os

import click
from sqlalchemy import select

from .db import Session
from .models import Tenant, User
from .services import audit


def register_cli(app):
    @app.cli.command("seed")
    def seed():
        """Garante parsers embutidos, formatos nativos e o tenant interno Trust Control (idempotente)."""
        from .services import catalog
        r = catalog.seed()
        if Session.execute(select(Tenant.id)).first() is None:
            Session.add(Tenant(name="Trust Control", segment="Interno", internal=True))
        from .services import eva_admin
        eva_admin.ensure_initial()
        audit.log("system.seed", json.dumps(r))
        Session.commit()
        click.echo(f"parsers/formatos criados: {r['created']} · atualizados: {r['updated']}")

    @app.cli.command("worker")
    def worker():
        """Laços de parsing, entrega, conectores, Estúdio IA e expurgo."""
        from .worker import run
        run(app)

    @app.cli.command("parse-loop")
    def parse_loop():
        """Processo extra de parsing (o worker também parseia; vários processos dividem a fila com SKIP LOCKED)."""
        import signal
        import time
        from . import db
        from .engine import pipeline
        stop = {"v": False}
        signal.signal(signal.SIGTERM, lambda *_: stop.update(v=True))
        last = time.monotonic()
        while not stop["v"]:
            try:
                n = pipeline.process_received()
                if time.monotonic() - last > 30:
                    pipeline.metrics.flush()
                    db.Session.commit()
                    last = time.monotonic()
            except Exception:  # noqa: BLE001
                db.Session.rollback()
                n = 0
                time.sleep(2)
            finally:
                db.Session.remove()
            if not n:
                time.sleep(1.0)

    @app.cli.command("fw-export")
    def fw_export():
        """Estado desejado do firewall do syslog (JSON) — lido pelo trustparser-fw no host."""
        from .services import sources
        click.echo(json.dumps(sources.firewall_state()))

    @app.cli.command("fw-applied")
    @click.option("--hash", "h", required=True)
    @click.option("--ok/--fail", default=True)
    @click.option("--message", default="")
    def fw_applied(h, ok, message):
        """Registra o resultado da aplicação do firewall (mostrado na tela)."""
        from .db import utcnow
        from .services import settings
        settings.set_("fw_status", {"hash": h, "ok": ok, "message": message[:500], "at": utcnow().isoformat()})
        Session.commit()

    @app.cli.command("parser-test")
    @click.argument("slug")
    @click.argument("path", type=click.Path(exists=True))
    def parser_test(slug, path):
        """Mede a cobertura de um parser publicado sobre um arquivo de amostras."""
        from .models import Parser, ParserVersion
        from .services import catalog
        p = Session.execute(select(Parser).where(Parser.slug == slug)).scalar_one()
        v = Session.get(ParserVersion, p.current_version_id)
        with open(path, encoding="utf-8", errors="replace") as f:
            cov = catalog.coverage(v.spec, f.read().splitlines())
        cov.pop("examples", None)
        click.echo(json.dumps(cov, ensure_ascii=False, indent=1))

    @app.cli.group("admin")
    def admin_grp():
        """Administração de emergência."""

    @admin_grp.command("create")
    @click.option("--email", required=True)
    @click.option("--name", default="")
    def admin_create(email, name):
        """Cria ou reativa um administrador (recuperação de acesso). O acesso é feito por magic link."""
        email = email.strip().lower()
        u = Session.execute(select(User).where(User.email == email)).scalar_one_or_none()
        if u is None:
            u = User(email=email, name=name or email.split("@")[0], role="admin", status="active")
            Session.add(u)
            action = "admin.recovery_created"
        else:
            u.role, u.tenant_id, u.status = "admin", None, "active"
            action = "admin.recovery_reactivated"
        audit.log(action, email, actor_label="cli")
        Session.commit()
        click.echo(f"administrador ativo: {email}")

    @admin_grp.command("revoke-sessions")
    @click.option("--email", required=True)
    def admin_revoke_sessions(email):
        """Encerra todas as sessões abertas de um usuário (ele precisa entrar de novo pelo link)."""
        from datetime import datetime, timezone
        from .services import settings as st
        u = Session.execute(select(User).where(User.email == email.strip().lower())).scalar_one_or_none()
        if u is None:
            raise click.ClickException("usuário não encontrado")
        revoked = dict(st.get("sessions_revoked") or {})
        revoked[str(u.id)] = datetime.now(timezone.utc).timestamp()
        st.set_("sessions_revoked", revoked)
        audit.log("admin.recovery_sessions_revoked", u.email, actor_label="cli")
        Session.commit()
        click.echo(f"sessões encerradas: {u.email}")

    @admin_grp.command("reset-mfa")
    @click.option("--email", required=True)
    def admin_reset_mfa(email):
        u = Session.execute(select(User).where(User.email == email.strip().lower())).scalar_one_or_none()
        if u is None:
            raise click.ClickException("usuário não encontrado")
        u.totp_enabled, u.totp_secret, u.recovery_codes = False, None, []
        audit.log("admin.recovery_mfa_reset", u.email, actor_label="cli")
        Session.commit()
        click.echo("MFA redefinido")

    @admin_grp.command("login-link")
    @click.option("--email", required=True)
    def admin_login_link(email):
        """Gera um magic link de uso único (15 min) sem enviar e-mail — acesso de emergência pelo servidor."""
        from flask import url_for
        from .services import auth as authsvc
        u = Session.execute(select(User).where(User.email == email.strip().lower())).scalar_one_or_none()
        if u is None or u.status == "suspended":
            raise click.ClickException("usuário não encontrado ou suspenso")
        token = authsvc.create_magic_link(u, "login" if u.status == "active" else "invite", app.config["MAGIC_LINK_MINUTES"], "cli")
        audit.log("admin.recovery_login_link", u.email, actor_label="cli")
        Session.commit()
        with app.test_request_context():
            click.echo(app.config["APP_BASE_URL"] + url_for("auth.magic", token=token))

    @app.cli.command("invite-admin")
    @click.option("--email", required=True)
    @click.option("--name", default="")
    @click.option("--send/--no-send", default=True)
    def invite_admin(email, name, send):
        """Convida um administrador por magic link (24 h)."""
        from .services import auth as authsvc, emails
        email = email.strip().lower()
        u = Session.execute(select(User).where(User.email == email)).scalar_one_or_none()
        if u is None:
            u = User(email=email, name=name or email.split("@")[0], role="admin", status="invited")
            Session.add(u)
            Session.flush()
        token = authsvc.create_magic_link(u, "invite" if u.status == "invited" else "login", app.config["INVITE_HOURS"] * 60, "cli")
        audit.log("admin.invited", email, actor_label="cli")
        Session.commit()
        if send:
            with app.test_request_context():
                emails.send_magic_link(u, token, "invite" if u.status == "invited" else "login")
            Session.commit()
        click.echo(f"convite {'enviado' if send else 'criado'}: {email}")

    @app.cli.command("api-chave-eva")
    @click.option("--rotacionar", "rotate", is_flag=True, default=False)
    def api_chave_eva(rotate):
        """Mesmo que eva-key (nome usado pelo orquestrador da EVA)."""
        from .services import api_keys
        k, secret = api_keys.ensure_eva_key(rotate=rotate)
        Session.commit()
        click.echo(secret or f"chave já existe (prefixo {k.prefix}); use --rotacionar para trocar o segredo")

    @app.cli.command("eva-key")
    @click.option("--rotate", is_flag=True, default=False)
    def eva_key(rotate):
        """Cria (ou rotaciona) a chave protegida de leitura da EVA e imprime o segredo uma única vez."""
        from .services import api_keys
        k, secret = api_keys.ensure_eva_key(rotate=rotate)
        Session.commit()
        click.echo(secret or f"chave já existe (prefixo {k.prefix}); use --rotate para trocar o segredo")
