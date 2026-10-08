"""Base dos testes: banco PostgreSQL descartável (trustparser_test), app de teste e fábricas."""
from __future__ import annotations

import os
import re
from datetime import timedelta

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

BASE_URL = os.environ["DATABASE_URL"]
TEST_DB = os.environ.get("PORTAL_TEST_DB", "trustparser_test")
TEST_URL = make_url(BASE_URL).set(database=TEST_DB).render_as_string(hide_password=False)


def _recreate_database():
    admin = create_engine(make_url(BASE_URL).set(database="postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as c:
        c.execute(text(f"select pg_terminate_backend(pid) from pg_stat_activity where datname = '{TEST_DB}' and pid <> pg_backend_pid()"))
        c.execute(text(f"drop database if exists {TEST_DB}"))
        c.execute(text(f"create database {TEST_DB}"))
    admin.dispose()


@pytest.fixture(scope="session")
def app():
    _recreate_database()
    os.environ["DATABASE_URL"] = TEST_URL
    from alembic import command
    from alembic.config import Config as AlembicConfig
    cfg = AlembicConfig(os.path.join(os.path.dirname(os.path.dirname(__file__)), "alembic.ini"))
    command.upgrade(cfg, "head")
    from app import create_app
    from app.config import TestConfig
    TestConfig.DATABASE_URL = TEST_URL
    TestConfig.SECRET_KEY = "test-secret-key-" + "x" * 32
    import base64
    TestConfig.SECRETS_KEY = base64.b64encode(b"k" * 32).decode()
    TestConfig.AI_ENABLED = os.environ.get("AI_ENABLED_TESTS", "0") == "1"
    application = create_app(TestConfig)
    yield application
    os.environ["DATABASE_URL"] = BASE_URL


TABLES = ["api_idempotency", "api_usage_daily", "api_keys", "event_deliveries", "events", "uploads", "studio_jobs", "metrics_minute",
          "destinations", "allowed_ips", "sources", "deliveries", "magic_links", "audit_log", "users", "tenants", "settings",
          "eva_attachments", "eva_messages", "eva_requests", "eva_threads"]


@pytest.fixture(autouse=True)
def clean_db(app):
    from app import db
    from app.web.limiter import limiter
    with app.app_context():
        db.Session.remove()
        with db.engine.begin() as c:
            c.execute(text("truncate " + ", ".join(TABLES) + " restart identity cascade"))
            c.execute(text("delete from eva_whitelist"))
        from app.services import catalog, eva_admin
        catalog.seed()
        eva_admin.ensure_initial()
        from app.services import settings
        settings.set_("require_mfa_admin", False)
        db.Session.commit()
        db.Session.remove()
    limiter.reset()
    yield
    with app.app_context():
        db.Session.remove()


@pytest.fixture
def ctx(app):
    with app.app_context():
        yield
        from app import db
        db.Session.remove()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def no_smtp(monkeypatch):
    """Captura envios sem SMTP real."""
    sent = []
    from app.services import mailer

    def fake_send(msg):
        sent.append(msg)
        return "250 OK (teste)"
    monkeypatch.setattr(mailer, "send_now", fake_send)
    return sent


# ------------------------------------------------------------------ fábricas
class F:
    def __init__(self, app):
        self.app = app

    def s(self):
        from app import db
        return db.Session

    def tenant(self, name="Cliente A", status="active"):
        from app.models import Tenant
        s = self.s()
        t = Tenant(name=name, status=status)
        s.add(t)
        s.commit()
        return t

    def user(self, email, role="admin", tenant=None, status="active", totp=False):
        from app.models import User
        s = self.s()
        u = User(email=email.lower(), name=email.split("@")[0], role=role, tenant_id=tenant.id if tenant else None, status=status)
        if totp:
            import pyotp
            u.totp_secret, u.totp_enabled = pyotp.random_base32(), True
        s.add(u)
        s.commit()
        return u

    def api_key(self, perms, tenant=None, owner="rogerio.crispim@brainwalk.com.br"):
        from app.services import api_keys
        k, secret = api_keys.create(name="teste", owner_email=owner, tenant_id=tenant.id if tenant else None, permissions=perms,
                                    allowed_ips=["127.0.0.1/32"], created_by="teste")
        self.s().commit()
        return {"Authorization": f"Bearer {secret}", "X-Real-IP": "127.0.0.1"}


@pytest.fixture
def f(app, ctx):
    """Fábrica com app context aberto durante o teste (testes de unidade)."""
    return F(app)


@pytest.fixture
def fx(app):
    """Fábrica para testes HTTP: sem app context persistente (evita g/current_user compartilhado entre requisições)."""
    return F(app)


CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


def csrf_from(client, path):
    r = client.get(path)
    m = CSRF_RE.search(r.get_data(as_text=True))
    assert m, f"sem token CSRF em {path} (status {r.status_code})"
    return m.group(1)


def login_as(client, app, user):
    """Login real pelo fluxo de magic link (token gerado pelo serviço, consumido pela rota)."""
    from app import db
    from app.services import auth
    with app.app_context():
        u = db.Session.get(type(user), user.id)
        token = auth.create_magic_link(u, "login", 15)
        db.Session.commit()
    tok = csrf_from(client, f"/auth/l/{token}")
    r = client.post(f"/auth/l/{token}", data={"csrf_token": tok})
    assert r.status_code == 302, r.get_data(as_text=True)[:300]
    return r


@pytest.fixture
def login(client, app):
    return lambda user: login_as(client, app, user)


@pytest.fixture
def csrf(client):
    return lambda path="/auth/login": csrf_from(client, path)
