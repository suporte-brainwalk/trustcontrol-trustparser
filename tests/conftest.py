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
    TestConfig.AI_ENABLED = os.environ.get("AI_ENABLED_TESTS", "0") == "1"
    application = create_app(TestConfig)
    yield application
    os.environ["DATABASE_URL"] = BASE_URL


TABLES = ["api_idempotency", "api_usage_daily", "api_keys", "alert_items", "alerts", "deliveries", "vulnerability_products", "vulnerabilities", "source_seen", "source_checks",
          "source_checks_daily", "sources", "tenant_assets", "recipients", "magic_links", "audit_log", "users", "tenants",
          "products", "vendors", "newsletters", "settings", "jarbas_attachments", "jarbas_messages", "jarbas_requests", "jarbas_threads"]


@pytest.fixture(autouse=True)
def clean_db(app):
    from app import db
    from app.cli import seed_catalog
    from app.web.limiter import limiter
    with app.app_context():
        db.Session.remove()
        with db.engine.begin() as c:
            c.execute(text("truncate " + ", ".join(TABLES) + " restart identity cascade"))
            # whitelist do Jarbas: volta ao estado da implantação (os dois donos), sem o que algum teste incluiu
            c.execute(text("delete from jarbas_whitelist where added_by <> 'implantação'"))
            c.execute(text("update jarbas_whitelist set active = true, role = 'owner'"))
        seed_catalog()
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

    def tenant(self, name="Cliente A", flash_min="high", daily=True, all_vendors=False, status="active", products=()):
        from app.models import Product, Tenant, TenantAsset, Vendor
        from sqlalchemy import select
        s = self.s()
        t = Tenant(name=name, flash_min=flash_min, daily_newsletter=daily, all_vendors=all_vendors, status=status)
        s.add(t)
        s.flush()
        for vname, pname in products:
            p = s.execute(select(Product).join(Vendor).where(Vendor.name == vname, Product.name == pname)).scalar_one()
            s.add(TenantAsset(tenant_id=t.id, product_id=p.id, version="1.0"))
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

    def recipient(self, tenant, email):
        from app.models import Recipient
        s = self.s()
        r = Recipient(tenant_id=tenant.id, name=email.split("@")[0], email=email.lower())
        s.add(r)
        s.commit()
        return r

    def vendor_id(self, name):
        from app.models import Vendor
        from sqlalchemy import select
        return self.s().execute(select(Vendor.id).where(Vendor.name == name)).scalar_one()

    def vuln(self, key="CVE-2026-0001", vendor="Palo Alto Networks", title="PAN-OS: buffer overflow in GlobalProtect", severity="high",
             cvss=8.1, kev=False, cpes=(), description="", enriched=True, ai_status="pending"):
        from app.db import utcnow
        from app.models import Vulnerability
        s = self.s()
        v = Vulnerability(vuln_key=key, cve_ids=[key] if key.startswith("CVE-") else [], vendor_id=self.vendor_id(vendor), title_en=title,
                          description_en=description or title, severity=severity, cvss=cvss, kev=kev, cpes=list(cpes),
                          enriched_at=utcnow() if enriched else None, ai_status=ai_status, url="https://example.org/adv")
        s.add(v)
        s.commit()
        return v


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
