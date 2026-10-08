"""Cenário de dados para as instâncias de verificação (antes/depois) da EVA. Roda dentro do container do Trust Parser.

Cria: administrador e gestor verificadores, um tenant de verificação com uma fonte syslog, um IP liberado e um destino
(sem credencial), e grava /tmp/cenario.json com os identificadores usados nas capturas. Idempotente.
Usa só o modelo de dados (sem serviços), para não depender de regras que mudam com o produto.
"""
import json

from sqlalchemy import select

from app import create_app, db
from app.models import AllowedIP, Destination, Parser, Source, Tenant, User
from app.services import settings

app = create_app()
with app.app_context():
    s = db.Session
    settings.set_("require_mfa_admin", False)
    t = s.execute(select(Tenant).where(Tenant.name == "Cliente Verificação EVA")).scalar_one_or_none()
    if t is None:
        t = Tenant(name="Cliente Verificação EVA", segment="Verificação", demo=True)
        s.add(t)
        s.flush()
    if not s.execute(select(User).where(User.email == "verificador@exemplo.com.br")).scalar_one_or_none():
        s.add(User(email="verificador@exemplo.com.br", name="Verificador", role="admin", status="active"))
    if not s.execute(select(User).where(User.email == "gestor.verificador@exemplo.com.br")).scalar_one_or_none():
        s.add(User(email="gestor.verificador@exemplo.com.br", name="Gestor Verificador", role="manager", tenant_id=t.id, status="active"))
    parser = s.execute(select(Parser).where(Parser.kind == "input").order_by(Parser.id)).scalars().first()
    src = s.execute(select(Source).where(Source.tenant_id == t.id, Source.name == "Firewall de verificação")).scalar_one_or_none()
    if src is None:
        src = Source(tenant_id=t.id, name="Firewall de verificação", transport="syslog", parser_id=parser.id if parser else None)
        s.add(src)
        s.flush()
    if not s.execute(select(AllowedIP).where(AllowedIP.source_id == src.id)).first():
        s.add(AllowedIP(tenant_id=t.id, source_id=src.id, cidr="203.0.113.10/32", protocols=["tls"], description="verificação"))
    dst = s.execute(select(Destination).where(Destination.tenant_id == t.id, Destination.name == "Wazuh de verificação")).scalar_one_or_none()
    if dst is None:
        dst = Destination(tenant_id=t.id, name="Wazuh de verificação", kind="wazuh", format="wazuh_json",
                          config={"host": "wazuh.exemplo.invalid", "port": 6514, "transport": "tls"}, active=False)
        s.add(dst)
        s.flush()
    s.commit()
    out = {"tenant_id": t.id, "source_id": src.id, "destination_id": dst.id, "parser_id": parser.id if parser else 1}
    json.dump(out, open("/tmp/cenario.json", "w"))
    print(json.dumps(out))
