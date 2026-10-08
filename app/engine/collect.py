"""Coleta dos conectores de API (pull): executa as fontes vencidas, grava as linhas no buffer e avança o cursor."""
from __future__ import annotations

import logging
from datetime import timedelta

from sqlalchemy import or_, select

from ..db import Session, utcnow
from ..models import Event, Source, Tenant
from ..services import ops_alerts, secrets_box

log = logging.getLogger(__name__)


def run_source(s: Source) -> tuple[bool, str, int]:
    from . import connectors
    try:
        c = connectors.get(s.connector)
    except connectors.ConnectorError as e:
        return False, str(e), 0
    try:
        sec = secrets_box.open_(s.secret_enc, f"source:{s.id}")
    except secrets_box.SecretsError as e:
        return False, str(e), 0
    try:
        res = c.pull(s.connector_config or {}, sec, dict(s.cursor or {}))
    except connectors.ConnectorError as e:
        return False, str(e), 0
    now = utcnow()
    for ln in res.lines:
        Session.add(Event(tenant_id=s.tenant_id, source_id=s.id, received_at=now, transport="api", peer_ip=c.vendor[:64], raw=ln))
    s.cursor = res.cursor or {}
    return True, res.note or f"{len(res.lines)} evento(s) coletado(s)", (1 if res.more else 0)


def run_due() -> int:
    now = utcnow()
    ids = [i for (i,) in Session.execute(select(Source.id).join(Tenant, Tenant.id == Source.tenant_id)
                                         .where(Source.transport == "api", Source.active.is_(True), Source.connector != "",
                                                Tenant.status == "active", or_(Source.next_run_at.is_(None), Source.next_run_at <= now))
                                         .order_by(Source.next_run_at.nulls_first()).limit(20))]
    done = 0
    for sid in ids:
        s = Session.get(Source, sid)
        ok, msg, more = False, "", 0
        try:
            ok, msg, more = run_source(s)
        except Exception as e:  # noqa: BLE001
            log.exception("conector %s falhou", sid)
            Session.rollback()
            s = Session.get(Source, sid)
            msg = f"erro interno: {str(e)[:300]}"
        s.last_run_at = utcnow()
        if ok:
            if s.consecutive_failures >= 5 and s.alerted_at:
                s.alerted_at = None
            s.last_status, s.last_error, s.consecutive_failures = "ok", msg[:1000], 0
            s.next_run_at = utcnow() + (timedelta(seconds=5) if more else timedelta(seconds=s.interval_s))
        else:
            s.last_status, s.last_error = "err", msg[:1000]
            s.consecutive_failures += 1
            s.next_run_at = utcnow() + timedelta(seconds=min(3600, s.interval_s * (2 ** min(s.consecutive_failures, 4))))
            if s.consecutive_failures >= 5 and s.alerted_at is None:
                ops_alerts._send("connector", f"Conector com falha: {s.name}", f"conn:{s.id}:{s.consecutive_failures // 5}",
                                 title="Conector de API falhando", lines=[("Fonte", s.name), ("Conector", s.connector),
                                                                           ("Falhas seguidas", s.consecutive_failures), ("Erro", msg)],
                                 action="Confira as credenciais e permissões na fonte.", link=f"/admin/fontes/{s.id}")
                s.alerted_at = utcnow()
        Session.commit()
        done += 1
    return done
