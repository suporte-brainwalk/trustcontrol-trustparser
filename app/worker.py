"""Worker do Trust Parser: agendador único (advisory lock do PostgreSQL).

Laços independentes (a lentidão de um não atrasa os outros):
  * pipeline (contínuo): parsing do que chegou → entregas → envio em lote aos destinos;
  * conectores (30 s): coleta das APIs com execução vencida;
  * estúdio (10 s): um pedido de IA por vez (pode levar minutos);
  * periódico: heartbeat e métricas (30 s), expurgo do buffer e saúde das fontes (60 s), aviso de chaves (diário).
"""
from __future__ import annotations

import logging
import signal
import threading
import time

from sqlalchemy import text

from . import db
from .db import utcnow
from .services import settings

log = logging.getLogger("worker")
LOCK_ID = 77031
_stop = False


def _sig(*_):
    global _stop
    _stop = True


def _in_ctx(app, fn, *a):
    with app.app_context():
        try:
            return fn(*a)
        except Exception:  # noqa: BLE001
            log.exception("falha em %s", getattr(fn, "__name__", fn))
            db.Session.rollback()
            return None
        finally:
            db.Session.remove()


def pipeline_tick(app):
    from .engine import pipeline

    def work():
        n = pipeline.process_received()
        while n >= pipeline.PARSE_BATCH and not _stop:
            n = pipeline.process_received()
        sent = pipeline.deliver_all()
        return n, sent
    res = _in_ctx(app, work)
    if not res or (res[0] == 0 and res[1] == 0):
        time.sleep(1.0)


def connectors_tick(app):
    from .engine import collect
    _in_ctx(app, collect.run_due)
    time.sleep(30)


def studio_tick(app):
    from .engine import studio
    did = _in_ctx(app, studio.run_next)
    if not did:
        time.sleep(10)


def periodic_tick(app, state: dict):
    from .engine import pipeline
    now = time.monotonic()
    if now - state.get("hb", 0) >= 30:
        state["hb"] = now
        if state.get("lock_conn") is not None:
            check_lock(app, state)

        def hb():
            pipeline.metrics.flush()
            settings.set_("worker_heartbeat", {"at": utcnow().isoformat()})
            db.Session.commit()
        _in_ctx(app, hb)
    if now - state.get("purge", 0) >= 60:
        state["purge"] = now
        _in_ctx(app, pipeline.purge)
        _in_ctx(app, pipeline.check_sources)
    if now - state.get("keys", 0) >= 86400:
        state["keys"] = now
        from .services import api_keys
        _in_ctx(app, api_keys.notify_expiring)
    time.sleep(2)


def _acquire_lock(wait: bool):
    """Conexão dedicada segurando o advisory lock (garante um único worker)."""
    while True:
        try:
            conn = db.engine.connect()
            got = conn.execute(text("select pg_try_advisory_lock(:k)"), {"k": LOCK_ID}).scalar()
            conn.commit()
            if got:
                return conn
            conn.close()
            log.info("outro worker detém o lock; aguardando")
        except Exception:  # noqa: BLE001
            log.exception("banco indisponível ao obter o lock")
        if not wait or _stop:
            return None
        time.sleep(15)


def _release(conn):
    """Libera o lock e descarta a conexão (close() devolveria ao pool com o lock de sessão ainda preso)."""
    if conn is None:
        return
    try:
        conn.execute(text("select pg_advisory_unlock(:k)"), {"k": LOCK_ID})
        conn.commit()
    except Exception:  # noqa: BLE001
        pass
    try:
        conn.invalidate()
    except Exception:  # noqa: BLE001
        pass


def check_lock(app, state: dict):
    """A cada 30 s confirma que a conexão do lock segue viva; após queda do banco, readquire ou encerra."""
    global _stop
    conn = state.get("lock_conn")
    try:
        held = conn.execute(text("select count(*) from pg_locks where locktype = 'advisory' and objid = :k and pid = pg_backend_pid()"),
                            {"k": LOCK_ID}).scalar()
        conn.commit()
        if held:
            return
    except Exception:  # noqa: BLE001
        pass
    log.warning("lock do worker perdido (queda do banco?); tentando readquirir")
    _release(conn)
    with app.app_context():
        new = _acquire_lock(wait=False)
    if new is None:
        log.error("não foi possível readquirir o lock; encerrando para o supervisord reiniciar")
        _stop = True
    else:
        state["lock_conn"] = new
        log.info("lock do worker readquirido")


def _loop(name, state, fn):
    """Repete fn até o encerramento; cada fn controla a própria espera (pipeline roda quase contínuo)."""
    while not _stop:
        try:
            fn()
        except Exception:  # noqa: BLE001
            log.exception("falha no ciclo %s", name)
            time.sleep(2)
        state.setdefault("threads", {})[name] = utcnow().isoformat()


def run(app):
    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)
    if not app.config.get("SCHEDULER_ENABLED", True):
        log.info("agendador desabilitado")
        return
    with app.app_context():
        conn = _acquire_lock(wait=True)
        if conn is None:
            return
        log.info("worker iniciado (lock %s obtido)", LOCK_ID)
    state: dict = {"lock_conn": conn}
    threads = [threading.Thread(target=_loop, name="pipeline-loop", args=("pipeline", state, lambda: pipeline_tick(app)), daemon=True),
               threading.Thread(target=_loop, name="connectors-loop", args=("connectors", state, lambda: connectors_tick(app)), daemon=True),
               threading.Thread(target=_loop, name="studio-loop", args=("studio", state, lambda: studio_tick(app)), daemon=True)]
    for t in threads:
        t.start()
    _loop("periodic", state, lambda: periodic_tick(app, state))
    for t in threads:
        t.join(timeout=60)
    _release(state.get("lock_conn"))
    log.info("worker encerrado")
