"""Processo principal da EVA: laços determinísticos de leitura da caixa, fila de pedidos, heartbeat, lembretes e acompanhamento do Estúdio IA."""
from __future__ import annotations

import logging
import os
import signal
import sys
import threading
import time
from datetime import datetime, timezone

from . import config, inbox, monitor, pipeline, store, studio_watch

logging.basicConfig(level=logging.INFO, stream=sys.stdout, format='{"t":"%(asctime)s","lvl":"%(levelname)s","log":"%(name)s","msg":"%(message)s"}')
log = logging.getLogger("eva")
STOP = threading.Event()


def loop(name, interval, fn):
    while not STOP.is_set():
        t0 = time.time()
        try:
            fn()
        except Exception:  # noqa: BLE001
            log.exception("falha no laço %s", name)
        STOP.wait(max(1.0, interval - (time.time() - t0)))


def main():
    for d in (config.STATE_DIR, config.REQUESTS_DIR, os.path.join(config.STATE_DIR, "tmp"), os.path.join(config.STATE_DIR, "state")):
        os.makedirs(d, exist_ok=True)
    store.init()
    lock = None
    while lock is None and not STOP.is_set():
        lock = store.try_lock()
        if lock is None:
            log.info("outro orquestrador ativo; aguardando")
            time.sleep(20)
    pipeline.cleanup_leftovers()
    n = store.requeue_stuck()
    if n:
        log.info("%s pedido(s) interrompido(s) voltaram para a fila", n)
    if store.get_setting("eva_mode") is None:
        store.set_setting("eva_mode", "demo")
    mailbox = inbox.Mailbox(config.IMAP_HOST, config.MAILBOX, config.MAIL_PASSWORD)

    def poll():
        try:
            pipeline.ingest(mailbox)
            monitor.STATE["imap_ok"], monitor.STATE["imap_failures"] = True, 0
        except Exception:
            monitor.STATE["imap_ok"] = False
            monitor.STATE["imap_failures"] += 1
            raise
        finally:
            monitor.STATE["poller_at"] = datetime.now(timezone.utc).isoformat()

    def work():
        monitor.STATE["worker_at"] = datetime.now(timezone.utc).isoformat()
        while not STOP.is_set():
            req_started = datetime.now(timezone.utc)
            monitor.STATE["busy_since"], monitor.STATE["busy_request"] = req_started, "…"
            try:
                if not pipeline.process_next():
                    break
            finally:
                monitor.STATE["busy_since"], monitor.STATE["busy_request"] = None, None
                monitor.STATE["worker_at"] = datetime.now(timezone.utc).isoformat()

    threads = [threading.Thread(target=loop, args=("caixa", config.POLL_SECONDS, poll), daemon=True),
               threading.Thread(target=loop, args=("fila", 5, work), daemon=True),
               threading.Thread(target=loop, args=("lembretes", 600, pipeline.reminders), daemon=True),
               threading.Thread(target=loop, args=("estudio", 120, studio_watch.tick), daemon=True)]
    for t in threads:
        t.start()
    log.info("EVA iniciada (modo %s)", store.get_setting("eva_mode"))
    loop("heartbeat", 30, lambda: monitor.heartbeat(mailbox))


def _stop(*_):
    STOP.set()


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    main()
