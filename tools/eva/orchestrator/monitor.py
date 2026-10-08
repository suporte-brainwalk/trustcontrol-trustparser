"""Heartbeat e verificações determinísticas; avisos operacionais com limite de 1 por tipo a cada 6 h."""
from __future__ import annotations

import html
import logging
import re
import shutil
from datetime import datetime, timedelta, timezone

from . import config, openrouter, outbox, store

log = logging.getLogger("eva.monitor")
_KEY_CACHE: dict = {"at": None, "st": None}
STATE = {"poller_at": None, "worker_at": None, "imap_ok": None, "imap_failures": 0, "busy_since": None, "busy_request": None}


def alert(kind: str, message: str, *, every_hours: int = 6) -> bool:
    from .policy import AI_VENDOR_NAMES
    message = re.sub(AI_VENDOR_NAMES, "IA", message)  # avisos também não citam fabricantes/modelos de IA
    now = datetime.now(timezone.utc)
    sent = store.get_setting("eva_alertas", {}) or {}
    last = sent.get(kind)
    if last and now - datetime.fromisoformat(last) < timedelta(hours=every_hours):
        return False
    body = ('<div style="font-family:Arial,sans-serif;font-size:14px;line-height:1.6;color:#1f2d3d;max-width:620px">'
            '<p style="color:#c0392b;font-weight:700;margin:0">Aviso automático da EVA (Trust Parser)</p>'
            f'<p>{html.escape(message)}</p>'
            f'<p style="color:#566573;font-size:12px">Painel: {html.escape(config.PORTAL_URL)}/admin/eva · tipo: {html.escape(kind)}</p></div>')
    try:
        msg = outbox.build(to=[config.ALERT_TO], cc=[], subject=f"[EVA] Atenção: {message[:90]}", html_body=body, text_body=message,
                           inline=[], in_reply_to=None, references=[], request_id=None)
        outbox.smtp_send(msg)  # aviso de sistema: nunca faz parte de uma conversa
    except Exception:  # noqa: BLE001
        log.exception("não foi possível enviar aviso %s", kind)
        return False
    sent[kind] = now.isoformat()
    store.set_setting("eva_alertas", sent)
    store.audit("eva.aviso_operacional", kind, {"mensagem": message[:500]})
    return True


def heartbeat(mailbox) -> dict:  # noqa: ARG001
    now = datetime.now(timezone.utc)
    if not config.openrouter_key():
        key = {"ok": False, "erro": "chave ausente"}
    elif _KEY_CACHE["at"] and now - _KEY_CACHE["at"] < timedelta(minutes=5) and _KEY_CACHE["st"].get("ok"):
        key = _KEY_CACHE["st"]  # situação da chave consultada no máximo a cada 5 min (falha: tenta de novo já)
    else:
        key = openrouter.key_status()
        _KEY_CACHE.update(at=now, st=key)
    auth_ok = bool(key.get("ok"))
    smtp = outbox.smtp_ok()
    queue = store.queue_stats()
    disk = shutil.disk_usage(config.STATE_DIR)
    hb = {"at": now.isoformat(), "poller_at": STATE["poller_at"], "worker_at": STATE["worker_at"], "imap_ok": STATE["imap_ok"],
          "smtp_ok": smtp, "auth_ok": auth_ok, "ai_limit_remaining_usd": key.get("limit_remaining"),
          "fila": {k: v["n"] for k, v in queue.items()}, "modo": store.get_setting("eva_mode", "demo"),
          "disco_livre_gb": round(disk.free / 1e9, 1), "processando": STATE["busy_request"]}
    store.set_setting("eva_heartbeat", hb)
    if not auth_ok:
        alert("ia_acesso", "O acesso da EVA ao serviço de IA falhou (chave ausente, inválida ou serviço indisponível). "
                           "A EVA não consegue atender pedidos até isso ser resolvido (ver docs/eva.md, Operação).")
    rem = key.get("limit_remaining")
    if auth_ok and isinstance(rem, (int, float)) and rem < config.AI_KEY_MIN_USD:
        alert("ia_saldo", f"O limite de gasto da chave de IA da EVA está quase no fim (restam US$ {rem:.2f}). "
                          "Aumente o limite da chave dedicada ou aguarde a renovação mensal.")
    if STATE["imap_failures"] >= 5:
        alert("imap", "A EVA não consegue ler a caixa de e-mail há alguns minutos.")
    if not smtp:
        alert("smtp", "A EVA não consegue enviar e-mails (servidor SMTP sem resposta).")
    if STATE["busy_since"] and now - STATE["busy_since"] > timedelta(minutes=75):
        alert("travado", f"O pedido nº {STATE['busy_request']} está em execução há mais de 75 minutos.")
    queued = queue.get("queued")
    if queued and queued["oldest"] and now - queued["oldest"] > timedelta(minutes=90):
        alert("fila", f"Há {queued['n']} pedido(s) aguardando há mais de 90 minutos.")
    if disk.free < 3e9:
        alert("disco", f"Pouco espaço em disco para a EVA ({disk.free / 1e9:.1f} GB livres).")
    return hb
