"""Avisos operacionais por e-mail (fonte parada, destino falhando, deriva de formato, buffer cheio, Estúdio).
Destinatários escolhidos em Configurações → Avisos (lista própria + administradores, se marcado)."""
from __future__ import annotations

import logging

from sqlalchemy import select

from ..db import Session
from ..models import Tenant, User
from . import emails, settings

log = logging.getLogger(__name__)


def recipients() -> list[str]:
    out = [e.strip().lower() for e in (settings.get("ops_recipients") or []) if e and "@" in e]
    if settings.get("ops_include_admins"):
        for (e,) in Session.execute(select(User.email).where(User.role == "admin", User.status == "active")):
            dest = emails.redirect_alert(e)
            if dest not in out:
                out.append(dest)
    return list(dict.fromkeys(out))


def _send(kind: str, subject: str, dedupe: str, **ctx):
    to = recipients()
    if not to:
        log.warning("aviso operacional sem destinatários: %s", subject)
        return 0
    try:
        return emails.send_system(to, f"[Trust Parser] {subject}", "email/ops_alert.html", dedupe, kind=kind, subject=subject,
                                  base_url=emails.base_url(), **ctx)
    except Exception:  # noqa: BLE001 — aviso nunca derruba o worker
        log.exception("falha ao enviar aviso operacional")
        return 0


def _tenant(tid):
    t = Session.get(Tenant, tid)
    return t.name if t else "?"


def destination_failing(d):
    _send("dest_fail", f"Destino com falha: {d.name} ({_tenant(d.tenant_id)})", f"dest:{d.id}:{d.last_error_at:%Y%m%d%H%M}",
          title="Destino de saída com falhas seguidas",
          lines=[("Tenant", _tenant(d.tenant_id)), ("Destino", d.name), ("Falhas seguidas", d.consecutive_failures), ("Último erro", d.last_error)],
          action="Os eventos ficam guardados e são reenviados automaticamente (até 24 h). Confira a configuração do destino.",
          link=f"/admin/destinos/{d.id}")


def destination_recovered(d):
    _send("dest_ok", f"Destino normalizado: {d.name} ({_tenant(d.tenant_id)})", f"destok:{d.id}:{d.last_ok_at:%Y%m%d%H%M}",
          title="Destino voltou a receber", lines=[("Tenant", _tenant(d.tenant_id)), ("Destino", d.name)],
          action="Os eventos pendentes estão sendo reenviados.", link=f"/admin/destinos/{d.id}")


def source_silent(s):
    _send("src_silent", f"Fonte sem eventos: {s.name} ({_tenant(s.tenant_id)})", f"silent:{s.id}:{s.last_event_at:%Y%m%d%H%M}",
          title="Fonte parou de enviar eventos",
          lines=[("Tenant", _tenant(s.tenant_id)), ("Fonte", s.name), ("Último evento", s.last_event_at.strftime("%d/%m/%Y %H:%M UTC")),
                 ("Limite configurado", f"{s.silence_alert_minutes} min")],
          action="Verifique o equipamento, a rede e se o IP de origem continua liberado.", link=f"/admin/fontes/{s.id}")


def drift(s, received: int, unparsed: int):
    _send("drift", f"Formato mudou? {s.name} ({_tenant(s.tenant_id)})", f"drift:{s.id}:{received}:{unparsed}",
          title="Muitas linhas não reconhecidas na última hora",
          lines=[("Tenant", _tenant(s.tenant_id)), ("Fonte", s.name), ("Recebidas (60 min)", received), ("Não reconhecidas", unparsed)],
          action="Abra “Não reconhecidos” e use “Pedir ajuste ao Estúdio IA” para gerar uma nova versão do parser.",
          link=f"/admin/nao-reconhecidos?source_id={s.id}")


def buffer_full(size_mb, cap_mb, trimmed):
    _send("buffer", "Buffer de eventos acima do limite de disco", f"buffer:{int(size_mb)}:{trimmed}",
          title="Buffer acima do limite", lines=[("Tamanho", f"{size_mb:.0f} MB"), ("Limite", f"{cap_mb:.0f} MB"), ("Eventos descartados", trimmed)],
          action="Os eventos mais antigos foram descartados. Verifique destinos com falha (eles acumulam pendências).", link="/admin/")


def studio_done(job):
    _send("studio", f"Estúdio IA: {job.title} — {('pronto para revisão' if job.status == 'done' else 'falhou')}", f"studio:{job.id}:{job.status}",
          title="Pedido do Estúdio IA concluído" if job.status == "done" else "Pedido do Estúdio IA falhou",
          lines=[("Pedido", job.title), ("Situação", job.status), ("Cobertura", f"{(job.report or {}).get('coverage', {}).get('pct', '—')}%"),
                 ("Erro", job.error or "—")],
          action="Revise o resultado e publique (só administradores publicam).", link=f"/admin/estudio/{job.id}")
