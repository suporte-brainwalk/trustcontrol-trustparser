"""Processamento contínuo (worker): parsing do que chegou, roteamento para destinos, envio em lote com retentativa,
expurgo do buffer (2 h; até 24 h se não entregue), métricas por minuto e avisos operacionais."""
from __future__ import annotations

import logging
import re
import time
from collections import defaultdict
from datetime import timedelta

from sqlalchemy import delete, func, select, text, update

from ..db import Session, utcnow
from ..models import Destination, Event, EventDelivery, Source, Tenant, Upload
from ..services import catalog, ops_alerts, secrets_box, settings
from . import dsl, formats, senders

log = logging.getLogger(__name__)
PARSE_BATCH = 1000
DELIVER_ROUNDS = 5


# ------------------------------------------------------------------------------------------------ métricas
class Metrics:
    def __init__(self):
        self.src = defaultdict(lambda: [0, 0, 0])  # recebidos, parseados, não reconhecidos
        self.dst = defaultdict(lambda: [0, 0, 0])  # enviados, falhas, descartados

    def flush(self):
        if not self.src and not self.dst:
            return
        minute = utcnow().replace(second=0, microsecond=0)
        for kind, data in (("s", self.src), ("d", self.dst)):
            for ref, (a, b, c) in data.items():
                Session.execute(text("""insert into metrics_minute (minute, kind, ref_id, a, b, c) values (:m, :k, :r, :a, :b, :c)
                    on conflict (minute, kind, ref_id) do update set a = metrics_minute.a + :a, b = metrics_minute.b + :b,
                    c = metrics_minute.c + :c"""), {"m": minute, "k": kind, "r": ref or 0, "a": a, "b": b, "c": c})
        self.src.clear()
        self.dst.clear()


metrics = Metrics()


# ------------------------------------------------------------------------------------------------ roteamento
def _dest_index() -> dict[int, list[Destination]]:
    out = defaultdict(list)
    for d in Session.execute(select(Destination).where(Destination.active.is_(True))).scalars():
        out[d.tenant_id].append(d)
    return out


def _passes(d: Destination, ev: Event) -> bool:
    f = d.filters or {}
    if f.get("source_ids") and ev.source_id not in f["source_ids"]:
        return False
    if ev.status == "unparsed":
        return d.include_unparsed
    e = ev.event or {}
    if f.get("min_severity_id") and int(e.get("severity_id") or 0) < int(f["min_severity_id"]):
        return False
    if f.get("class_uids") and e.get("class_uid") not in f["class_uids"]:
        return False
    return True


_source_cache: dict = {}


def _source(sid):
    if sid is None:
        return None
    s = _source_cache.get(sid)
    if s is None or time.monotonic() - s[1] > 20:
        obj = Session.get(Source, sid)
        _source_cache[sid] = s = (obj, time.monotonic())
    return s[0]


def process_received(limit: int = PARSE_BATCH) -> int:
    """Parseia os eventos recebidos (syslog, upload, conector) e cria as entregas. Idempotente por linha (status)."""
    rows = Session.execute(select(Event).where(Event.status == "received").order_by(Event.id).limit(limit)
                           .with_for_update(skip_locked=True)).scalars().all()
    if not rows:
        return 0
    dests = _dest_index()
    uploads: dict[int, Upload] = {}
    per_source = defaultdict(lambda: [0, 0, 0, None])
    to_delete = []
    for ev in rows:
        src = _source(ev.source_id)
        up = None
        if ev.upload_id:
            up = uploads.get(ev.upload_id) or Session.get(Upload, ev.upload_id)
            uploads[ev.upload_id] = up
        parser_id = (up.parser_id if up and up.parser_id else None) or (src.parser_id if src else None)
        meta = {"peer_ip": ev.peer_ip, "transport": ev.transport}
        try:
            parsed, vid = catalog.parse_line(ev.raw, meta, parser_id)
            ev.event, ev.parser_version_id, ev.status, ev.error = parsed, vid, "parsed", ""
        except (dsl.ParseError, dsl.SpecError) as e:
            ev.status, ev.error = "unparsed", str(e)[:500]
        except Exception as e:  # noqa: BLE001 — nunca travar a fila por uma linha
            ev.status, ev.error = "unparsed", f"erro interno: {str(e)[:300]}"
        ps = per_source[ev.source_id]
        ps[0] += 1
        ps[1 if ev.status == "parsed" else 2] += 1
        ps[3] = ev.received_at
        metrics.src[ev.source_id or 0][0] += 1
        metrics.src[ev.source_id or 0][1 if ev.status == "parsed" else 2] += 1
        if up is not None:
            if ev.status == "parsed":
                up.parsed += 1
            else:
                up.unparsed += 1
        if ev.status == "unparsed" and src is not None and src.unparsed_policy == "drop" and up is None:
            to_delete.append(ev.id)
            continue
        if ev.status == "unparsed" and (src is None or src.unparsed_policy != "forward_raw"):
            continue  # fica em "Não reconhecidos"
        if up is not None and not up.send_to_destinations:
            continue
        n = 0
        for d in dests.get(ev.tenant_id, []):
            if _passes(d, ev):
                Session.add(EventDelivery(event_id=ev.id, destination_id=d.id, next_attempt_at=utcnow()))
                n += 1
        ev.pending_deliveries = n
    if to_delete:
        Session.flush()
        Session.execute(delete(Event).where(Event.id.in_(to_delete)))
    for sid, (n, p, u, last) in per_source.items():
        if sid:
            Session.execute(update(Source).where(Source.id == sid).values(
                events_total=Source.events_total + n, parsed_total=Source.parsed_total + p, unparsed_total=Source.unparsed_total + u,
                last_event_at=func.greatest(func.coalesce(Source.last_event_at, last), last)))
    for up in uploads.values():
        if up is not None and up.status == "processing" and up.parsed + up.unparsed >= up.lines:
            up.status, up.finished_at = "done", utcnow()
    Session.commit()
    return len(rows)


# ------------------------------------------------------------------------------------------------ envio
def _ctx(ev: Event, tenants: dict, sources: dict) -> dict:
    t = tenants.get(ev.tenant_id)
    s = sources.get(ev.source_id)
    return {"tenant": t, "source": s, "parser": (ev.event or {}).get("metadata", {}).get("parser")}


def _payload(d: Destination, ev: Event, ctx: dict):
    if ev.status != "parsed" or ev.event is None:
        if d.kind in ("secops_chronicle", "secops_legacy"):  # UDM não aceita bruto: vira GENERIC_EVENT com a linha
            base = {"time": ev.received_at.isoformat(timespec="milliseconds").replace("+00:00", "Z"), "class_uid": 0,
                    "message": "Linha não reconhecida pelo Trust Parser",
                    "metadata": {"product": {"vendor_name": "Trust Control", "name": "Trust Parser"}, "event_code": "unparsed"},
                    "observer": {"hostname": ev.peer_ip or "trustparser"}, "unmapped": {"raw": ev.raw[:8000], "erro": ev.error}}
            return formats.to_udm(base, ev.raw, ctx)
        return f"[trustparser:nao_reconhecido] {ev.raw}"
    return formats.render(d.format, ev.event, ev.raw, ctx, catalog.output_spec(d.format))


def deliver_destination(d: Destination, tenants: dict, sources: dict, max_items: int = 2000) -> int:
    now = utcnow()
    if d.paused_until and d.paused_until > now:
        return 0
    rows = Session.execute(select(EventDelivery, Event).join(Event, Event.id == EventDelivery.event_id)
                           .where(EventDelivery.destination_id == d.id, EventDelivery.status == "pending",
                                  EventDelivery.next_attempt_at <= now)
                           .order_by(EventDelivery.event_id).limit(max_items).with_for_update(of=EventDelivery, skip_locked=True)).all()
    if not rows:
        return 0
    try:
        sec = secrets_box.open_(d.secret_enc, f"dest:{d.id}") if d.secret_enc else {}
    except secrets_box.SecretsError as e:
        _fail(d, [r[0] for r in rows], str(e), permanent=False)
        Session.commit()
        return 0
    items, sizes, sevs = [], [], []
    for dl, ev in rows:
        try:
            p = _payload(d, ev, _ctx(ev, tenants, sources))
        except Exception as e:  # noqa: BLE001 — formato quebrado para este evento: falha só ele
            dl.status, dl.last_error, dl.attempts = "failed", f"formato: {str(e)[:300]}", dl.attempts + 1
            ev.pending_deliveries = max(0, ev.pending_deliveries - 1)
            metrics.dst[d.id][1] += 1
            continue
        items.append((dl, ev, p))
        sizes.append(len(formats.to_line(p).encode()) + 16)
        sevs.append({0: 6, 1: 6, 2: 5, 3: 4, 4: 3, 5: 2, 6: 1}.get(int((ev.event or {}).get("severity_id") or 0), 6))
    sent = 0
    for idx in senders.split_batches(d.kind, items, sizes):
        batch = [items[i] for i in idx]
        sent += _send_batch(d, sec, batch, [sevs[i] for i in idx])
    Session.commit()
    return sent


def _send_batch(d: Destination, sec: dict, batch: list, sevs: list) -> int:
    try:
        senders.send(d.kind, d.id, d.config, sec, [p for _, _, p in batch], sevs)
    except senders.SendError as e:
        if e.permanent and len(batch) > 1:  # um evento ruim derruba o lote inteiro no SecOps: isola um a um
            ok = 0
            for i, item in enumerate(batch[:200]):
                ok += _send_batch(d, sec, [item], [sevs[i]])
            if len(batch) > 200:
                _fail(d, [x[0] for x in batch[200:]], str(e), permanent=False, evs=[x[1] for x in batch[200:]])
            return ok
        _fail(d, [x[0] for x in batch], str(e), permanent=e.permanent, evs=[x[1] for x in batch])
        return 0
    now = utcnow()
    for dl, ev, _ in batch:
        dl.status, dl.sent_at, dl.attempts, dl.last_error = "sent", now, dl.attempts + 1, ""
        ev.pending_deliveries = max(0, ev.pending_deliveries - 1)
    if d.status != "ok" and d.consecutive_failures >= 5 and d.alerted_at:
        ops_alerts.destination_recovered(d)
        d.alerted_at = None
    d.status, d.last_ok_at, d.consecutive_failures = "ok", now, 0
    d.sent_total += len(batch)
    metrics.dst[d.id][0] += len(batch)
    return len(batch)


def _fail(d: Destination, dls: list, err: str, permanent: bool, evs: list | None = None):
    now = utcnow()
    for i, dl in enumerate(dls):
        dl.attempts += 1
        dl.last_error = err[:1000]
        if permanent:
            dl.status = "failed"
            if evs:
                evs[i].pending_deliveries = max(0, evs[i].pending_deliveries - 1)
        else:
            dl.next_attempt_at = now + timedelta(seconds=min(600, 15 * (2 ** min(dl.attempts, 6))))
    d.status, d.last_error, d.last_error_at = "err", err[:1000], now
    d.consecutive_failures += 1
    d.failed_total += len(dls) if permanent else 0
    metrics.dst[d.id][1] += len(dls)
    if not permanent and d.consecutive_failures >= 3:  # destino fora do ar: espaça as tentativas do destino inteiro
        d.paused_until = now + timedelta(seconds=min(300, 20 * d.consecutive_failures))
    if d.consecutive_failures >= int(settings.get("dest_fail_threshold") or 5) and d.alerted_at is None:
        ops_alerts.destination_failing(d)
        d.alerted_at = now


def deliver_all() -> int:
    tenants = {t.id: t.name for t in Session.execute(select(Tenant)).scalars()}
    sources = {s.id: s.name for s in Session.execute(select(Source)).scalars()}
    total = 0
    for d in Session.execute(select(Destination).where(Destination.active.is_(True)).order_by(Destination.id)).scalars().all():
        try:
            total += deliver_destination(d, tenants, sources)
        except Exception:  # noqa: BLE001
            log.exception("falha ao entregar destino %s", d.id)
            Session.rollback()
    return total


# ------------------------------------------------------------------------------------------------ expurgo
def purge() -> dict:
    """Buffer curto: entregue/sem destino some em 2 h; não entregue fica até 24 h; acima do limite de disco, os mais antigos saem."""
    now = utcnow()
    keep_h = float(settings.get("buffer_hours") or 2)
    max_h = float(settings.get("undelivered_max_hours") or 24)
    r1 = Session.execute(delete(Event).where(Event.received_at < now - timedelta(hours=keep_h), Event.pending_deliveries == 0,
                                             Event.status != "received")).rowcount
    old = select(Event.id).where(Event.received_at < now - timedelta(hours=max_h))
    dropped = Session.execute(update(EventDelivery).where(EventDelivery.event_id.in_(old), EventDelivery.status == "pending")
                              .values(status="dropped", last_error="expirado após o limite de retenção")).rowcount
    r2 = Session.execute(delete(Event).where(Event.received_at < now - timedelta(hours=max_h))).rowcount
    Session.execute(delete(EventDelivery).where(EventDelivery.status.in_(("sent", "failed", "dropped")),
                                                EventDelivery.event_id.notin_(select(Event.id))))
    Session.execute(text("delete from metrics_minute where minute < now() - interval '7 days'"))
    for up in Session.execute(select(Upload).where(Upload.expires_at < now, Upload.status != "expired")).scalars():
        up.status = "expired"
    cap_mb = float(settings.get("buffer_max_mb") or 8000)
    size_mb = Session.execute(text("select pg_total_relation_size('events') / 1048576.0")).scalar() or 0
    trimmed = 0
    if size_mb > cap_mb:
        n = Session.execute(text("select count(*) from events")).scalar() or 0
        cut = max(1000, int(n * 0.1))
        trimmed = Session.execute(text("delete from events where id in (select id from events order by id limit :n)"), {"n": cut}).rowcount
        ops_alerts.buffer_full(size_mb, cap_mb, trimmed)
    Session.commit()
    if dropped:
        log.warning("expurgo: %s entregas pendentes descartadas após %s h", dropped, max_h)
    return {"delivered_or_kept": r1, "expired": r2, "dropped_deliveries": dropped, "trimmed": trimmed, "size_mb": round(float(size_mb), 1)}


# ------------------------------------------------------------------------------------------------ saúde das fontes
def check_sources():
    now = utcnow()
    for s in Session.execute(select(Source).where(Source.active.is_(True))).scalars():
        if s.silence_alert_minutes and s.last_event_at and s.last_event_at < now - timedelta(minutes=s.silence_alert_minutes):
            if s.alerted_at is None:
                ops_alerts.source_silent(s)
                s.alerted_at = now
        elif s.alerted_at and s.last_event_at and s.last_event_at > s.alerted_at:
            s.alerted_at = None
    # deriva de formato: muitas linhas não reconhecidas na última hora
    rows = Session.execute(text("""select ref_id, sum(a) rec, sum(c) unp from metrics_minute
                                   where kind = 's' and minute > now() - interval '60 minutes' and ref_id > 0 group by ref_id""")).all()
    thr = float(settings.get("drift_threshold_pct") or 20)
    last = settings.get("drift_alerted") or {}
    for r in rows:
        if r.rec >= 20 and 100.0 * r.unp / r.rec >= thr:
            key = str(r.ref_id)
            if key in last and time.time() - last[key] < 6 * 3600:
                continue
            s = Session.get(Source, r.ref_id)
            if s is not None:
                ops_alerts.drift(s, int(r.rec), int(r.unp))
                last[key] = time.time()
    settings.set_("drift_alerted", last)
    Session.commit()


def split_lines(data: bytes) -> list[str]:
    text_ = data.decode("utf-8", "replace") if not data.startswith(b"\xff\xfe") else data.decode("utf-16", "replace")
    return [ln for ln in re.split(r"\r?\n", text_) if ln.strip()]
