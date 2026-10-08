"""Receptor syslog do Trust Parser (container parser-ingest).

  * TLS (RFC 5425) na 6514, TCP sem TLS e UDP na 1514 do container (publicadas como 514 no host);
  * TCP/TLS: enquadramento detectado por mensagem (octet-counting "123 <pri>..." ou uma mensagem por linha);
  * identifica tenant/fonte pelo IP de origem (lista de IPs liberados) e, se preciso, pelo hostname do cabeçalho syslog;
  * grava em lote no buffer (events, status 'received'); o parsing é do worker.
O firewall do host (trustparser-fw) já descarta IPs não liberados; aqui a checagem se repete (defesa em profundidade).
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import queue
import re
import signal
import ssl
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from sqlalchemy import create_engine, text

from .engine import syslog as sl

log = logging.getLogger("ingest")
MAX_MSG = int(os.getenv("SYSLOG_MAX_MSG", str(256 * 1024)))
MAX_CONN_PER_IP = int(os.getenv("SYSLOG_MAX_CONN_PER_IP", "64"))
RATE_PER_IP = int(os.getenv("SYSLOG_RATE_PER_IP", "20000"))  # mensagens/minuto por IP
CERT = os.getenv("SYSLOG_TLS_CERT", "/certs/fullchain.pem")
KEY = os.getenv("SYSLOG_TLS_KEY", "/certs/key.pem")
RE_OCTET = re.compile(rb"^(\d{1,6}) ")


class Router:
    """IP de origem → (tenant_id, source_id). Recarregado do banco a cada 15 s."""

    def __init__(self, engine):
        self.engine = engine
        self.nets: list = []
        self.sources: dict = defaultdict(list)
        self.loaded = 0.0

    def refresh(self, force=False):
        if not force and time.monotonic() - self.loaded < 15:
            return
        with self.engine.connect() as c:
            ips = c.execute(text("""select a.cidr, a.tenant_id, a.source_id, a.protocols from allowed_ips a join tenants t on t.id = a.tenant_id
                                    where a.active and t.status = 'active' and (a.expires_at is null or a.expires_at > now())""")).all()
            srcs = c.execute(text("""select id, tenant_id, match_hostname from sources where active and transport = 'syslog'
                                     order by id""")).all()
        nets = []
        for cidr, tid, sid, protos in ips:
            try:
                nets.append((ipaddress.ip_network(cidr, strict=False), tid, sid, set(protos or [])))
            except ValueError:
                continue
        nets.sort(key=lambda x: -x[0].prefixlen)
        by_t = defaultdict(list)
        for sid, tid, mh in srcs:
            try:
                rx = re.compile(mh) if mh else None
            except re.error:
                rx = None
            by_t[tid].append((sid, rx))
        self.nets, self.sources, self.loaded = nets, by_t, time.monotonic()

    def resolve(self, ip: str, proto: str, hostname: str) -> tuple[int, int | None] | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if addr.version == 6 and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        for net, tid, sid, protos in self.nets:
            if addr in net and (proto in protos):
                if sid:
                    return tid, sid
                cands = self.sources.get(tid, [])
                for s_id, rx in cands:
                    if rx is not None and hostname and rx.search(hostname):
                        return tid, s_id
                plain = [s_id for s_id, rx in cands if rx is None]
                if len(plain) == 1:
                    return tid, plain[0]
                return tid, None
        return None


class Writer(threading.Thread):
    """Grava em lote (até 1000 linhas ou 0,5 s)."""

    def __init__(self, engine):
        super().__init__(daemon=True, name="writer")
        self.engine, self.q = engine, queue.Queue(maxsize=200_000)
        self.written = 0

    def put(self, row) -> bool:
        try:
            self.q.put_nowait(row)
            return True
        except queue.Full:
            return False

    def run(self):
        while True:
            batch = [self.q.get()]
            deadline = time.monotonic() + 0.5
            while len(batch) < 1000:
                try:
                    batch.append(self.q.get(timeout=max(0.0, deadline - time.monotonic())))
                except queue.Empty:
                    break
            for attempt in range(10):
                try:
                    with self.engine.begin() as c:
                        c.execute(text("""insert into events (tenant_id, source_id, received_at, peer_ip, transport, raw, status, error,
                                          pending_deliveries) values (:t, :s, :at, :ip, :tr, :raw, 'received', '', 0)"""), batch)
                    self.written += len(batch)
                    break
                except Exception:  # noqa: BLE001
                    log.exception("falha ao gravar lote (%s linhas), tentativa %s", len(batch), attempt + 1)
                    time.sleep(min(30, 2 ** attempt))


class Ingest:
    def __init__(self, engine):
        self.router, self.writer = Router(engine), Writer(engine)
        self.engine = engine
        self.conns = defaultdict(int)
        self.rate = defaultdict(lambda: deque())
        self.stats = defaultdict(int)
        self.rejected: dict = {}

    def accept_line(self, data: bytes, ip: str, proto: str):
        if not data.strip():
            return
        if len(data) > MAX_MSG:
            data = data[:MAX_MSG]
            self.stats["truncated"] += 1
        now = time.monotonic()
        dq = self.rate[ip]
        dq.append(now)
        while dq and now - dq[0] > 60:
            dq.popleft()
        if len(dq) > RATE_PER_IP:
            self.stats["rate_limited"] += 1
            return
        line = data.decode("utf-8", "replace").rstrip("\r\n\x00")
        hdr = sl.parse(line[:2048]) if line.startswith("<") else None
        host = (hdr or {}).get("hostname") or ""
        self.router.refresh()
        r = self.router.resolve(ip, proto, host)
        if r is None:
            self.stats["rejected"] += 1
            self.rejected[ip] = {"at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "proto": proto}
            return
        tid, sid = r
        if not self.writer.put({"t": tid, "s": sid, "at": datetime.now(timezone.utc), "ip": ip, "tr": proto, "raw": line}):
            self.stats["dropped_full"] += 1
            return
        self.stats[f"in_{proto}"] += 1

    # ------------------------------------------------------------------ TCP/TLS
    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, proto: str):
        peer = writer.get_extra_info("peername") or ("?", 0)
        ip = peer[0]
        if ip.startswith("::ffff:"):
            ip = ip[7:]
        self.router.refresh()
        if self.router.resolve(ip, proto, "") is None:
            self.stats["rejected_conn"] += 1
            self.rejected[ip] = {"at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "proto": proto}
            writer.close()
            return
        if self.conns[ip] >= MAX_CONN_PER_IP:
            self.stats["too_many_conns"] += 1
            writer.close()
            return
        self.conns[ip] += 1
        buf = b""
        try:
            while True:
                chunk = await asyncio.wait_for(reader.read(65536), timeout=3600)
                if not chunk:
                    break
                buf += chunk
                while buf:
                    m = RE_OCTET.match(buf)
                    if m and len(buf) > m.end() and buf[m.end():m.end() + 1] == b"<":
                        n = int(m.group(1))
                        if len(buf) < m.end() + n:
                            if n > MAX_MSG * 2:
                                self.accept_line(buf[m.end():], ip, proto)
                                buf = b""
                            break
                        self.accept_line(buf[m.end():m.end() + n], ip, proto)
                        buf = buf[m.end() + n:].lstrip(b"\r\n")
                        continue
                    i = buf.find(b"\n")
                    if i < 0:
                        if len(buf) > MAX_MSG:
                            self.accept_line(buf, ip, proto)
                            buf = b""
                        break
                    self.accept_line(buf[:i], ip, proto)
                    buf = buf[i + 1:]
            if buf.strip():
                self.accept_line(buf, ip, proto)
        except (asyncio.TimeoutError, ConnectionError, ssl.SSLError, OSError):
            pass
        finally:
            self.conns[ip] -= 1
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    # ------------------------------------------------------------------ status para a tela
    def publish_status(self):
        st = {"at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "written": self.writer.written,
              "queue": self.writer.q.qsize(), "stats": dict(self.stats), "connections": sum(self.conns.values()),
              "rejected_recent": dict(list(self.rejected.items())[-50:])}
        try:
            with self.engine.begin() as c:
                c.execute(text("""insert into settings (key, value, updated_at) values ('ingest_status', cast(:v as jsonb), now())
                                  on conflict (key) do update set value = excluded.value, updated_at = now()"""), {"v": json.dumps({"v": st})})
        except Exception:  # noqa: BLE001
            log.exception("falha ao publicar status")


class UDP(asyncio.DatagramProtocol):
    def __init__(self, ing: Ingest):
        self.ing = ing

    def datagram_received(self, data, addr):
        ip = addr[0][7:] if addr[0].startswith("::ffff:") else addr[0]
        for part in data.split(b"\n") if data.count(b"\n") > 1 else [data]:
            self.ing.accept_line(part, ip, "udp")


def tls_context() -> ssl.SSLContext | None:
    if not (os.path.exists(CERT) and os.path.exists(KEY)):
        log.error("certificado TLS ausente (%s); TLS desativado", CERT)
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(CERT, KEY)
    return ctx


async def main():
    logging.basicConfig(level=logging.INFO, format='{"t":"%(asctime)s","lvl":"%(levelname)s","log":"%(name)s","msg":"%(message)s"}')
    engine = create_engine(os.environ["DATABASE_URL"], pool_pre_ping=True, pool_size=3, max_overflow=2)
    ing = Ingest(engine)
    ing.writer.start()
    ing.router.refresh(force=True)
    ctx = tls_context()
    servers = []
    tls_port, tcp_port, udp_port = int(os.getenv("TLS_PORT", "6514")), int(os.getenv("TCP_PORT", "1514")), int(os.getenv("UDP_PORT", "1514"))
    if ctx is not None:
        servers.append(await asyncio.start_server(lambda r, w: ing.handle(r, w, "tls"), "0.0.0.0", tls_port, ssl=ctx,
                                                  ssl_handshake_timeout=15, limit=MAX_MSG * 2))
    servers.append(await asyncio.start_server(lambda r, w: ing.handle(r, w, "tcp"), "0.0.0.0", tcp_port, limit=MAX_MSG * 2))
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(lambda: UDP(ing), local_addr=("0.0.0.0", udp_port))
    log.info("syslog no ar: tls=%s tcp=%s udp=%s", tls_port if ctx else "off", tcp_port, udp_port)
    stop = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    mtime = os.path.getmtime(CERT) if ctx is not None else 0
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=30)
        except asyncio.TimeoutError:
            pass
        await loop.run_in_executor(None, ing.publish_status)
        if ctx is not None:
            try:
                m = os.path.getmtime(CERT)
                if m != mtime:  # certificado renovado: as próximas conexões já usam o novo
                    ctx.load_cert_chain(CERT, KEY)
                    mtime = m
                    log.info("certificado TLS recarregado")
            except (OSError, ssl.SSLError):
                log.exception("falha ao recarregar certificado")
    for s in servers:
        s.close()
    deadline = time.monotonic() + 10
    while ing.writer.q.qsize() and time.monotonic() < deadline:
        await asyncio.sleep(0.2)


if __name__ == "__main__":
    asyncio.run(main())
