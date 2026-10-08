"""Caixa de entrada da EVA (IMAP): leitura, autenticidade (DKIM verificado aqui mesmo), parsing e anexos."""
from __future__ import annotations

import email
import email.policy
import hashlib
import html
import imaplib
import logging
import os
import re
import ssl
from dataclasses import dataclass, field
from email.header import decode_header, make_header
from email.utils import getaddresses, parseaddr

import dkim

log = logging.getLogger("eva.inbox")
SEEN_KEYWORD = __import__("os").getenv("EVA_IMAP_KEYWORD", "EvaVisto")
IMAGE_TYPES = {"image/png": ".png", "image/jpeg": ".jpg", "image/jpg": ".jpg", "image/gif": ".gif", "image/webp": ".webp"}
MAX_IMAGE_BYTES = 8 * 1024 * 1024
MAX_IMAGES = 8


@dataclass
class Incoming:
    uid: str
    raw: bytes
    sender: str
    sender_name: str
    subject: str
    message_id: str
    in_reply_to: list[str]
    references: list[str]
    text: str
    cc: list[str] = field(default_factory=list)
    to: list[str] = field(default_factory=list)
    images: list[tuple[str, bytes]] = field(default_factory=list)  # (nome, bytes)
    other_attachments: list[str] = field(default_factory=list)
    auto_generated: bool = False
    from_count: int = 1
    image_names: list[str] = field(default_factory=list)


def _dec(v) -> str:
    try:
        return str(make_header(decode_header(v or "")))
    except Exception:  # noqa: BLE001
        return str(v or "")


def _ids(v: str | None) -> list[str]:
    return re.findall(r"<[^<>\s]+>", v or "")


def html_to_text(h: str) -> str:
    h = re.sub(r"(?is)<(script|style|head).*?</\1>", "", h)
    h = re.sub(r"(?is)<blockquote.*?</blockquote>", "\n", h)  # citação da conversa anterior
    h = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</li>|</tr>|</h\d>", "\n", h)
    h = re.sub(r"<[^>]+>", " ", h)
    t = html.unescape(h)
    return re.sub(r"[ \t\xa0]+", " ", re.sub(r"\n\s*\n+", "\n\n", t)).strip()


QUOTE_MARKERS = [
    r"^\s*Em .{5,120}escreveu:\s*$", r"^\s*On .{5,120}wrote:\s*$", r"^\s*-{2,}\s*Mensagem original\s*-{2,}", r"^\s*-{2,}\s*Original Message\s*-{2,}",
    r"^\s*De:\s.*$\n^\s*(Enviado|Enviada|Data|Sent):", r"^\s*From:\s.*$\n^\s*(Sent|Date):", r"^_{10,}\s*$",
]


def strip_quoted(text: str) -> str:
    """Mantém só a mensagem nova (o histórico já está na sessão do agente)."""
    cut = len(text)
    for rx in QUOTE_MARKERS:
        m = re.search(rx, text, flags=re.M | re.I)
        if m and m.start() < cut:
            cut = m.start()
    lines = [ln for ln in text[:cut].splitlines() if not ln.lstrip().startswith(">")]
    return "\n".join(lines).strip()[:20000]


def parse(uid: str, raw: bytes) -> Incoming:
    msg = email.message_from_bytes(raw, policy=email.policy.compat32)
    froms = msg.get_all("From") or []
    name, addr = parseaddr(_dec(froms[0]) if froms else "")
    plain, htmlbody = None, None
    images, others = [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        disp = (part.get("Content-Disposition") or "").lower()
        fname = _dec(part.get_filename() or "")
        payload = part.get_payload(decode=True) or b""
        if ctype in IMAGE_TYPES:
            if len(payload) <= MAX_IMAGE_BYTES and len(images) < MAX_IMAGES:
                digest = hashlib.sha1(payload).hexdigest()[:10]
                images.append((f"imagem-{len(images) + 1}-{digest}{IMAGE_TYPES[ctype]}", payload))
            continue
        if "attachment" in disp or fname:
            others.append(fname or ctype)
            continue
        charset = part.get_content_charset() or "utf-8"
        try:
            body = payload.decode(charset, errors="replace")
        except LookupError:
            body = payload.decode("utf-8", errors="replace")
        if ctype == "text/plain" and plain is None:
            plain = body
        elif ctype == "text/html" and htmlbody is None:
            htmlbody = body
    text = plain if plain and plain.strip() else html_to_text(htmlbody or "")
    auto = bool(re.match(r"(?i)auto-(generated|replied|notified)", msg.get("Auto-Submitted", "") or "")) \
        or (msg.get("Precedence", "") or "").lower() in ("bulk", "junk", "list") \
        or bool(msg.get("X-Autoreply") or msg.get("X-Autorespond")) \
        or addr.lower().startswith(("mailer-daemon@", "postmaster@", "no-reply", "noreply"))
    return Incoming(uid=uid, raw=raw, sender=addr.strip().lower(), sender_name=name.strip(), subject=_dec(msg.get("Subject", "")).strip()[:300],
                    message_id=(_ids(msg.get("Message-ID")) or [f"<sem-id-{hashlib.sha1(raw).hexdigest()}@eva>"])[0],
                    in_reply_to=_ids(msg.get("In-Reply-To")), references=_ids(msg.get("References")),
                    text=strip_quoted(text or ""), cc=[a.lower() for _, a in getaddresses(msg.get_all("Cc") or [])],
                    to=[a.lower() for _, a in getaddresses(msg.get_all("To") or [])],
                    images=images, other_attachments=others, auto_generated=auto, from_count=len(froms))


def age_hours(raw: bytes) -> float:
    """Idade do e-mail pelo cabeçalho Received mais recente (carimbo do nosso servidor); cai para Date."""
    from datetime import datetime, timezone
    from email.utils import parsedate_to_datetime
    msg = email.message_from_bytes(raw)
    stamps = []
    for rcv in (msg.get_all("Received") or [])[:1]:
        part = rcv.rsplit(";", 1)[-1].strip()
        try:
            stamps.append(parsedate_to_datetime(part))
        except (TypeError, ValueError):
            pass
    if not stamps and msg.get("Date"):
        try:
            stamps.append(parsedate_to_datetime(msg["Date"]))
        except (TypeError, ValueError):
            pass
    if not stamps:
        return 0.0
    d = stamps[0] if stamps[0].tzinfo else stamps[0].replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - d).total_seconds() / 3600


def dkim_aligned(raw: bytes, sender: str, dnsfunc=None) -> tuple[bool, str]:
    """Verifica TODAS as assinaturas DKIM do e-mail cru e exige uma válida alinhada ao domínio do remetente.

    Não confia em cabeçalhos Authentication-Results (podem ser forjados pelo remetente)."""
    domain = sender.rsplit("@", 1)[-1].lower() if "@" in sender else ""
    if not domain:
        return False, "remetente sem domínio"
    kw = {"dnsfunc": dnsfunc} if dnsfunc else {}
    try:
        d = dkim.DKIM(raw)
        sigs = [h for h in d.headers if h[0].lower() == b"dkim-signature"]
    except Exception as e:  # noqa: BLE001
        return False, f"mensagem ilegível: {type(e).__name__}"
    if not sigs:
        return False, "sem assinatura DKIM"
    reasons = []
    for idx, (_, value) in enumerate(sigs):
        tags = dict(t.strip().split("=", 1) for t in value.decode(errors="ignore").replace("\r\n", "").split(";") if "=" in t)
        sd = re.sub(r"\s+", "", tags.get("d", "")).lower()
        if "l" in {k.strip() for k in tags}:
            reasons.append(f"d={sd} usa l= (corpo parcialmente assinado)")
            continue
        if not sd or not (domain == sd or domain.endswith("." + sd)):
            reasons.append(f"d={sd} não alinhado")
            continue
        try:
            if dkim.DKIM(raw).verify(idx=idx, **kw):
                return True, f"dkim=pass d={sd}"
            reasons.append(f"d={sd} assinatura inválida")
        except Exception as e:  # noqa: BLE001
            reasons.append(f"d={sd} erro {type(e).__name__}")
    return False, "; ".join(reasons)[:300]


class Mailbox:
    def __init__(self, host: str, user: str, password: str, port: int = 993):
        self.host, self.user, self.password, self.port = host, user, password, port

    def _conn(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE  # rede interna do Docker (postfix-mail)
        c = imaplib.IMAP4_SSL(self.host, self.port, ssl_context=ctx, timeout=60)
        c.login(self.user, self.password)
        return c

    def check(self) -> bool:
        try:
            c = self._conn()
            c.logout()
            return True
        except Exception:  # noqa: BLE001
            return False

    def list_new(self, limit: int = 200) -> list[tuple[str, str, bool]]:
        """(uid, remetente, é_automática) das mensagens da INBOX ainda não examinadas — só cabeçalhos."""
        c = self._conn()
        try:
            c.select("INBOX")
            typ, data = c.uid("SEARCH", None, "UNKEYWORD", SEEN_KEYWORD)
            uids = (data[0] or b"").split()[:limit]
            out = []
            for uid in uids:
                typ, md = c.uid("FETCH", uid, "(BODY.PEEK[HEADER.FIELDS (FROM AUTO-SUBMITTED X-TRUSTSOC-ORIGINAL-TO)])")
                hdr = next((p[1] for p in md if isinstance(p, tuple)), b"")
                m = email.message_from_bytes(hdr)
                sender = parseaddr(_dec(m.get("From", "")))[1].lower()
                auto = bool(m.get("X-TrustSOC-Original-To")) or bool(re.match(r"(?i)auto-", m.get("Auto-Submitted", "") or ""))
                out.append((uid.decode(), sender, auto))
            return out
        finally:
            c.logout()

    def fetch(self, uid: str) -> bytes:
        c = self._conn()
        try:
            c.select("INBOX")
            typ, md = c.uid("FETCH", uid, "(BODY.PEEK[])")
            return next((p[1] for p in md if isinstance(p, tuple)), b"")
        finally:
            c.logout()

    def mark(self, uid: str, folder: str | None = None):
        """Marca como examinada; opcionalmente move para uma pasta (criada se preciso)."""
        c = self._conn()
        try:
            c.select("INBOX")
            c.uid("STORE", uid, "+FLAGS", f"({SEEN_KEYWORD})")
            if folder:
                c.create(folder)  # ignora erro se já existe
                typ, _ = c.uid("MOVE", uid, folder)
                if typ != "OK":
                    c.uid("COPY", uid, folder)
                    c.uid("STORE", uid, "+FLAGS", r"(\Deleted)")
                    c.expunge()
        finally:
            c.logout()

    def save_copy(self, folder: str, raw: bytes):
        c = self._conn()
        try:
            c.create(folder)
            c.append(folder, r"(\Seen)", None, raw)
        finally:
            c.logout()


def save_request_files(base_dir: str, inc: Incoming) -> dict:
    os.makedirs(base_dir, exist_ok=True)
    with open(os.path.join(base_dir, "mensagem.eml"), "wb") as fh:
        fh.write(inc.raw)
    with open(os.path.join(base_dir, "pedido.txt"), "w", encoding="utf-8") as fh:
        fh.write(inc.text)
    names = []
    for name, data in inc.images:
        with open(os.path.join(base_dir, name), "wb") as fh:
            fh.write(data)
        names.append(name)
    os.chmod(base_dir, 0o755)
    return {"images": names, "other_attachments": inc.other_attachments}


def build_api_message(*, sender: str, name: str, mailbox: str, cc: list[str], subject: str, text: str, message_id: str,
                      in_reply_to: str = "", references=(), images=()) -> bytes:
    """Pedido recebido pela API do portal no mesmo formato de um e-mail — assim ele segue exatamente o mesmo fluxo
    (entendimento, regras, proibições, resposta). As imagens viram anexos, como num e-mail com prints."""
    from email.message import EmailMessage
    from email.utils import formataddr, formatdate
    msg = EmailMessage()
    msg["From"] = formataddr((name or "", sender))
    msg["To"] = mailbox
    if cc:
        msg["Cc"] = ", ".join(cc)
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = message_id
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
        msg["References"] = " ".join(list(dict.fromkeys([*references, in_reply_to]))[-20:])
    msg["X-Eva-Canal"] = "api"
    msg.set_content(text or "")
    for fname, ctype, data in images or ():
        maintype, subtype = ctype.split("/", 1)
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=fname)
    return msg.as_bytes()
