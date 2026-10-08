"""Regras de negócio determinísticas da EVA (funções puras, testáveis)."""
from __future__ import annotations

import re
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

BRT = ZoneInfo("America/Sao_Paulo")
ROGERIO = "rogerio.crispim@brainwalk.com.br"
MAILBOX_DEFAULT = "eva-trustparser@trustcontrol.nuvem.tec.br"
EMAIL_RE = re.compile(r"^[a-z0-9._%+-]{1,64}@[a-z0-9-]+(\.[a-z0-9-]+)+$")
INTENTS = ("alteracao", "manutencao", "pergunta", "desfazer", "whitelist_incluir", "whitelist_remover", "esclarecimento", "fora_de_escopo")


def admit(sender: str, whitelist: dict[str, dict], *, mode: str, dkim_ok: bool, auto_generated: bool, from_count: int,
          mailbox: str) -> tuple[str, str]:
    """Decide o que fazer com um e-mail recebido.

    Retorna (acao, motivo): 'ignorar' (não é conversa com a EVA: deixa na caixa intocada),
    'rejeitar' (parece pedido mas não passou na autenticação: move p/ Ignorados e avisa Rogério),
    'demo' (whitelist, mas modo demonstração só atende Rogério), 'aceitar'."""
    entry = whitelist.get(sender)
    if sender == mailbox or auto_generated:
        return "ignorar", "mensagem automática ou da própria EVA"
    if entry is None or not entry.get("active", True):
        return "ignorar", "remetente fora da lista de autorizados"
    if from_count != 1:
        return "rejeitar", "cabeçalho From múltiplo"
    if not dkim_ok:
        return "rejeitar", "assinatura DKIM ausente ou inválida para o domínio do remetente"
    demo_extra = {e.strip().lower() for e in __import__("os").getenv("EVA_DEMO_EXTRA_SENDERS", "").split(",") if e.strip()}
    if mode == "demo" and sender != ROGERIO and sender not in demo_extra:
        return "demo", "modo demonstração: só o Rogério é atendido"
    return "aceitar", ""


def whitelist_change(action: str, requester: str, whitelist: dict[str, dict], target_email: str, target_name: str = "") -> tuple[bool, str]:
    """Valida inclusão/remoção. Só donos alteram; donos não podem ser removidos nem rebaixados por e-mail."""
    req = whitelist.get(requester) or {}
    if req.get("role") != "owner" or not req.get("active", True):
        return False, "somente os donos da lista (cadastrados no Trust Parser) podem alterar a lista de pessoas autorizadas"
    email = (target_email or "").strip().lower()
    if not EMAIL_RE.match(email):
        return False, "endereço de e-mail inválido"
    cur = whitelist.get(email)
    if action == "whitelist_incluir":
        if cur and cur.get("active", True):
            return False, "essa pessoa já está autorizada"
        return True, ""
    if action == "whitelist_remover":
        if not cur or not cur.get("active", True):
            return False, "essa pessoa não está na lista"
        if cur.get("role") == "owner":
            return False, "donos não podem ser removidos por e-mail (só pela tela EVA do Trust Parser)"
        return True, ""
    return False, "ação desconhecida"


def admit_api(sender: str, whitelist: dict[str, dict], *, mode: str, demo_extra=()) -> tuple[bool, str]:
    """Pedido recebido pela API do portal: a autenticação (chave, IP, MFA) já foi feita lá; aqui valem as mesmas
    condições do e-mail no momento de processar — estar ativo na whitelist e o modo demonstração."""
    entry = whitelist.get((sender or "").lower())
    if entry is None or not entry.get("active", True):
        return False, "o responsável pela chave não está ativo na lista de autorizados da EVA"
    if mode == "demo" and sender != ROGERIO and sender not in set(demo_extra or ()):
        return False, "modo demonstração: só o Rogério é atendido"
    return True, ""


SYSTEM_PREFIXES = ("mailer-daemon@", "postmaster@", "no-reply", "noreply", "bounce", "do-not-reply")
MAX_RECIPIENTS = 15


def keep_participants(addresses, *, mailbox: str, exclude: set[str]) -> list[str]:
    """Pessoas que o remetente colocou no e-mail e devem continuar na conversa (sem a caixa da EVA nem endereços de sistema)."""
    out = []
    for a in addresses or []:
        a = (a or "").strip().lower()
        if not EMAIL_RE.match(a) or a == mailbox.lower() or a in exclude or a in out:
            continue
        if a.startswith(SYSTEM_PREFIXES):
            continue
        out.append(a)
    return out


def recipients(requester: str, *, intent: str, owners: list[str], added: str = "", to_header=None, cc_header=None,
               mailbox: str = "") -> tuple[list[str], list[str]]:
    """(To, Cc). Mantém quem o remetente pôs em Para/Cc, sempre com o Rogério em cópia;
    mudanças de whitelist vão aos dois donos e a pessoa incluída recebe em cópia."""
    to = [requester]
    if intent in ("whitelist_incluir", "whitelist_remover"):
        to = sorted(set(owners) | {requester})
    to += keep_participants(to_header, mailbox=mailbox or MAILBOX_DEFAULT, exclude=set(to))
    cc = keep_participants(cc_header, mailbox=mailbox or MAILBOX_DEFAULT, exclude=set(to))
    if ROGERIO not in to and ROGERIO not in cc:
        cc.append(ROGERIO)
    added = (added or "").strip().lower()
    if intent == "whitelist_incluir" and EMAIL_RE.match(added) and added not in to and added not in cc:
        cc.append(added)
    return to[:MAX_RECIPIENTS], cc[:max(0, MAX_RECIPIENTS - len(to))]


def next_state(*, next_trust: list[str], next_rogerio: list[str], failed: bool = False, clarification: bool = False,
               requester: str = "") -> str:
    if clarification:
        return "aguardando_rogerio" if requester == ROGERIO else "aguardando_trust"
    if next_trust:
        return "aguardando_trust"
    if next_rogerio:
        return "aguardando_rogerio"
    return "concluido"


def add_business_days(start: datetime, days: int) -> datetime:
    d = start.astimezone(BRT)
    added = 0
    while added < days:
        d += timedelta(days=1)
        if d.weekday() < 5:
            added += 1
    return d


def reminder_due(state: str, last_eva_at: datetime | None, reminders_sent: int, now: datetime) -> str | None:
    """'lembrete' (enviar), 'parar' (marcar parado e avisar Rogério) ou None."""
    if state not in ("aguardando_trust", "aguardando_rogerio") or last_eva_at is None:
        return None
    if now < add_business_days(last_eva_at, 2):
        return None
    return "lembrete" if reminders_sent < 2 else "parar"


def clean_subject(subject: str) -> str:
    s = subject or "Sua solicitação"
    while True:
        new = re.sub(r"^\s*(re|res|fw|fwd|enc|encaminhado)\s*:\s*", "", s, flags=re.I)
        if new == s:
            return s.strip()[:200] or "Sua solicitação"
        s = new


def pages_whitelist(paths: list[str]) -> list[str]:
    """Só caminhos do portal (admin/cliente) viram capturas de tela; limita quantidade."""
    out = []
    for p in paths or []:
        p = (p or "").strip()
        if (re.fullmatch(r"/(admin|t)(/[\w\-/]*)?(\?[\w=&%.\-]*)?", p) or p == "/auth/login") and "logout" not in p and p not in out:
            out.append(p)
    return out[:6]
