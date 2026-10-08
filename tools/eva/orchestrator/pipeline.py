"""Fluxo determinístico de cada solicitação. A IA é chamada só para: entender, alterar, escolher o que desfazer e redigir."""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import time
import traceback
from datetime import datetime, timezone

import dns.resolver

from . import config, dataapi, deploy, gitops, inbox, openrouter, outbox, policy, prompts, rules, sandbox, store, verify

log = logging.getLogger("eva.pipeline")
FOLDER_OK = "EVA-Processados"
FOLDER_BAD = "EVA-Ignorados"
FRIENDLY_PAGE = {"/auth/login": "Tela de entrada (login)", "/admin/": "Painel do administrador", "/t/": "Painel do cliente",
                 "/admin/tenants": "Tenants", "/admin/fontes": "Fontes", "/admin/firewall": "IPs liberados (syslog)",
                 "/admin/destinos": "Destinos", "/admin/parsers": "Parsers", "/admin/estudio": "Estúdio IA",
                 "/admin/uploads": "Uploads", "/admin/nao-reconhecidos": "Não reconhecidos", "/admin/eva": "EVA", "/admin/api": "API",
                 "/admin/auditoria": "Auditoria", "/admin/configuracoes": "Configurações", "/admin/ajuda": "Ajuda", "/auth/account": "Minha conta"}

# telas de exemplo que o suporte pode anexar numa resposta: chave -> (sessão, caminho, legenda)
SUPPORT_PAGES = {
    "painel": ("admin", "/admin/", "Painel do administrador"), "tenants": ("admin", "/admin/tenants", "Lista de tenants"),
    "tenant_detalhe": ("admin", "/admin/tenants/{tenant}", "Detalhe de um tenant"),
    "fontes": ("admin", "/admin/fontes", "Fontes"), "fonte_detalhe": ("admin", "/admin/fontes/{source}", "Detalhe de uma fonte"),
    "ips_liberados": ("admin", "/admin/firewall", "Syslog · IPs liberados"),
    "destinos": ("admin", "/admin/destinos", "Destinos"), "destino_detalhe": ("admin", "/admin/destinos/{destination}", "Detalhe de um destino"),
    "parsers": ("admin", "/admin/parsers", "Parsers"), "estudio": ("admin", "/admin/estudio", "Estúdio IA"),
    "uploads": ("admin", "/admin/uploads", "Uploads e downloads"), "nao_reconhecidos": ("admin", "/admin/nao-reconhecidos", "Não reconhecidos"),
    "eva": ("admin", "/admin/eva", "EVA · pessoas autorizadas"), "api_chaves": ("admin", "/admin/api", "Sistema · API (chaves de acesso)"),
    "auditoria": ("admin", "/admin/auditoria", "Auditoria"), "configuracoes": ("admin", "/admin/configuracoes", "Configurações"),
    "ajuda": ("admin", "/admin/ajuda", "Ajuda"), "minha_conta": ("admin", "/auth/account", "Minha conta"),
    "cliente_painel": ("gestor", "/t/", "Área do cliente · Visão geral"),
}


def support_targets(keys) -> list[str]:
    """Filtra deterministicamente as telas escolhidas pela IA: só chaves conhecidas, sem repetição, no máximo 2."""
    out = []
    for k in keys or []:
        if isinstance(k, str) and k in SUPPORT_PAGES and k not in out:
            out.append(k)
    return out[:2]


def now():
    return datetime.now(timezone.utc)


def first_name(name: str, email: str) -> str:
    n = (name or "").strip().split()
    return n[0].title() if n else email.split("@")[0].split(".")[0].title()


def secrets() -> list[str]:
    extra = [config.MAIL_PASSWORD, config.openrouter_key(), config.API_KEY]
    return policy.load_secrets(config.SECRET_ENV_FILES, extra=[e for e in extra if e])


def domain_signs_mail(domain: str) -> bool:
    """Heurística determinística: domínio publica DKIM em seletores comuns (Google, Microsoft 365, genéricos)."""
    r = dns.resolver.Resolver()
    r.lifetime = 6
    for sel in ("google", "selector1", "selector2", "default", "k1", "s1", "s2", "dkim", "mail", "zoho", "mandrill", "brainwalk"):
        for rtype in ("TXT", "CNAME"):
            try:
                if r.resolve(f"{sel}._domainkey.{domain}", rtype):
                    return True
            except Exception:  # noqa: BLE001
                continue
    return False


# ======================================================================= ENTRADA
def ingest(mailbox: inbox.Mailbox) -> int:
    wl = store.whitelist()
    mode = store.get_setting("eva_mode", "demo")
    queued = 0
    for uid, sender, auto in mailbox.list_new():
        entry = wl.get(sender)
        if not entry or sender == config.MAILBOX or auto:
            mailbox.mark(uid)  # não é conversa com a EVA: fica na caixa, só marcada como examinada
            continue
        raw = mailbox.fetch(uid)
        inc = inbox.parse(uid, raw)
        if inbox.age_hours(raw) > 24:
            mailbox.mark(uid)  # e-mail antigo (anterior à EVA ou atrasado): não é pedido novo nem tentativa de fraude
            continue
        dkim_ok, dkim_why = inbox.dkim_aligned(raw, inc.sender)
        action, reason = rules.admit(inc.sender, wl, mode=mode, dkim_ok=dkim_ok, auto_generated=inc.auto_generated,
                                     from_count=inc.from_count, mailbox=config.MAILBOX)
        if action == "ignorar":
            mailbox.mark(uid)
            continue
        if action in ("rejeitar", "demo"):
            store.audit("eva.email_rejeitado" if action == "rejeitar" else "eva.email_modo_demo", inc.sender,
                        {"motivo": reason, "dkim": dkim_why, "assunto": inc.subject[:200]})
            mailbox.mark(uid, FOLDER_BAD)
            if action == "rejeitar":
                from . import monitor
                monitor.alert("autenticacao", f"E-mail em nome de {inc.sender} rejeitado: {reason} ({dkim_why}). Assunto: {inc.subject[:120]}")
            continue
        if store.request_exists(inc.message_id):
            mailbox.mark(uid, FOLDER_OK)
            continue
        th = store.find_thread(inc.in_reply_to + inc.references)
        tid = th["id"] if th else store.create_thread(rules.clean_subject(inc.subject), inc.sender, inc.message_id)
        store.add_thread_message_ids(tid, [inc.message_id] + inc.in_reply_to)
        rid = store.create_request(tid, inc.message_id, inc.sender, inc.subject, {"uid": uid, "dkim": dkim_why})
        reqdir = os.path.join(config.REQUESTS_DIR, str(rid))
        files = inbox.save_request_files(reqdir, inc)
        store.update_request(rid, details={"uid": uid, "dkim": dkim_why, **files, "nome": inc.sender_name, "channel": "email"})
        store.add_message(tid, rid, "in", "email", inc.sender, inc.subject, inc.text)  # a conversa fica visível também pela API
        store.audit("eva.pedido_recebido", inc.sender, {"pedido": rid, "assunto": inc.subject[:200], "imagens": len(files["images"])})
        mailbox.mark(uid, FOLDER_OK)
        queued += 1
    return queued


# ======================================================================= PROCESSAMENTO
class Job:
    def __init__(self, req):
        self.req = dict(req)
        self.rid = req["id"]
        self.dir = os.path.join(config.REQUESTS_DIR, str(self.rid))
        raw = open(os.path.join(self.dir, "mensagem.eml"), "rb").read()
        self.inc = inbox.parse(req["details"].get("uid", ""), raw)
        self.inc.image_names = req["details"].get("images", [])
        self.inc.image_info = req["details"].get("image_info", {})
        self.thread = dict(store.thread(req["thread_id"]))
        self.channel = "api" if (req["details"] or {}).get("channel") == "api" else "email"
        self.wl = store.whitelist()
        self.role = (self.wl.get(self.inc.sender) or {}).get("role", "member")
        self.session = self.thread.get("session_id") or None
        self.secrets = secrets()
        self.cost = 0.0
        self.instances: list[dict] = []
        self.timeline: list[str] = []

    def ai(self, prompt, schema, *, write=False, timeout=1500, web_search=False):
        # o modelo às vezes não fecha a saída estruturada (error_max_structured_output_retries): tenta de novo, até 3 vezes
        for attempt in range(3):
            try:
                res = sandbox.run_claude(prompt, system=prompts.PERSONA, schema=schema, request_dir=self.dir, write=write,
                                         session_id=self.session, timeout=timeout, web_search=web_search)
                break
            except sandbox.SandboxError as e:
                if attempt == 2 or not any(x in str(e) for x in ("structured", "sem saída", "resposta inválida")):
                    raise
                log.warning("pedido %s: nova tentativa da IA (%s)", self.rid, str(e)[:120])
        self.session = res["session_id"] or self.session
        self.cost += res.get("cost") or 0
        store.update_thread(self.thread["id"], session_id=self.session or "")
        return res["structured"]

    def note(self, msg):
        self.timeline.append(f"{time.strftime('%H:%M:%S')} {msg}")
        log.info("pedido %s: %s", self.rid, msg)


def _prepare_api(req) -> dict | None:
    """Pedido da API: confere as mesmas condições do e-mail no momento de processar e monta a mensagem no formato de um
    e-mail (com as imagens como anexos) na pasta do pedido. Recusado: grava a resposta na conversa e devolve None."""
    details = dict(req["details"] or {})
    sender = req["sender"]
    ok, why = rules.admit_api(sender, store.whitelist(), mode=store.get_setting("eva_mode", "demo"),
                              demo_extra=config.DEMO_EXTRA_SENDERS)
    if not ok:
        store.update_request(req["id"], status="failed", error=why, finished_at=now())
        store.add_message(req["thread_id"], req["id"], "out", "api", "eva", "Re: " + rules.clean_subject(req["subject"]),
                          f"Não posso atender este pedido agora: {why}. Nada foi alterado.", status_key="nao_publicado",
                          status_text="Pedido não atendido — nada foi alterado.")
        store.audit("eva.pedido_api_recusado", sender, {"pedido": req["id"], "motivo": why})
        return None
    msg, images = store.api_message(req["id"])
    if msg is None:
        raise RuntimeError("mensagem do pedido não encontrada")
    raw = inbox.build_api_message(sender=sender, name=details.get("nome", ""), mailbox=config.MAILBOX, cc=details.get("cc") or [],
                                  subject=req["subject"], text=msg["body_text"], message_id=req["message_id"],
                                  in_reply_to=details.get("in_reply_to", ""), references=details.get("references") or [], images=images)
    inc = inbox.parse("", raw)
    files = inbox.save_request_files(os.path.join(config.REQUESTS_DIR, str(req["id"])), inc)
    details.update(files)
    store.update_request(req["id"], details=details)
    store.audit("eva.pedido_recebido", sender, {"pedido": req["id"], "assunto": req["subject"][:200], "imagens": len(files["images"]),
                                                    "canal": "api", "chave": details.get("chave", "")})
    return {**dict(req), "details": details}


def process_next() -> bool:
    req = store.next_queued()
    if not req:
        return False
    job = None
    api = (req["details"] or {}).get("channel") == "api"
    outbox.capture({"thread_id": req["thread_id"], "request_id": req["id"], "channel": "api" if api else "email",
                    "deliver": (not api) or bool((req["details"] or {}).get("email_copy", True))})
    try:
        if api:
            req = _prepare_api(req)
            if req is None:
                return True
        job = Job(req)
        _process(job)
    except Exception as e:  # noqa: BLE001
        log.exception("falha no pedido %s", req["id"])
        err = f"{type(e).__name__}: {str(e)[:500]}"
        store.update_request(req["id"], status="failed", error=err, finished_at=now())
        try:
            if job:
                _send_failure_notice(job, err)
            elif api:
                store.add_message(req["thread_id"], req["id"], "out", "api", "eva", "Re: " + rules.clean_subject(req["subject"]),
                                  "Recebi seu pedido, mas tive um problema técnico e não consegui concluir. Nada foi alterado; o Rogério foi avisado.",
                                  status_key="nao_publicado", status_text="Não consegui concluir — nada foi alterado.")
        except Exception:  # noqa: BLE001
            log.exception("falha ao avisar sobre o pedido %s", req["id"])
        from . import monitor
        monitor.alert("pedido_falhou", f"Pedido nº {req['id']} de {req['sender']} falhou: {err}")
    finally:
        outbox.capture(None)
        if job:
            for inst in job.instances:
                verify.stop_instance(inst)
            subprocess.run(["docker", "image", "rm", "-f", f"eva-cand:{job.rid}"], capture_output=True)
            try:
                gitops.reset_worktree()
            except Exception:  # noqa: BLE001
                pass
    return True


def _process(job: Job):
    job.base_sha = gitops.sync_worktree()  # cópia idêntica ao GitHub para leitura já na etapa de entendimento
    recent = store.recent_changes()
    job.note("entendendo o pedido")
    cls = job.ai(prompts.classify(job.inc, job.role, recent), prompts.INTENT_SCHEMA, timeout=900)
    intent = cls["intent"] if cls.get("intent") in rules.INTENTS else "esclarecimento"
    store.update_request(job.rid, intent=intent, summary=cls.get("entendimento", "")[:500])
    job.note(f"intenção: {intent}")
    if intent == "pergunta":
        return _question(job, cls)
    if intent == "esclarecimento":
        return _clarify(job, cls, cls.get("perguntas") or [])
    if intent == "fora_de_escopo":
        return _out_of_scope(job, cls)
    if intent in ("whitelist_incluir", "whitelist_remover"):
        return _whitelist(job, cls, intent)
    if intent == "manutencao":
        return _maintenance(job, cls)
    if intent == "desfazer":
        target = next((c for c in recent if c["id"] == cls.get("desfazer_id")), None)
        if not target:
            return _clarify(job, cls, cls.get("perguntas") or ["Qual das mudanças recentes você quer que eu desfaça?"])
        if target["intent"] == "manutencao":
            return _undo_maintenance(job, cls, target)
        return _change(job, cls, undo=target)
    return _change(job, cls)


# ----------------------------------------------------------------------- respostas
def _reply_and_close(job: Job, *, facts: dict, status_key: str, status_text: str, intent: str, shots=None, version="",
                     deployed=False, next_trust=None, next_rogerio=None, clarification=False, summary="", extra_request=None, added=""):
    facts = {**facts, "solicitante": first_name(job.req["details"].get("nome", ""), job.inc.sender), "publicado": deployed,
             "situacao": status_text}
    if job.channel == "api":
        facts["canal"] = "pedido feito pela API do Trust Parser: a pessoa lê e responde pela própria API (não diga 'responda este e-mail')"
    reply = None
    for attempt in range(2):
        try:
            reply = job.ai(prompts.reply(facts) + ("\n\nATENÇÃO: a versão anterior foi recusada pela revisão automática: " + "; ".join(problems) if attempt else ""),
                           prompts.REPLY_SCHEMA, timeout=600)
        except sandbox.SandboxError:
            reply = None
            break
        texts = [reply.get("saudacao", ""), reply.get("fechamento", "")] + reply.get("paragrafos", []) + reply.get("o_que_fiz", []) + \
            reply.get("proximos_passos_trust", []) + reply.get("proximos_passos_rogerio", []) + reply.get("proximos_passos_eva", [])
        problems = policy.validate_reply(texts, deployed=deployed or status_key == "desfeito", secrets=job.secrets)
        if not problems:
            break
        reply = None
    if reply is None:
        reply = _fallback_reply(facts, status_text)
    if next_trust is not None:
        reply["proximos_passos_trust"] = reply.get("proximos_passos_trust") or next_trust
    if next_rogerio is not None:
        reply["proximos_passos_rogerio"] = reply.get("proximos_passos_rogerio") or next_rogerio
    mail_shots = []
    for s in shots or []:
        item = {"legenda": FRIENDLY_PAGE.get(s["titulo"], "Tela alterada")}
        for label in ("antes", "depois"):
            if s.get(label):
                item[f"{label}_png"] = verify.shrink(s[label])
        mail_shots.append(item)
    original = None
    mode = store.get_setting("eva_mode", "demo")
    owners = [e for e, w in job.wl.items() if w["role"] == "owner" and w.get("active", True)]
    to, cc = rules.recipients(job.inc.sender, intent=intent, owners=owners, added=added, to_header=job.inc.to,
                              cc_header=job.inc.cc, mailbox=config.MAILBOX)
    if mode == "demo":
        to, cc = [rules.ROGERIO], []
    if rules.ROGERIO not in [a.lower() for a in job.inc.cc] and job.inc.sender != rules.ROGERIO:
        original = {"de": job.inc.sender, "texto": job.inc.text}
    html_body, text_body, inline = outbox.render(reply, status_key=status_key, status_text=status_text, shots=mail_shots, version=version, original=original)
    leak = policy.scan_secrets(html_body + text_body, job.secrets)
    if leak:
        raise RuntimeError("resposta bloqueada: segredo detectado no texto")
    subject = "Re: " + rules.clean_subject(job.inc.subject)
    msg = outbox.build(to=to, cc=cc, subject=subject, html_body=html_body, text_body=text_body, inline=inline, in_reply_to=job.inc.message_id,
                       references=job.inc.references, request_id=job.rid)
    mid = outbox.send(msg)
    trust = reply.get("proximos_passos_trust") or []
    rog = reply.get("proximos_passos_rogerio") or []
    state = rules.next_state(next_trust=trust, next_rogerio=rog, clarification=clarification, requester=job.inc.sender)
    store.update_thread(job.thread["id"], state=state, pending=(trust + rog)[:10], last_eva_at=now(), reminders_sent=0)
    store.add_thread_message_ids(job.thread["id"], [mid])
    store.update_request(job.rid, status="done", reply_message_id=mid, finished_at=now(), summary=(summary or job.req.get("summary") or "")[:500],
                         details={**job.req["details"], "custo_ia_usd": round(job.cost, 4), "linha_do_tempo": job.timeline[-40:], **(extra_request or {})})
    job.note(f"resposta enviada ({state})")


def _fallback_reply(facts: dict, status_text: str) -> dict:
    return {"saudacao": f"Olá, {facts.get('solicitante', '')}!", "paragrafos": ["Recebi sua mensagem e já tratei por aqui."],
            "o_que_fiz": facts.get("o_que_foi_feito") or [], "proximos_passos_trust": [], "proximos_passos_rogerio": [],
            "proximos_passos_eva": [], "fechamento": "Se precisar de qualquer ajuste, é só responder este e-mail."}


def _send_failure_notice(job: Job, err: str):
    reply = {"saudacao": f"Olá, {first_name(job.req['details'].get('nome', ''), job.inc.sender)}!",
             "paragrafos": ["Recebi seu pedido, mas tive um problema técnico do meu lado e não consegui concluir agora.",
                            "Nada foi alterado no Trust Parser. O Rogério já foi avisado para verificar."],
             "o_que_fiz": [], "proximos_passos_trust": [], "proximos_passos_rogerio": ["Verificar o problema da EVA no servidor."],
             "proximos_passos_eva": ["Assim que o problema for resolvido, você pode reenviar o pedido respondendo este e-mail."], "fechamento": ""}
    to, cc = ([rules.ROGERIO], []) if store.get_setting("eva_mode", "demo") == "demo" else rules.recipients(job.inc.sender, intent="", owners=[], to_header=job.inc.to, cc_header=job.inc.cc, mailbox=config.MAILBOX)
    html_body, text_body, inline = outbox.render(reply, status_key="nao_publicado", status_text="Não consegui concluir — nada foi alterado.", shots=[], version="", original=None)
    msg = outbox.build(to=to, cc=cc, subject="Re: " + rules.clean_subject(job.inc.subject), html_body=html_body, text_body=text_body, inline=inline,
                       in_reply_to=job.inc.message_id, references=job.inc.references, request_id=job.rid)
    mid = outbox.send(msg)
    store.add_thread_message_ids(job.thread["id"], [mid])
    store.update_thread(job.thread["id"], state="aguardando_rogerio", pending=["Verificar falha técnica da EVA"], last_eva_at=now())


# ----------------------------------------------------------------------- tipos simples
def _question(job: Job, cls):
    job.note("respondendo dúvida (suporte)")
    telas = {k: v[2] for k, v in SUPPORT_PAGES.items()}
    ans, problems = None, []
    for attempt in range(2):
        extra = ("\n\nATENÇÃO: a versão anterior foi recusada pela revisão automática: " + "; ".join(problems)) if attempt else ""
        ans = job.ai(prompts.answer_question(job.inc, config.PORTAL_URL, telas) + extra, prompts.SUPPORT_SCHEMA, timeout=900)
        ans = _with_data(job, ans, prompts.SUPPORT_SCHEMA)
        texts = [ans.get("saudacao", ""), ans.get("fechamento", "")] + ans.get("paragrafos", []) + ans.get("proximos_passos_eva", []) + \
            ans.get("passo_a_passo", []) + ans.get("proximos_passos_trust", []) + ans.get("proximos_passos_rogerio", [])
        problems = policy.validate_reply(texts, deployed=False, secrets=job.secrets)
        if not problems:
            break
    if problems:
        return _reply_and_close(job, facts={"tipo": "pergunta", "pergunta_entendida": cls.get("entendimento")}, status_key="sem_mudanca",
                                status_text="Respondi sua dúvida — nada foi alterado no Trust Parser.", intent="pergunta")
    ans["o_que_fiz"] = []
    shots = []
    keys = support_targets(ans.get("telas"))
    if keys:
        try:
            shots = _support_shots(job, keys)
        except Exception as e:  # noqa: BLE001 — a resposta segue sem imagens
            log.warning("capturas de suporte indisponíveis: %s", e)
            job.note("capturas de tela indisponíveis; resposta enviada sem imagens")
    _send_prepared(job, ans, shots=shots, intent="pergunta", summary=cls.get("entendimento", ""))


def _with_data(job: Job, ans: dict, schema: dict, rounds: int = 2) -> dict:
    """Se o agente pediu dados do Trust Parser, consulta pela API (só leitura, rotas validadas) e pede a resposta de novo."""
    seen: dict = {}
    for _ in range(rounds):
        wanted = [p for p in (ans.get("consultar_dados") or []) if p not in seen][:dataapi.MAX_QUERIES]
        if not wanted:
            break
        got = dataapi.consult(wanted)
        seen.update(got)
        job.note(f"consultou dados do Trust Parser: {', '.join(got)}"[:300])
        ans = job.ai(prompts.data_results(got), schema, timeout=900)
    ans["consultar_dados"] = []
    return ans


def _support_shots(job: Job, keys: list[str]) -> list[dict]:
    job.note("capturando telas de exemplo")
    sha = gitops.sync_worktree()
    img = f"eva-base:{sha[:12]}"
    if not verify.image_exists(img):
        verify.build_image(img, config.WORK_REPO)
    inst = None
    try:
        inst = verify.start_instance("eva-inst-antes", img, "trustparser_eva_antes")
        files = verify.capture_pages(inst, [SUPPORT_PAGES[k][:2] for k in keys], os.path.join(job.dir, "suporte"))
    finally:
        verify.stop_instance(inst)
    shots = []
    for k, fn in zip(keys, files):
        shots.append({"legenda": f"Tela de exemplo · {SUPPORT_PAGES[k][2]}", "tela_png": verify.shrink(fn)})
    return shots


def _send_prepared(job: Job, reply, *, shots, intent, summary):
    status_text = "Respondi sua dúvida — nada foi alterado no Trust Parser."
    mode = store.get_setting("eva_mode", "demo")
    owners = [e for e, w in job.wl.items() if w["role"] == "owner"]
    to, cc = rules.recipients(job.inc.sender, intent=intent, owners=owners, to_header=job.inc.to, cc_header=job.inc.cc,
                              mailbox=config.MAILBOX)
    if mode == "demo":
        to, cc = [rules.ROGERIO], []
    original = None
    if rules.ROGERIO not in [a.lower() for a in job.inc.cc] and job.inc.sender != rules.ROGERIO:
        original = {"de": job.inc.sender, "texto": job.inc.text}
    html_body, text_body, inline = outbox.render(reply, status_key="sem_mudanca", status_text=status_text, shots=shots, version="", original=original)
    if policy.scan_secrets(html_body + text_body, job.secrets):
        raise RuntimeError("resposta bloqueada: segredo detectado no texto")
    msg = outbox.build(to=to, cc=cc, subject="Re: " + rules.clean_subject(job.inc.subject), html_body=html_body, text_body=text_body, inline=inline,
                       in_reply_to=job.inc.message_id, references=job.inc.references, request_id=job.rid)
    mid = outbox.send(msg)
    trust, rog = reply.get("proximos_passos_trust") or [], reply.get("proximos_passos_rogerio") or []
    store.update_thread(job.thread["id"], state=rules.next_state(next_trust=trust, next_rogerio=rog), pending=(trust + rog)[:10], last_eva_at=now(), reminders_sent=0)
    store.add_thread_message_ids(job.thread["id"], [mid])
    store.update_request(job.rid, status="done", reply_message_id=mid, finished_at=now(), summary=summary[:500],
                         details={**job.req["details"], "custo_ia_usd": round(job.cost, 4), "linha_do_tempo": job.timeline[-40:]})
    job.note("resposta enviada")


def _clarify(job: Job, cls, questions):
    job.note("pedindo esclarecimento")
    return _reply_and_close(job, facts={"tipo": "esclarecimento", "pedido_entendido": cls.get("entendimento"), "perguntas": questions,
                                        "instrucao": "Faça as perguntas de forma objetiva, de preferência com opções (A/B). Nada foi alterado."},
                            status_key="sem_mudanca", status_text="Antes de mexer, preciso de uma confirmação sua — nada foi alterado ainda.",
                            intent="esclarecimento", clarification=True, next_trust=questions if job.inc.sender != rules.ROGERIO else None,
                            next_rogerio=questions if job.inc.sender == rules.ROGERIO else None)


def _out_of_scope(job: Job, cls):
    job.note("fora de escopo")
    store.audit("eva.pedido_recusado", job.inc.sender, {"pedido": job.rid, "motivo": cls.get("parte_fora_de_escopo") or cls.get("entendimento")})
    return _reply_and_close(job, facts={"tipo": "fora_de_escopo", "pedido_entendido": cls.get("entendimento"),
                                        "motivo": cls.get("parte_fora_de_escopo") or "O pedido não é sobre o Trust Parser ou envolve algo que a EVA não pode fazer.",
                                        "instrucao": "Explique com gentileza por que não pode fazer, sugira uma alternativa dentro do escopo se houver e, se fizer sentido, indique que o Rogério pode avaliar."},
                            status_key="nao_publicado", status_text="Este pedido eu não posso fazer — nada foi alterado.", intent="fora_de_escopo")


def _whitelist(job: Job, cls, intent):
    email = (cls.get("whitelist_email") or "").strip().lower()
    name = (cls.get("whitelist_nome") or "").strip()
    ok, why = rules.whitelist_change(intent, job.inc.sender, job.wl, email, name)
    if ok and intent == "whitelist_incluir" and not domain_signs_mail(email.rsplit("@", 1)[-1]):
        ok, why = False, "o domínio desse e-mail não assina as mensagens (DKIM), então eu não teria como confirmar que os pedidos vêm mesmo dessa pessoa"
    if ok:
        if intent == "whitelist_incluir":
            store.whitelist_add(email, name, job.inc.sender)
            status = f"Pronto: {email} agora pode fazer pedidos à EVA."
        else:
            store.whitelist_remove(email, job.inc.sender)
            status = f"Pronto: {email} não pode mais fazer pedidos à EVA."
        job.wl = store.whitelist()
    else:
        status = "Não alterei a lista de pessoas autorizadas."
    return _reply_and_close(job, facts={"tipo": intent, "pessoa": {"email": email, "nome": name}, "alterado": ok, "motivo": why,
                                        "instrucao": "Confirme a alteração da lista de pessoas autorizadas (ou explique por que não foi feita). "
                                                     "Se incluída: a pessoa está em cópia deste e-mail; dê boas-vindas a ela e explique em poucas "
                                                     f"linhas que já pode escrever para {config.MAILBOX} pedindo ajustes no Trust Parser, "
                                                     "manutenção (tenants, fontes, IPs liberados, destinos, pessoas, pedidos ao Estúdio IA) "
                                                     "ou tirando dúvidas sobre como usar cada menu, sempre do próprio e-mail corporativo."},
                            status_key="publicado" if ok else "nao_publicado", status_text=status, intent=intent, deployed=ok, summary=status,
                            added=email if ok and intent == "whitelist_incluir" else "")


# ----------------------------------------------------------------------- alteração / desfazer
def _change(job: Job, cls, undo: dict | None = None):
    base_sha = gitops.sync_worktree()
    base_img = f"eva-base:{base_sha[:12]}"
    if not verify.image_exists(base_img):
        job.note("preparando versão atual para comparação")
        verify.build_image(base_img, config.WORK_REPO)
    base_count = store.get_setting(f"eva_testes_{base_sha[:12]}")
    if base_count is None:
        base_count = verify.count_tests(base_img)
        store.set_setting(f"eva_testes_{base_sha[:12]}", base_count)
    impl = {"resumo": "", "o_que_fiz": [], "paginas": [], "emails": [], "proximos_passos_trust": [], "proximos_passos_rogerio": [], "nao_consegui": ""}
    if undo:
        job.note(f"desfazendo a mudança nº {undo['id']}")
        try:
            gitops.revert(undo["commit_sha"])
        except gitops.GitError as e:
            return _not_published(job, cls, [str(e)], impl, undo=undo)
        prev = undo.get("details") or {}
        impl.update(resumo=f"Desfeita a mudança nº {undo['id']}: {undo['summary'][:80]}", paginas=prev.get("paginas", []), emails=prev.get("emails", []),
                    o_que_fiz=[f"Voltei como estava antes da mudança “{undo['summary'][:120]}”."])
        patch = gitops.git("show", "--binary", "--no-color", "HEAD")
        deleted_ok = set(re.findall(r"^diff --git a/(\S+) b/\S+\ndeleted file mode", patch, flags=re.M))
        verdict = policy.check_diff(patch, job.secrets, allow_deletions_of=deleted_ok)
        if not verdict.ok:
            return _not_published(job, cls, verdict.violations, impl, undo=undo)
        tests = verify.run_tests(verify.build_image(f"eva-cand:{job.rid}", config.WORK_REPO), os.path.join(job.dir, "testes"))
        if not tests.ok:
            return _not_published(job, cls, ["os testes automáticos falharam ao desfazer"] + tests.failures[:3], impl, undo=undo)
        vis = _visual(job, base_img, impl)
        if not vis.ok:
            return _not_published(job, cls, vis.problems, impl, undo=undo)
        return _publish(job, cls, impl, tests, vis, commit_sha=gitops.git("rev-parse", "HEAD"), base_sha=base_sha, undo=undo)

    job.note("alterando")
    impl = job.ai(prompts.implement(job.inc, cls.get("entendimento", ""), cls.get("parte_fora_de_escopo", "")), prompts.CHANGE_SCHEMA, write=True, timeout=2700)
    tests = vis = None
    problems: list[str] = []
    for attempt in range(3):
        patch = gitops.staged_patch()
        if not patch.strip():
            return _no_change(job, cls, impl)
        verdict = policy.check_diff(patch, job.secrets)
        if not verdict.ok:
            problems = verdict.violations
            job.note(f"política recusou: {problems[:2]}")
            if attempt == 2:
                return _not_published(job, cls, problems, impl, attempts=3)
            impl = job.ai(prompts.fix("A alteração saiu das regras e foi recusada: " + "; ".join(problems) +
                                      ". Desfaça essas partes e mantenha só o que é permitido."), prompts.CHANGE_SCHEMA, write=True, timeout=1800)
            continue
        job.note("rodando testes")
        cand_img = verify.build_image(f"eva-cand:{job.rid}", config.WORK_REPO)
        tests = verify.run_tests(cand_img, os.path.join(job.dir, f"testes-{attempt + 1}"))
        if tests.collected and base_count and tests.collected < base_count:
            tests.ok = False
            tests.failures.insert(0, f"a quantidade de testes caiu de {base_count} para {tests.collected}")
        if not tests.ok:
            problems = ["testes automáticos falharam"] + tests.failures[:5]
            job.note(f"testes falharam ({tests.failed + tests.errors})")
            if attempt == 2:
                return _not_published(job, cls, problems, impl, tests=tests, attempts=3)
            impl = job.ai(prompts.fix("Testes que falharam:\n" + "\n\n".join(tests.failures[:8]) + "\n\nFinal da saída:\n" + tests.output_tail[-1500:]),
                          prompts.CHANGE_SCHEMA, write=True, timeout=1800)
            continue
        job.note(f"testes ok ({tests.collected}); verificando telas")
        vis = _visual(job, base_img, impl)
        if not vis.ok:
            problems = vis.problems
            job.note(f"verificação visual falhou: {problems[:2]}")
            if attempt == 2:
                return _not_published(job, cls, problems, impl, tests=tests, attempts=3)
            impl = job.ai(prompts.fix("A verificação das telas encontrou problemas:\n" + "\n".join(vis.problems[:15])), prompts.CHANGE_SCHEMA,
                          write=True, timeout=1800)
            continue
        break
    sha = gitops.commit(f"EVA: {impl.get('resumo') or cls.get('entendimento', '')[:100]}\n\nSolicitado por {job.inc.sender} (pedido nº {job.rid}).")
    return _publish(job, cls, impl, tests, vis, commit_sha=sha, base_sha=base_sha)


def _visual(job: Job, base_img: str, impl: dict) -> verify.VisualResult:
    for inst in job.instances:
        verify.stop_instance(inst)
    job.instances = []
    base = verify.start_instance("eva-inst-antes", base_img, "trustparser_eva_antes")
    job.instances.append(base)
    cand = verify.start_instance("eva-inst-depois", f"eva-cand:{job.rid}", "trustparser_eva_depois")
    job.instances.append(cand)
    pages = rules.pages_whitelist(impl.get("paginas", []))
    emails = [e for e in impl.get("emails", []) if e in verify.EMAIL_PAGES]
    return verify.visual_check(base, cand, pages, emails, os.path.join(job.dir, "capturas"))


def _publish(job: Job, cls, impl, tests, vis, *, commit_sha: str, base_sha: str, undo: dict | None = None):
    ok_prod, why = gitops.prod_status()
    if not ok_prod:
        from . import monitor
        monitor.alert("deploy_bloqueado", f"Pedido nº {job.rid}: {why}. Nada publicado.")
        return _not_published(job, cls, [why], impl, tests=tests, undo=undo)
    job.note("publicando")
    try:
        gitops.push()
        commit_sha = gitops.git("rev-parse", "HEAD")
        gitops.prod_pull()
    except gitops.GitError as e:
        return _not_published(job, cls, [str(e)], impl, tests=tests, undo=undo)
    ok, detail = deploy.publish()
    problems = [] if ok else [f"o Trust Parser não ficou saudável após publicar ({detail})"]
    if ok:
        problems = deploy.smoke_production(rules.pages_whitelist(impl.get("paginas", [])))
    if problems:
        job.note(f"verificação no ar falhou: {problems[:2]} — voltando versão anterior")
        rb_ok, rb_detail = deploy.rollback_image()
        try:
            gitops.revert(commit_sha)
            gitops.push()
            gitops.prod_pull()
        except gitops.GitError as e:
            problems.append(f"reversão no GitHub precisa de atenção: {e}")
        from . import monitor
        monitor.alert("rollback", f"Pedido nº {job.rid}: verificação pós-publicação falhou ({'; '.join(problems)[:300]}). "
                                  f"Versão anterior restaurada: {'ok' if rb_ok else 'FALHOU ' + rb_detail}.")
        store.update_request(job.rid, commit_sha=commit_sha, deployed=False, rolled_back=True)
        return _reply_and_close(job, facts={"tipo": "desfazer" if undo else "alteracao", "pedido_entendido": cls.get("entendimento"),
                                            "o_que_foi_feito": impl.get("o_que_fiz"), "motivo_nao_publicado": "a verificação automática logo após publicar encontrou um problema, então voltei sozinho para a versão anterior",
                                            "o_trust_parser_continua": "funcionando normalmente, como antes do pedido"},
                                status_key="nao_publicado", status_text="Tentei publicar, mas a verificação no ar falhou — voltei automaticamente para a versão anterior.",
                                intent="alteracao", summary=impl.get("resumo", ""), next_rogerio=["Avaliar por que a verificação pós-publicação falhou."])
    store.update_request(job.rid, commit_sha=commit_sha, deployed=True)
    if undo:
        store.update_request(undo["id"], reverted_by=job.rid)
    store.audit("eva.desfeito_publicado" if undo else "eva.alteracao_publicada", impl.get("resumo", "")[:300],
                {"pedido": job.rid, "por": job.inc.sender, "versao": commit_sha[:10], "testes": tests.collected if tests else None})
    job.note("publicado e verificado")
    status = "Pronto! Desfiz a mudança e o Trust Parser já voltou a ser como era." if undo else "Pronto! A alteração já está no ar."
    return _reply_and_close(job, facts={"tipo": "desfazer" if undo else "alteracao", "pedido_entendido": cls.get("entendimento"),
                                        "o_que_foi_feito": impl.get("o_que_fiz"), "nao_consegui": impl.get("nao_consegui"),
                                        "parte_fora_de_escopo": cls.get("parte_fora_de_escopo"),
                                        "verificacoes": {"testes_automaticos_aprovados": tests.collected if tests else None,
                                                         "telas_verificadas_modo_claro_escuro_celular_computador": vis.checked if vis else None},
                                        "proximos_passos_sugeridos_trust": impl.get("proximos_passos_trust"),
                                        "proximos_passos_sugeridos_rogerio": impl.get("proximos_passos_rogerio"),
                                        "pode_desfazer": "sim, basta pedir respondendo o e-mail"},
                            status_key="desfeito" if undo else "publicado", status_text=status, intent="alteracao", deployed=True,
                            shots=vis.shots if vis else [], version=commit_sha[:10], summary=impl.get("resumo", ""),
                            extra_request={"paginas": impl.get("paginas", []), "emails": impl.get("emails", [])})


def _no_change(job: Job, cls, impl):
    job.note("nenhuma alteração produzida")
    return _reply_and_close(job, facts={"tipo": "alteracao_sem_mudanca", "pedido_entendido": cls.get("entendimento"),
                                        "motivo": impl.get("nao_consegui") or "não encontrei o que alterar com segurança",
                                        "proximos_passos_sugeridos_trust": impl.get("proximos_passos_trust")},
                            status_key="nao_publicado", status_text="Não fiz nenhuma alteração desta vez.", intent="alteracao",
                            next_trust=impl.get("proximos_passos_trust"), summary=impl.get("resumo", ""))


def _not_published(job: Job, cls, problems: list[str], impl, *, tests=None, undo=None, attempts: int = 1):
    gitops.reset_worktree()
    store.update_request(job.rid, error="; ".join(problems)[:1500])
    return _reply_and_close(job, facts={"tipo": "desfazer" if undo else "alteracao", "pedido_entendido": cls.get("entendimento"),
                                        "motivo_nao_publicado_para_explicar_em_linguagem_simples": problems[:6],
                                        "tentativas_de_ajuste_feitas": attempts,
                                        "alteracao_descartada": "sim — nada ficou pendente; posso refazer quando o problema for resolvido",
                                        "o_trust_parser_continua": "funcionando normalmente, sem nenhuma alteração"},
                            status_key="nao_publicado", status_text="Não publiquei — as verificações automáticas não passaram. O Trust Parser segue como estava.",
                            intent="alteracao", summary=impl.get("resumo", "") or cls.get("entendimento", ""),
                            next_rogerio=["Avaliar o pedido que a EVA não conseguiu publicar."] if not undo else None)


# ----------------------------------------------------------------------- manutenção (tenants, fontes, IPs, destinos, Estúdio, pessoas)
MAINT_MODULE = "app.services.eva_maintenance"


def _maint_cli(mode: str, payload: dict, requester: str) -> dict:
    """Executa a manutenção DENTRO do container da aplicação (serviços do Trust Parser, mesma regra da tela).
    JSON no stdin, JSON na última linha do stdout. Fora do alcance de edição da EVA (paths.DENY_WRITE)."""
    import json as _json
    r = subprocess.run(["docker", "exec", "-i", "-w", "/app", config.MAINT_CONTAINER, "python", "-m", MAINT_MODULE,
                        "--modo", mode, "--solicitante", requester], input=_json.dumps(payload), capture_output=True, text=True, timeout=600)
    lines = [ln for ln in (r.stdout or "").splitlines() if ln.strip().startswith("{")]
    if not lines:
        raise RuntimeError(f"manutenção sem resposta ({r.returncode}): {(r.stderr or r.stdout)[-300:]}")
    return _json.loads(lines[-1])


def _maintenance(job: Job, cls):
    job.note("planejando manutenção")
    plan = job.ai(prompts.maintenance(job.inc, cls.get("entendimento", "")), prompts.MAINT_SCHEMA, timeout=1500)
    plan = _with_data(job, plan, prompts.MAINT_SCHEMA)
    results = []
    for attempt in range(3):
        if not plan.get("operacoes"):
            break
        test = _maint_cli("testar", {"operacoes": plan["operacoes"]}, job.inc.sender)
        results = test.get("resultados") or []
        if test.get("erro"):
            results = [{"ok": False, "erro": test["erro"]}]
        job.note(f"simulação das operações: {sum(1 for r in results if r.get('ok'))}/{len(results)} ok")
        if results and all(r.get("ok") for r in results):
            break
        if attempt == 2:
            break
        plan = job.ai(prompts.maintenance_feedback(results), prompts.MAINT_SCHEMA, timeout=1500)
    ok_all = bool(plan.get("operacoes")) and bool(results) and all(r.get("ok") for r in results)
    applied = []
    if ok_all:
        out = _maint_cli("aplicar", {"operacoes": plan["operacoes"]}, job.inc.sender)
        applied = out.get("resultados") or []
        ok_all = bool(applied) and all(r.get("ok") for r in applied) and not out.get("erro")
    if ok_all:
        store.update_request(job.rid, deployed=True)
        store.audit("eva.manutencao_aplicada", plan.get("resumo", "")[:300], {"pedido": job.rid, "por": job.inc.sender, "operacoes": len(applied)})
        job.note("manutenção aplicada")
        facts = {"tipo": "manutencao", "pedido_entendido": cls.get("entendimento"), "o_que_foi_feito": plan.get("o_que_fiz"),
                 "resultado_das_operacoes": [{"operacao": r.get("tipo"), "resultado": r.get("resumo"), "aviso": r.get("aviso")} for r in applied],
                 "onde_ver": "Trust Parser, área do administrador (Tenants, Fontes, IPs liberados, Destinos ou Estúdio IA, conforme o caso)",
                 "proximos_passos_sugeridos_trust": plan.get("proximos_passos_trust"),
                 "lembretes": "credenciais de destinos/conectores são cadastradas por um administrador na tela; versão criada pelo Estúdio IA "
                              "só passa a valer depois que um administrador aprovar e publicar",
                 "pode_desfazer": "sim, basta pedir respondendo o e-mail (o que foi incluído é desativado; o que foi editado volta como era)"}
        return _reply_and_close(job, facts=facts, status_key="publicado", status_text="Pronto! A manutenção já está valendo no Trust Parser.",
                                intent="manutencao", deployed=True, summary=plan.get("resumo", ""),
                                extra_request={"manutencao": applied, "operacoes": plan.get("operacoes")})
    job.note("manutenção não aplicada")
    reasons = [r.get("erro") for r in results if r.get("erro")] or [plan.get("nao_consegui") or "faltaram informações para concluir"]
    return _reply_and_close(job, facts={"tipo": "manutencao_nao_aplicada", "pedido_entendido": cls.get("entendimento"),
                                        "motivos_para_explicar_em_linguagem_simples": reasons[:6], "nao_consegui": plan.get("nao_consegui"),
                                        "o_trust_parser_continua": "sem nenhuma alteração nos cadastros",
                                        "proximos_passos_sugeridos_trust": plan.get("proximos_passos_trust")},
                            status_key="nao_publicado", status_text="Não apliquei a manutenção — nada foi alterado no Trust Parser.",
                            intent="manutencao", next_trust=plan.get("proximos_passos_trust"), summary=plan.get("resumo", ""))


def _undo_maintenance(job: Job, cls, target: dict):
    job.note(f"desfazendo a manutenção nº {target['id']}")
    applied = (target.get("details") or {}).get("manutencao") or []
    out = _maint_cli("desfazer", {"resultados": applied}, job.inc.sender) if applied else {"resultados": []}
    ok = bool(out.get("resultados")) and all(r.get("ok") for r in out["resultados"])
    if ok:
        store.update_request(job.rid, deployed=True)
        store.update_request(target["id"], reverted_by=job.rid)
    return _reply_and_close(job, facts={"tipo": "desfazer_manutencao", "pedido_entendido": cls.get("entendimento"), "manutencao_original": target["summary"],
                                        "resultado": out.get("resultados") or out.get("erro"),
                                        "observacao": "o que foi incluído foi desativado (não excluído); o que foi editado voltou como era; "
                                                      "pedido ao Estúdio IA ainda na fila foi cancelado"},
                            status_key="desfeito" if ok else "nao_publicado",
                            status_text="Pronto! Desfiz a manutenção e os cadastros voltaram a ser como eram." if ok else "Não consegui desfazer — nada foi alterado.",
                            intent="desfazer", deployed=ok, summary=f"Desfeita a manutenção nº {target['id']}")


# ======================================================================= LEMBRETES
def reminders():
    for th in store.threads_waiting():
        due = rules.reminder_due(th["state"], th["last_eva_at"], th["reminders_sent"], now())
        if not due:
            continue
        ids = th["message_ids"] or []
        last_id = ids[-1] if ids else None
        mode = store.get_setting("eva_mode", "demo")
        if due == "parar":
            store.update_thread(th["id"], state="parado")
            store.audit("eva.conversa_parada", th["subject"], {"conversa": th["id"], "pendencias": th["pending"]})
            from . import monitor
            monitor.alert(f"parado_{th['id']}", f"A conversa “{th['subject']}” com {th['requester']} ficou sem resposta após 2 lembretes. Pendências: {'; '.join(th['pending'])[:400]}")
            continue
        facts = {"assunto": th["subject"], "pendencias": th["pending"], "quem_precisa_responder": "time Trust Control" if th["state"] == "aguardando_trust" else "Rogério",
                 "lembrete_numero": th["reminders_sent"] + 1}
        try:
            got, _cost = openrouter.chat_json(prompts.REMINDER_SYSTEM, prompts.reminder(facts), max_tokens=800)
            reply = {"saudacao": str(got.get("saudacao") or "Olá!"), "paragrafos": [str(x) for x in (got.get("paragrafos") or [])][:4],
                     "o_que_fiz": [], "proximos_passos_trust": th["pending"] if th["state"] == "aguardando_trust" else [],
                     "proximos_passos_rogerio": th["pending"] if th["state"] == "aguardando_rogerio" else [], "proximos_passos_eva": [],
                     "fechamento": str(got.get("fechamento") or "")}
            texts = [reply["saudacao"], reply["fechamento"]] + reply["paragrafos"]
            if not reply["paragrafos"] or policy.validate_reply(texts, deployed=False, secrets=secrets()):
                raise openrouter.OpenRouterError("lembrete recusado pela revisão")
        except openrouter.OpenRouterError:
            reply = {"saudacao": "Olá!", "paragrafos": [f"Passando para lembrar da nossa conversa sobre “{th['subject']}”."],
                     "o_que_fiz": [], "proximos_passos_trust": th["pending"] if th["state"] == "aguardando_trust" else [],
                     "proximos_passos_rogerio": th["pending"] if th["state"] == "aguardando_rogerio" else [], "proximos_passos_eva": [],
                     "fechamento": "Quando puder, é só responder este e-mail."}
        to = [th["requester"]] if th["state"] == "aguardando_trust" else [rules.ROGERIO]
        cc = [] if rules.ROGERIO in to else [rules.ROGERIO]
        if mode == "demo":
            to, cc = [rules.ROGERIO], []
        last = store.last_request(th["id"])
        ld = dict((last or {}).get("details") or {})
        api = ld.get("channel") == "api"
        outbox.capture({"thread_id": th["id"], "request_id": None, "channel": "api" if api else "email",
                        "deliver": not (api and not ld.get("email_copy", True) and th["state"] == "aguardando_trust")})
        try:
            html_body, text_body, inline = outbox.render(reply, status_key="sem_mudanca", status_text="Lembrete: ainda aguardo um retorno para continuar.",
                                                         shots=[], version="", original=None)
            msg = outbox.build(to=to, cc=cc, subject="Re: " + th["subject"], html_body=html_body, text_body=text_body, inline=inline,
                               in_reply_to=last_id, references=ids[-10:], request_id=None)
            mid = outbox.send(msg)
        finally:
            outbox.capture(None)
        store.add_thread_message_ids(th["id"], [mid])
        store.update_thread(th["id"], reminders_sent=th["reminders_sent"] + 1, last_eva_at=now())
        store.audit("eva.lembrete_enviado", th["subject"], {"conversa": th["id"], "numero": th["reminders_sent"] + 1})


def cleanup_leftovers():
    for prefix in ("eva-sbx-", "eva-inst-"):
        names = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}", "--filter", f"name={prefix}"], capture_output=True, text=True).stdout.split()
        for n in names:
            subprocess.run(["docker", "rm", "-f", n], capture_output=True)
    tmp = os.path.join(config.STATE_DIR, "tmp")
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp, exist_ok=True)
