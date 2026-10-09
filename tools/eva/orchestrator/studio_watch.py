"""Acompanhamento determinístico (sem IA) dos pedidos que a EVA abriu no Estúdio IA.

Quando a EVA pede algo ao Estúdio (estudio_pedir), ela promete avisar quem pediu. Este laço cumpre a promessa:
a cada mudança de situação do pedido (rascunho pronto, publicado, descartado, falhou) manda um e-mail fixo na
mesma conversa, com o Rogério em cópia, e ajusta as pendências da conversa. Falhas passageiras do provedor de IA
já são repetidas pelo próprio Estúdio; aqui só chega a falha definitiva.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import text

from . import config, monitor, outbox, rules, store

log = logging.getLogger("eva.estudio")
TRACK_KEY = "eva_studio_track"  # {job_id: {"thread", "request", "sender", "notified"}}
FINAL = {"approved", "rejected", "failed"}


def _portal(path: str) -> str:
    return config.PORTAL_URL.rstrip("/") + path


def decide(job: dict, *, requester_admin: bool) -> dict | None:
    """Mensagem e novo estado da conversa para a situação atual do pedido (ou None se não há o que avisar).
    job: id, kind, title, status, error, parser_id, parser_name."""
    jid, st, kind = job["id"], job["status"], job["kind"]
    page = _portal(f"/admin/estudio/{jid}")
    if st == "done":
        steps = [f"Abrir o pedido nº {jid} no portal: {page}",
                 "Conferir a cobertura das amostras, os testes e o resultado gerado.",
                 "Clicar em “Aprovar e publicar” (ou “Descartar”, se algo não estiver certo)."]
        if kind == "secops":
            steps.append("Depois da aprovação, o download fica no botão “⬇ Parser para o Google SecOps (CBN)” da página do parser.")
        quem = "você mesmo pode fazer a revisão, porque tem perfil de administrador no portal" if requester_admin \
            else "um administrador do portal faz a revisão"
        return {"status_key": "sem_mudanca", "status_text": f"Pedido nº {jid} pronto — aguardando revisão e aprovação.",
                "paragrafos": [f"O Estúdio IA terminou o pedido nº {jid} ({job['title']}). O resultado está como rascunho, pronto para a revisão.",
                               f"Antes de valer, {quem}: são poucos cliques."],
                "passo_a_passo": steps,
                "state": "aguardando_trust" if requester_admin else "aguardando_rogerio",
                "pending": [f"Revisar e aprovar o pedido nº {jid} no Estúdio IA ({page})."]}
    if st == "approved":
        paras = [f"O pedido nº {jid} ({job['title']}) foi aprovado e publicado."]
        steps = []
        if kind == "secops" and job.get("parser_id"):
            url = _portal(f"/admin/parsers/{job['parser_id']}/secops.conf")
            paras.append("O parser para o Google SecOps (CBN) já está disponível para download no portal.")
            steps = [f"Baixar o arquivo: {url} (ou, no portal, Parsers › {job.get('parser_name') or 'parser'} › “⬇ Parser para o Google SecOps (CBN)”).",
                     "No Google SecOps: Configurações do SIEM › Parsers › localizar o tipo de log indicado no início do arquivo › Criar parser personalizado.",
                     "Colar o conteúdo do arquivo, carregar de 10 a 50 linhas reais em Amostras de log e clicar em Preview / Validate.",
                     "Se os eventos saírem corretos, clicar em Submit / Ativar.",
                     f"Passo a passo completo: {_portal('/admin/parsers/secops-leia-me')}"]
        else:
            paras.append("Ele já está valendo no Trust Parser.")
        return {"status_key": "publicado", "status_text": f"Pedido nº {jid} publicado.", "paragrafos": paras,
                "passo_a_passo": steps, "state": "concluido", "pending": []}
    if st == "rejected":
        return {"status_key": "sem_mudanca", "status_text": f"Pedido nº {jid} descartado.",
                "paragrafos": [f"O pedido nº {jid} ({job['title']}) foi descartado na revisão e não entrou em produção.",
                               "Se quiser uma nova tentativa com outro ajuste, é só responder este e-mail dizendo o que mudar."],
                "passo_a_passo": [], "state": "concluido", "pending": []}
    if st == "failed":
        return {"status_key": "nao_publicado", "status_text": f"Pedido nº {jid} não foi concluído — já estamos tratando.",
                "paragrafos": [f"O Estúdio IA não conseguiu concluir o pedido nº {jid} ({job['title']}), mesmo após novas tentativas automáticas.",
                               "Nada foi alterado em produção. Já avisei o Rogério para verificar e refazer o pedido; volto a escrever assim que estiver pronto."],
                "passo_a_passo": [], "state": "aguardando_rogerio",
                "pending": [f"Verificar a falha do pedido nº {jid} no Estúdio IA ({(job.get('error') or '')[:160]}) e refazê-lo."]}
    return None


def discover(track: dict) -> dict:
    """Inclui no acompanhamento os pedidos ao Estúdio registrados nas manutenções da EVA."""
    with store.tx() as c:
        rows = c.execute(text("""select id, thread_id, sender, details from eva_requests
                                 where details::text like '%estudio_pedir%' and thread_id is not null""")).all()
    for rid, tid, sender, details in rows:
        for item in (details or {}).get("manutencao") or []:
            jid = ((item or {}).get("ids") or {}).get("job_id")
            if item.get("tipo") == "estudio_pedir" and item.get("ok") and jid and str(jid) not in track:
                track[str(jid)] = {"thread": tid, "request": rid, "sender": sender, "notified": ""}
    return track


def follow(track: dict, jid: str, *, thread: int, request: int | None, sender: str, notified: str = "") -> dict:
    """Acompanha um pedido aberto à mão (ex.: refeito pelo Rogério) na mesma conversa."""
    track[str(jid)] = {"thread": thread, "request": request, "sender": sender, "notified": notified}
    return track


def tick():
    track = discover(dict(store.get_setting(TRACK_KEY) or {}))
    changed = False
    for jid, t in sorted(track.items(), key=lambda kv: int(kv[0])):
        if t.get("notified") in FINAL:
            continue
        with store.tx() as c:
            row = c.execute(text("""select j.id, j.kind, j.title, j.status, j.error, j.parser_id, p.name
                                    from studio_jobs j left join parsers p on p.id = j.parser_id where j.id = :j"""), {"j": int(jid)}).first()
            admin = c.execute(text("select 1 from users where lower(email)=lower(:e) and role='admin' and status='active'"),
                              {"e": t.get("sender") or ""}).first() is not None
        if row is None:
            t["notified"] = "rejected"
            changed = True
            continue
        job = dict(zip(("id", "kind", "title", "status", "error", "parser_id", "parser_name"), row))
        if job["status"] == t.get("notified"):
            continue
        msg = decide(job, requester_admin=admin)
        if msg is None:
            continue
        try:
            _send(t, job, msg)
        except Exception:  # noqa: BLE001
            log.exception("estúdio: falha ao avisar sobre o pedido %s", jid)
            continue
        t["notified"] = job["status"]
        changed = True
        if job["status"] == "failed":
            monitor.alert(f"estudio_falhou_{jid}", f"O pedido nº {jid} do Estúdio IA ({job['title']}) falhou: {(job['error'] or '')[:300]}. "
                                                   f"A EVA avisou {t.get('sender')} e aguarda você refazer o pedido.")
    if changed:
        store.set_setting(TRACK_KEY, track)


def _send(t: dict, job: dict, m: dict):
    th = store.thread(t["thread"])
    if th is None:
        return
    ids = th["message_ids"] or []
    name = (t.get("sender") or "").split("@")[0].split(".")[0].capitalize()
    reply = {"saudacao": f"Olá, {name}!" if name else "Olá!", "paragrafos": m["paragrafos"], "o_que_fiz": [],
             "passo_a_passo": m["passo_a_passo"],
             "proximos_passos_trust": m["pending"] if m["state"] == "aguardando_trust" else [],
             "proximos_passos_rogerio": m["pending"] if m["state"] == "aguardando_rogerio" else [], "proximos_passos_eva": [],
             "fechamento": "Qualquer dúvida, é só responder este e-mail."}
    to, cc = [t["sender"]], [rules.ROGERIO]
    if t["sender"] == rules.ROGERIO:
        cc = []
    if store.get_setting("eva_mode", "demo") == "demo":
        to, cc = [rules.ROGERIO], []
    outbox.capture({"thread_id": th["id"], "request_id": t.get("request"), "channel": "email", "deliver": True})
    try:
        html_body, text_body, inline = outbox.render(reply, status_key=m["status_key"], status_text=m["status_text"],
                                                     shots=[], version="", original=None)
        msg = outbox.build(to=to, cc=cc, subject="Re: " + rules.clean_subject(th["subject"]), html_body=html_body, text_body=text_body,
                           inline=inline, in_reply_to=ids[-1] if ids else None, references=ids[-10:], request_id=t.get("request"))
        mid = outbox.send(msg)
    finally:
        outbox.capture(None)
    store.add_thread_message_ids(th["id"], [mid])
    store.update_thread(th["id"], state=m["state"], pending=m["pending"], reminders_sent=0, last_eva_at=datetime.now(timezone.utc))
    store.audit("eva.estudio_aviso", th["subject"], {"conversa": th["id"], "pedido": job["id"], "situacao": job["status"]})
    log.info("estúdio: aviso do pedido %s (%s) enviado", job["id"], job["status"])
