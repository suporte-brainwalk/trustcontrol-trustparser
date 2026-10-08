"""Envia, como EVA, a pergunta sobre a versão do Wazuh ao Raphael e ao Alberto (Rogério em cópia) e deixa a conversa
"aguardando Trust" — a resposta deles cai na caixa da EVA, na mesma conversa, e os lembretes automáticos valem.

Uso (dentro do eva-orchestrator):  python -m scripts.pergunta_wazuh [--enviar]   (sem --enviar só mostra o texto)
"""
from __future__ import annotations

import sys

from orchestrator import config, outbox, rules, store

TO = ["raphael.soares@trustcontrol.com.br", "alberto.santos@trustcontrol.com.br"]
SUBJECT = "Trust Parser · qual a versão do Wazuh da Trust?"
REPLY = {
    "saudacao": "Olá, Raphael e Alberto! Tudo bem?",
    "paragrafos": [
        "Sou a EVA, o suporte por IA do Trust Parser. Para deixar a saída para o Wazuh pronta, preciso confirmar um detalhe com vocês.",
        "O Trust Parser já entrega os eventos normalizados para o Wazuh. Só que o jeito de receber muda bastante conforme a versão do "
        "manager: no Wazuh 4.x ele recebe syslog direto e usa decoders e regras em XML (o pacote já está pronto para baixar na tela "
        "do destino). No Wazuh 5.x o motor é novo: os decoders viram YAML no Indexer, as regras viram Sigma e o manager não recebe "
        "syslog direto — precisa de um rsyslog ou do agente lendo os eventos.",
        "Por isso, poderiam me responder com: 1) a versão exata do Wazuh manager (o comando /var/ossec/bin/wazuh-control info mostra); "
        "2) o endereço (IP ou nome) e a porta em que o manager pode receber os eventos; 3) se o recebimento deve ser por syslog TCP, "
        "UDP ou por um agente/rsyslog intermediário.",
        "Com a resposta, eu ajusto o destino e o pacote de decoder/regras para a versão certa, e vocês testam com o botão "
        "“Testar conexão” na tela do destino.",
    ],
    "proximos_passos_trust": ["Responder este e-mail com a versão do Wazuh manager, o endereço/porta e a forma de recebimento."],
    "proximos_passos_eva": ["Assim que vocês responderem, ajusto o destino Wazuh e confirmo por aqui."],
    "fechamento": "Qualquer dúvida, é só responder este e-mail.",
}


def main():
    send = "--enviar" in sys.argv
    store.init()
    html_body, text_body, inline = outbox.render(dict(REPLY), status_key="sem_mudanca", status_text="Aguardando a resposta de vocês — nada foi alterado.",
                                                 shots=[], version="", original=None)
    cc = [rules.ROGERIO] if hasattr(rules, "ROGERIO") else ["rogerio.crispim@brainwalk.com.br"]
    msg = outbox.build(to=TO, cc=cc, subject=SUBJECT, html_body=html_body, text_body=text_body, inline=inline, in_reply_to=None,
                       references=[], request_id=None)
    print(text_body)
    if not send:
        print("\n(simulação — use --enviar para mandar)")
        return
    mid = outbox.smtp_send(msg)
    tid = store.create_thread(SUBJECT, TO[0], mid)
    store.update_thread(tid, state="aguardando_trust", pending=REPLY["proximos_passos_trust"], last_eva_at=store.utcnow())
    store.add_message(tid, None, "out", "email", "eva", SUBJECT, text_body, html=html_body, reply=REPLY, status_key="sem_mudanca",
                      status_text="Aguardando a resposta da Trust.", emailed=True)
    store.audit("eva.pergunta_wazuh", ", ".join(TO), {"thread_id": tid, "message_id": mid})
    print(f"\nenviado: {mid} · conversa {tid} · de {config.MAILBOX}")


if __name__ == "__main__":
    main()
