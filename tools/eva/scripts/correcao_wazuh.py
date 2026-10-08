"""Correção de 08/10/2026: registra na conversa a pergunta original do Wazuh (que não foi gravada por falha do banco) e
responde corretamente ao Alberto (versão 4.14.7 recebida; faltam endereço/porta/forma de recebimento)."""
import sys
from datetime import datetime, timezone
from sqlalchemy import text
from orchestrator import outbox, store
from scripts.pergunta_wazuh import REPLY as ORIGINAL, SUBJECT

TID = 47
IDS = ["<179145632519.27.15992651803975239258.9bdd812c3ce4@trustcontrol.nuvem.tec.br>",
       "<179146356018.7.14261545365282994341.187f260e9809@trustcontrol.nuvem.tec.br>",
       "<CP4P284MB173155310FDE1766218EF503C1932@CP4P284MB1731.BRAP284.PROD.OUTLOOK.COM>",
       "<CP4P284MB1731072C7A9CB36339E86A7CC1932@CP4P284MB1731.BRAP284.PROD.OUTLOOK.COM>"]
LAST = "<179146391035.7.3100488284170632219.3e0864cc846f@trustcontrol.nuvem.tec.br>"
REPLY = {
    "saudacao": "Olá, Alberto! Tudo bem?",
    "paragrafos": [
        "Peço desculpas pela confusão nas minhas duas últimas mensagens: eu não tinha associado a sua resposta à pergunta que eu mesma fiz hoje cedo sobre o Wazuh. Já corrigi.",
        "Obrigada pela versão: Wazuh 4.14.7. Por ser da linha 4.x, o recebimento por syslog e o pacote de decoder e regras em XML que o Trust Parser fornece servem diretamente — não é preciso nenhuma adaptação para a versão 5.",
        "Para eu deixar o destino Wazuh configurado, faltam só dois pontos: 1) o endereço (IP ou nome) e a porta em que o manager pode receber os eventos — se for pela VPN que estamos montando, pode ser o IP interno; 2) a forma de recebimento: syslog TCP (recomendado) ou UDP.",
    ],
    "passo_a_passo": [
        "No manager, habilitar o recebimento syslog em /var/ossec/etc/ossec.conf, liberando o IP de origem do Trust Parser.",
        "Copiar trustparser_decoders.xml para /var/ossec/etc/decoders/ e trustparser_rules.xml para /var/ossec/etc/rules/ (os arquivos ficam disponíveis na tela do destino Wazuh do Trust Parser).",
        "Reiniciar o wazuh-manager e usar o botão “Testar conexão” na tela do destino.",
    ],
    "proximos_passos_trust": ["Informar o endereço/porta do Wazuh manager e se o recebimento será por syslog TCP ou UDP."],
    "proximos_passos_eva": ["Com esses dados, cadastro o destino Wazuh e confirmo por aqui."],
    "fechamento": "Qualquer dúvida, é só responder este e-mail.",
}


def main():
    store.init()
    with store.tx() as c:
        n = c.execute(text("select count(*) from eva_messages where thread_id=:t and subject=:s and direction='out' and created_at < '2026-10-08 10:46:00+00'"),
                      {"t": TID, "s": SUBJECT}).scalar()
    if not n:
        h, t, _ = outbox.render(dict(ORIGINAL), status_key="sem_mudanca", status_text="Aguardando a resposta de vocês — nada foi alterado.",
                                shots=[], version="", original=None)
        mid = store.add_message(TID, None, "out", "email", "eva", SUBJECT, t, html=h, reply=ORIGINAL, status_key="sem_mudanca",
                                status_text="Aguardando a resposta da Trust.", emailed=True)
        with store.tx() as c:
            c.execute(text("update eva_messages set created_at = '2026-10-08 10:45:25+00' where id=:m"), {"m": mid})
        print("pergunta original registrada na conversa:", mid)
    if "--enviar" not in sys.argv:
        print("simulação"); return
    html_body, text_body, inline = outbox.render(dict(REPLY), status_key="sem_mudanca", status_text="Versão registrada — aguardando endereço e porta do manager.",
                                                 shots=[], version="", original=None)
    msg = outbox.build(to=["alberto.santos@trustcontrol.com.br", "raphael.soares@trustcontrol.com.br"], cc=["rogerio.crispim@brainwalk.com.br"],
                       subject="Re: " + SUBJECT, html_body=html_body, text_body=text_body, inline=inline, in_reply_to=LAST,
                       references=IDS, request_id=None)
    mid = outbox.smtp_send(msg)
    store.add_thread_message_ids(TID, [mid])
    store.add_message(TID, None, "out", "email", "eva", "Re: " + SUBJECT, text_body, html=html_body, reply=REPLY, status_key="sem_mudanca",
                      status_text="Versão registrada — aguardando endereço e porta do manager.", emailed=True)
    store.update_thread(TID, state="aguardando_trust", pending=REPLY["proximos_passos_trust"], last_eva_at=datetime.now(timezone.utc))
    print("enviado", mid)


if __name__ == "__main__":
    main()
