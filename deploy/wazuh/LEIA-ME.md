# Trust Parser → Wazuh

**Primeiro confirme a versão do manager** (`/var/ossec/bin/wazuh-control info`). O formato mudou entre 4.x e 5.x.

## Wazuh 4.x (recomendado hoje — versão estável)
1. No manager, habilite o recebimento syslog em `/var/ossec/etc/ossec.conf`:
   ```xml
   <remote>
     <connection>syslog</connection>
     <port>514</port>
     <protocol>tcp</protocol>
     <allowed-ips>46.224.130.58</allowed-ips>   <!-- IP do Trust Parser -->
   </remote>
   ```
   O syslog do Wazuh 4.x não tem TLS: use VPN/rede privada ou TCP restrito ao IP acima.
2. Copie `trustparser_decoders.xml` para `/var/ossec/etc/decoders/` e `trustparser_rules.xml` para `/var/ossec/etc/rules/`.
3. Teste: `/var/ossec/bin/wazuh-logtest` e cole uma linha (sem o `<14>` inicial), por exemplo:
   `Oct  8 12:00:00 trustparser trustparser: {"srcip":"203.0.113.7","tp":{"product":"trustparser","class_uid":3002,"status":"Failure","severity_id":2,"host":"PC-01","message":"teste"}}`
   Esperado: decoder `trustparser`, campos `tp.*`, regra 100520.
4. `systemctl restart wazuh-manager`.
5. No Trust Parser: Destinos → novo → Wazuh, host do manager, porta 514, TCP, cabeçalho RFC 3164. Use “Testar conexão”.

## Wazuh 5.x (rascunho)
O 5.x usa decoders YAML no Indexer e não recebe syslog direto (rsyslog + agente). O arquivo
`trustparser-wazuh5-integration.yml` é um ponto de partida; precisa ser validado num ambiente 5.x.
Alternativa para 5.x: destino “Syslog genérico” para um rsyslog que grava arquivo lido pelo agente.

Limites: mensagens < 64 KB (o Trust Parser envia ~2–8 KB) e até ~200 campos por evento (o Trust Parser limita).
