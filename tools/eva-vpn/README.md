# EVA · Suporte de VPN · Trust Control

Agente determinístico (serviço systemd `eva-vpn` no host) que conduz por e-mail, na caixa `eva-vpn@trustcontrol.nuvem.tec.br`,
a montagem da VPN IPsec Brainwalk ↔ Trust Control — e só isso.

- Lê a caixa a cada 60 s; aceita só Rogério, Raphael, Paulo e Alberto com DKIM válido; responde a todos com o Rogério em cópia.
- IA (OpenRouter, provedor ZDR): só extrai parâmetros em JSON e redige a resposta; validador bloqueia segredos, nomes de
  ferramentas/IA, caminhos e IPs internos (fallback: texto-modelo). A PSK é extraída por regra (linha `PSK: ...`) e removida do
  texto antes de qualquer IA; fica em `/var/lib/eva-vpn/psk` (600) e nunca é repetida.
- Servidor: modelo fixo de strongSwan (IKEv2, DH19, AES-256-GCM/CBC+SHA-256, 8 h/1 h, PFS, IDs por IP, baseada em rota com
  interface XFRM `xfrm-trust` if_id 42, túnel 169.254.99.18/30) + cadeias `EVAVPN-*` (DNAT dos IPs 172.30.254.17/.18/.19 para o
  nginx e o receptor syslog; SNAT .30 para a rede da Trust; saída só para destinos/portas combinados; exceção no TRUSTLABS-EGRESS).
- Aplica só após **APROVADO** do Rogério por e-mail; rollback automático se o servidor não confirmar saúde. `PAUSAR`/`RETOMAR` também por e-mail.
- Estado: `/var/lib/eva-vpn/state.json` · log: `/var/log/eva-vpn.log` · `systemctl status eva-vpn`.
