# Trust Parser — histórico da implantação (07–08/10/2026)

## Linha do tempo
| Quando | O quê |
|---|---|
| 07/10 noite | Plano v0.1 → v0.2 → v0.3 (`docs/PLANO.md`), decisões do Rogério N1–N7, amostras reais (Nginx 3.306 linhas, WithSecure 1.031) |
| 08/10 00:40–01:30 | Motor declarativo (`app/engine/dsl.py`), parsers Nginx e WithSecure (100% das amostras), formatos de saída (UDM, Wazuh, CEF, LEEF, OCSF, CSV), serviços, telas, API, receptor syslog, Estúdio IA; pesquisa de formatos e destinos |
| 08/10 01:24–01:33 | **Incidente:** servidor travou por falta de RAM (builds em paralelo, sem swap). Medidas: swap 4 GB, earlyoom, vigia de memória, builds um por vez |
| 08/10 01:40–02:10 | Deploy: parser-db, parser-app, parser-ingest, nginx (trustparser.*), cert LE, firewall do syslog (`trustparser-fw`), backup, EVA (caixa eva-trustparser@, orquestrador, sandbox via OpenRouter MiMo V2.6 Pro) |
| 08/10 02:00–02:40 | Testes de integração, E2E no navegador, teste de carga (~3.650 EPS), Estúdio IA real (Apache 100%), EVA real (dúvida e manutenção) |
| 08/10 ~02:15 | **Incidente de privacidade:** teste de "formato de saída" do Estúdio enviou até 8 eventos reais (amostra WithSecure) sem máscara ao provedor ZDR. Corrigido: exemplos de saída só sintéticos (+ teste); EVA sem acesso às linhas de log |
| 08/10 02:34 | Limpeza dos dados de teste; EVA em modo ativo; timer 07:45 (`trustparser-golive-convites`) para convites de admin e e-mail da EVA sobre a versão do Wazuh |
| 08/10 02:40–03:10 | Ajustes pós-entrega: login com a marca do Trust Parser, Estúdio IA como submenu da EVA, convite do Rogério (acesso confirmado) |

## Estado entregue
- Portal/API: https://trustparser.trustcontrol.nuvem.tec.br (`/api/v1`, documentação `/api/docs`).
- Entradas: syslog 6514/TCP TLS, 514/TCP e 514/UDP (só IPs liberados na tela), 6 conectores de API, upload (.txt/.log/.json/.csv/.gz/.xlsx).
- Parsers: 13 embutidos — Nginx e WithSecure com amostra real; 11 pela documentação ("validar com dado real"). Detalhes: `docs/parsers.md`.
- Saídas: Google SecOps (API Chronicle e legada), Wazuh (pacote 4.x XML + rascunho 5.x), QRadar LEEF, CEF, OCSF, CSV, syslog, webhook, download.
- Buffer 2 h (não entregue até 24 h), avisos operacionais, auditoria, MFA, perfis admin/gestor/leitor, multitenant.
- Testes: 412 unitários (motor, 75 casos dourados, conectores, EVA) + 15 de integração, todos passando.

## Decisões pós-entrega (Rogério, 08/10)
- Estúdio IA fica como submenu da EVA.
- Fora por ora: saída Splunk, leitura de PDF no Estúdio, caixa de retorno para `trustparser@` (entrada de e-mail só na EVA), pendências de LGPD/hospedagem.
- Parser de Apache gerado no teste do Estúdio segue como rascunho (publicar ou descartar a critério do admin).

## Pendências
- Trust: versão do Wazuh (pergunta enviada pela EVA), credenciais SecOps por cliente, amostras reais dos demais fabricantes, credenciais de API dos conectores, cadastro de tenants/fontes/IPs.
- **VPN Brainwalk ↔ Trust** (próxima etapa): peer 46.224.130.58 ↔ 177.19.132.193, túnel 169.254.99.18/30, nossa rede na VPN 172.30.254.16/28
  (plano: .17 Trust Parser, .18 TrustRadar, .19 Trust Labs, .30 saída dos containers). Conversa por e-mail na caixa dedicada `eva-vpn@`
  (persona "EVA · Suporte de VPN · Trust Control", só Rogério/Raphael/Paulo/Alberto, Rogério sempre em cópia, escopo só VPN, rollback automático).
  Regras e ferramenta ficam fora do Git, no servidor (`/root/trustparser/vpn/`).

## Onde está cada coisa
- Operação: `docs/operacao.md` · Linguagem dos parsers: `docs/dsl.md` · Conectores: `docs/conectores.md` · EVA: `docs/eva.md`
- Infra fora do Git: `/root/docker-compose.yml`, `/root/nginx/` (nginx, cert-watchdog, mem-watchdog, host.crontab), `/root/mailserver/`,
  segredos em `/root/trustparser/secrets/` (600), backups do banco em `/srv/trustparser/backups/`.
