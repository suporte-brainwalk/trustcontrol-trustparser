# Trust Parser — plano v0.2 (para aprovação)

Data: 08/10/2026 · Autor: Rogério Crispim / Claude · Status: **aguardando aprovação**
Histórico: v0.1 (08/10) → v0.2 (08/10) incorpora as respostas do Rogério às dúvidas 1–10.

## 1. Objetivo

Portal web + API **multitenant** que recebe logs e eventos de segurança por três vias: **syslog seguro**, **upload de
arquivo** e **coleta por API** dos serviços em nuvem. Ele faz o **parsing determinístico** para um modelo canônico e
**entrega o evento já parseado** no destino e no formato escolhidos: Google SecOps (UDM), Wazuh, QRadar (LEEF) ou
download .txt. A IA estuda amostras e documentação e **gera** parsers e mapeamentos de saída. Esses artefatos são
versionados e testados. **A IA não fica no caminho de cada log.**

- URL: https://trustparser.trustcontrol.nuvem.tec.br (DNS A → 46.224.130.58 feito 08/10). O tráfego passa pelo
  nginx-proxy existente com geofiltro BR e cert LE via webroot.
- Suporte por IA: **EVA**, no e-mail eva-trustparser@trustcontrol.nuvem.tec.br e na conversa pela API, nos moldes do Jarbas.
- Repo: github.com/suporte-brainwalk/trustcontrol-trustparser (alias SSH `github-tc-trustparser`).

## 2. Princípios

1. **Determinístico em produção.** Cada linha passa por um parser declarativo versionado (regex/grok, KV, JSON, CEF,
   LEEF, CSV, XML, structured-data do syslog), por mapeamento de campos e por normalização (datas/fuso, IPs, severidade,
   correção de acentuação quebrada). Mesma entrada, mesma saída.
2. **IA só em tempo de projeto.** Ela gera o parser, o mapeamento e os casos de teste a partir de amostras e da
   documentação. Também explica as linhas que não casaram com nenhum parser e propõe ajustes. Tudo passa por **testes
   dourados** (amostra → saída esperada) e **aprovação de admin**, e cada publicação vira uma nova versão com rollback.
3. **Nada some sem aviso.** Linha não reconhecida vai para "Não reconhecidos", com o comportamento configurável por
   fonte: reter, encaminhar bruto com etiqueta ou descartar. Há métrica de cobertura por fonte e alerta de **deriva**
   quando o fabricante muda o formato.
4. **Segredos só de escrita.** Credenciais de destinos e conectores ficam cifradas no banco (AES-GCM, chave mestra fora
   do banco). A tela e a API nunca devolvem o valor, só "cadastrado em DD/MM/AAAA por X" e o botão **Testar**.
5. **Buffer curto.** Dado bruto e parseado ficam no máximo **2 horas** (ver dúvida N1 sobre destino fora do ar).

## 3. Arquitetura

```
 Dispositivos ──syslog TLS 6514──▶ parser-ingest ─┐
 APIs SaaS ◀──pull── parser-collector ────────────┤
 Upload (tela/API) ──▶ parser-app ────────────────┼─▶ fila (Postgres) ─▶ parser-worker ─▶ destinos / download
                                                   │                     (parse → OCSF → formato → envio)
 Documentação + amostras ─▶ Estúdio IA (parser-app) ─▶ parsers/mapeamentos versionados + testes dourados
 Regras de IP (tela/API) ─▶ parser-fw-sync (host) ─▶ ipset/iptables da porta 6514
```

| Componente | Papel | Base |
|---|---|---|
| `parser-app` | Flask: GUI (Jinja/Tailwind, claro/escuro, pt-BR, DD/MM/AAAA) + API v1 + Estúdio IA | código do TrustRadar |
| `parser-worker` | parsing, roteamento, envio em lote com retentativa/backoff, fila morta, métricas | worker do TrustRadar (advisory lock) |
| `parser-ingest` | receptor syslog RFC 5425 (TLS 1.2/1.3, mTLS opcional), RFC 3164/5424, octet-counting e quebra por linha | novo (Python asyncio) |
| `parser-collector` | conectores de API (pull) com cursor, limite de taxa e retentativa | novo |
| `parser-db` | PostgreSQL 18 próprio, separado do portal-db | igual ao portal-db |
| `parser-fw-sync` | serviço **no host** (systemd) que aplica as regras de IP da tela ao firewall | padrão `trustlabs-fw` |
| `eva-orchestrator` + `eva-egress` + sandbox | EVA, com saída do sandbox liberada **só para openrouter.ai** | cópia do Jarbas |

- Rede própria `trustparser_net`. O nginx-proxy entra nela, como no Trust Labs. Sem acesso ao portal-db, ao Trust Labs
  ou ao host.
- **Modelo canônico interno: OCSF** (padrão aberto de eventos de segurança). Os mapeamentos de saída partem dele.

### 3.1 Firewall de syslog pela GUI (pedido do Rogério)

- Tela "Syslog → IPs permitidos", também disponível na API, por tenant e por fonte: IP ou CIDR IPv4, descrição,
  validade opcional e ativo/inativo.
- O container **não** mexe no firewall. O `parser-fw-sync` no host lê o estado desejado pela API interna (chave
  própria, só leitura), valida e aplica atomicamente num ipset (`ipset swap`). A regra fica em
  `iptables -t raw PREROUTING` na 6514: **só IPs da lista passam, o resto é DROP**. Funciona antes do DNAT e durante o
  boot, como no Trust Labs.
- Travas: recusa `0.0.0.0/0` e prefixos maiores que /16, salvo confirmação explícita de admin. Toda mudança fica
  auditada. A tela mostra "aplicado no firewall às HH:MM" ou o erro.
- O syslog **não** tem geofiltro BR, porque serviços em nuvem enviam de fora do Brasil. A proteção é a lista de IPs
  mais TLS. A 6514 também precisa ser liberada no firewall da Hetzner.
- Proteções extras: limite de conexões e de taxa por IP, e tamanho máximo de mensagem.
- A fonte é identificada pelo IP de origem, pelo hostname do syslog e pelo certificado de cliente (mTLS) quando o
  equipamento suporta.

## 4. Entradas — todas entregues com parser pronto e cadastrado

| Tecnologia | Via | Formato | Base do parser |
|---|---|---|---|
| Nginx | syslog TLS / upload | access log custom delimitado por ` \| ` (13 campos) + combined/JSON | **amostra real** (3.306 linhas) |
| WithSecure Elements | syslog (conector on-prem) / API / upload | JSON {facility, hostname, priority, message} com `[alertMeta@0 k="v" …]` + XML de evento Windows embutido | **amostra real** (1.031 linhas, 7 tipos de evento) |
| WatchGuard Firebox | syslog TLS / upload | syslog WatchGuard (traffic/event/alarm, msg_id) | documentação |
| WatchGuard EPDR | syslog (SIEM Feeder) / API / upload | CEF/LEEF | documentação |
| Cortex XDR | syslog / API (alertas, incidentes) / upload | CEF / JSON | documentação |
| Trend Vision One | syslog (Service Gateway) / API / upload | CEF / JSON | documentação |
| Axur | API / upload | JSON (tickets, detecções) | documentação |
| Tenable | API / upload | JSON/CSV (vulnerabilidades, ativos) | documentação |

- Parsers feitos só com documentação são publicados como **"v1 — validar com dado real"**. A tela mostra o selo até
  chegar a primeira amostra real com 100% de cobertura.
- **Novos formatos pela tela:** em "Estúdio → Nova entrada" o usuário informa a tecnologia, envia amostras e anexa a
  documentação (PDF/HTML/URL). A IA propõe parser, mapeamento OCSF e testes. O sistema roda os testes e mostra
  cobertura e campos lado a lado. O admin aprova e publica.
- Variações do mesmo fabricante, como cada cliente ter um `log_format` de Nginx diferente, viram **variantes** do
  parser, detectadas automaticamente pela assinatura da linha.
- Upload aceita .txt/.log/.json/.csv e .gz (ver dúvida N4 sobre .xlsx).

## 5. Saídas — evento já parseado

| Destino | Entrega | O que a Trust cadastra na GUI (por tenant) |
|---|---|---|
| Google SecOps | eventos **UDM** pela API de ingestão, em lote | Customer ID, região, credencial de service account (JSON) e, se for a API nova do Chronicle, projeto e instância; rótulo de namespace opcional |
| Wazuh | JSON por syslog TLS/TCP ao manager + **decoders e regras XML gerados** para importar | host, porta, transporte, certificado de CA opcional, versão do Wazuh |
| QRadar (baixa prioridade) | LEEF 2.0 por syslog | host, porta, transporte, identificador de log source |
| Download | botão/API por fonte, período ou upload | JSONL (UDM, OCSF ou Wazuh), CEF, LEEF, CSV |
| Genérico (fase 2) | webhook HTTPS / syslog TLS | URL, cabeçalhos/segredos |

- Cada destino tem filtros (fonte/tipo/severidade), lote, limite de envio, **Testar conexão** (evento sintético) e
  painel de entregas e falhas.
- O Wazuh segue a documentação oficial e a Trust testa depois. Os decoders e regras ficam disponíveis para download
  na tela.
- **Novas saídas pela tela:** "Estúdio → Nova saída", com a IA lendo a documentação do destino. O mesmo ciclo vale:
  proposta → testes → aprovação → versão.

## 6. Portal e API (reaproveitado do TrustRadar)

- Login por magic link, MFA TOTP, perfis Administrador (Trust) / Gestor / Leitor, auditoria.
- **Tenant = cliente da Trust.** Cada tenant tem suas fontes, conectores, destinos e IPs. O admin vê tudo.
- Telas: Painel (EPS, cobertura, fila, falhas por destino), Fontes, Syslog/IPs permitidos, Conectores de API, Parsers
  (versões, testes, diff), Destinos, Uploads/Downloads, Não reconhecidos, Estúdio IA, Tenants, Pessoas, **EVA
  (quem pode falar)**, Configurações.
- API v1 com chave, escopos, IP permitido, OpenAPI e paginação. Tem leitura e escrita com as mesmas regras da tela.
- Dimensionamento: o servidor atual atende o início. O painel mede EPS e uso de recursos para sabermos quando migrar
  para uma VM dedicada.

## 7. EVA (suporte por IA)

- Mesma estrutura do Jarbas: orquestrador determinístico, DKIM verificado, sandbox sem segredos ou banco, testes antes
  e depois, deploy com rollback, Rogério em cópia, linguagem humana, nunca cita fabricante ou modelo de IA.
- **Quem pode falar com a EVA é cadastrado pelo admin na GUI**, com papéis dono e membro e também pela API.
- Usa a chave OpenRouter dedicada com **xiaomi/mimo-v2.6-pro**, só em provedores ZDR. Validado em 08/10: o endpoint
  compatível do OpenRouter faz chamadas com ferramentas no MiMo, então reaproveitamos o harness do Jarbas.
- Intenções: dúvidas de uso, manutenção (fontes, IPs, conectores, destinos, tenants, pessoas), **pedir nova entrada ou
  saída** (dispara o Estúdio, e a publicação continua exigindo aprovação de admin), ajustes de front-end e textos.
- Proibido: banco/migrações, segurança/login/MFA, segredos, firewall/infra, a própria EVA.

## 8. IA

- Principal: xiaomi/mimo-v2.6-pro (US$ 0,435 / 0,87 por milhão de tokens in/out, 1 M de contexto). Reserva:
  deepseek-v4-flash-0731. A bancada com as amostras reais acontece na fase 1.
- O custo e o limite da chave (hoje US$ 3/mês) serão avaliados nos testes. Haverá teto local com aviso, como no TrustRadar.
- Amostras enviadas à IA passam por **mascaramento** de IPs, usuários, hosts e e-mails, com reversão local.

## 9. Dados de amostra (recebidos 08/10)

- `Raw-Logs.zip`: NGINX.xlsx e WITH_SECURE.xlsx, aparentemente exportados de busca de log bruto do SecOps (colunas
  timestamp e raw log). Ficam em `/root/trustparser/samples` (0600, fora do Git).
- Os arquivos contêm **dados reais de clientes**: nomes de usuários, hosts, IPs e razão social. Por isso o repo recebe
  só versões **anonimizadas** para os testes dourados.
- Achados que o parser já precisa tratar: o Nginx tem dois timestamps (UTC do coletor e local -0300) e lista de IPs
  X-Forwarded-For (IPv4/IPv6). O WithSecure tem acentos com dupla codificação (`InformaÃ§Ãµes`), timestamps em epoch
  (s e ms), XML de evento Windows (4625 etc.) dentro de um campo e IPs com máscara (`192.168.113.61/24 …`).

## 10. Fases e entregáveis

| Fase | Entregas |
|---|---|
| 0 — Base | repo, cert, containers, nginx, banco, login/MFA/perfis/tenants, CI de testes |
| 1 — Núcleo | motor declarativo + testes dourados + OCSF; upload → parse → download; parsers **Nginx e WithSecure (reais)**; bancada IA |
| 2 — Syslog | `parser-ingest` TLS 6514, fontes, **firewall pela GUI** (`parser-fw-sync`), métricas, fila morta |
| 3 — Parsers por documentação | Firebox, EPDR, Cortex XDR, Vision One, Axur, Tenable (selo "validar com dado real") |
| 4 — Conectores de API | WithSecure, Cortex XDR, Vision One, EPDR, Axur, Tenable, com credenciais cadastradas pela Trust na GUI |
| 5 — Saídas | SecOps UDM, Wazuh (JSON + decoders/regras), QRadar LEEF, download; credenciais na GUI; teste de conexão |
| 6 — Estúdio IA | nova entrada/saída por IA, documentação, diff, aprovação, versões, deriva, "não reconhecidos" |
| 7 — EVA | e-mail + API, lista de autorizados na GUI, sandbox OpenRouter, testes E2E |
| 8 — Aceite | carga, relatório de testes, manual, UAT da Trust |

## 11. Novas dúvidas

- **N1. Destino fora do ar por mais de 2 h** (ex.: SecOps indisponível). Proposta: o buffer de 2 h vale para o que já
  foi entregue. O que **não foi entregue** fica até 24 h, com limite de disco e alerta, e só depois é descartado.
  Ou descartamos em 2 h mesmo?
- **N2. Syslog sem TLS.** Alguns equipamentos (Firebox antigo, por exemplo) só enviam UDP/TCP sem criptografia.
  Aceitamos TCP 514 sem TLS, por fonte e só para IPs liberados, ou fica **somente TLS**?
- **N3. Google SecOps.** A Trust usa a API de ingestão clássica (Customer ID + service account) ou a API nova do
  Chronicle no Google Cloud (projeto/instância)? Proposta: suportar as duas.
- **N4. Upload de .xlsx.** As amostras vieram em planilha exportada do SecOps. Aceitamos .xlsx/.csv nesse formato
  (coluna "raw log") no upload?
- **N5. Amostras do restante.** Firebox, EPDR, Cortex XDR, Vision One, Axur e Tenable sairão por documentação. Se a
  Trust tiver exportações (mesmo pequenas) ou um tenant de teste com credenciais de API, a qualidade sobe muito.
- **N6. Wazuh.** Qual a versão do manager da Trust? Ele recebe por syslog TLS ou por agente?
- **N7. Alertas operacionais** (fonte parou, destino falhando, deriva de formato): vão para os admins cadastrados e para
  suporte.trustcontrol@brainwalk.com.br, como no TrustRadar?
