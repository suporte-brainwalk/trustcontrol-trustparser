# Trust Parser — parsers embutidos

Specs em `app/engine/builtin/*.json` (linguagem: `docs/dsl.md`). Cada um traz testes próprios (`tests`), validados por
`tests/unit/test_builtin_specs.py` (estrutura, campos esperados, autodetecção sem ambiguidade entre parsers e saídas
UDM/CEF/LEEF/Wazuh/CSV sem erro). Base **amostra real** = construído e testado com logs de cliente (anonimizados nos testes);
**documentação** = construído só com documentação do fabricante/exemplos públicos — precisa de amostra real antes de produção.

| Parser (slug) | Fabricante | Via | Formato | Base | Classes OCSF geradas | Pendências de validação |
|---|---|---|---|---|---|---|
| `nginx-access-pipe` | NGINX | syslog / upload | access log delimitado por ` \| ` | amostra real | 4002 | Só GET/200/401/403 na amostra; outros métodos e log_formats não vistos |
| `withsecure-elements-syslog` | WithSecure | syslog (Elements Connector, formato "Syslog") | `[alertMeta@0 …]`, puro, com cabeçalho ou envelope JSON do coletor | amostra real | 3002, 3001, 3006, 1008, 1007, 4002, 2004, 0 | Cabeçalho syslog original nunca visto; PRI de eventos "critical"; formatos CEF/LEEF do Connector não suportados |
| `withsecure-elements-api-event` | WithSecure | API (POST /security-events/v1) | JSON (1 item por linha; envelope lista ou por tipo) | documentação | as do syslog + 4001 (firewall), 2004 (DeepGuard/AMSI/EDR) | Confirmar envelope real e presença de `details.url` no controle web |
| `watchguard-firebox-syslog` | WatchGuard | syslog (UDP 514) / upload (Traffic Monitor colado) | syslog nativo `msg_id="XXXX-XXXX"` + posicional + chave="valor" | documentação | 4001, 4002, 3002, 1008, 0 | Cabeçalho real por versão do Fireware; fuso do Firebox; formato de mensagens de evento/login no syslog nativo |
| `watchguard-firebox-leef` | WatchGuard | syslog (IBM LEEF) | LEEF 1.0 (TAB ou `#011`), com/sem `LEEF:` | documentação | 4001, 4002, 3002, 1008, 0 | Chaves LEEF só de amostras de terceiros; produto `XTM` x `Firebox`; linhas sem devTime dependem do cabeçalho syslog |
| `watchguard-epdr-siemfeeder` | WatchGuard | syslog / Kafka / pasta (Event Importer) | CEF:1 e LEEF:1.0 (`paps`) | documentação | 2004, 1007, 1001, 4001, 4002, 3002, 0 | Só 2 linhas oficiais (registryc); delimitador LEEF (espaço/TAB); formato de ExecutionStatus; escala de severidade do thalert; `\n` em caminhos é interpretado como escape CEF |
| `watchguard-epdr-api-json` | WatchGuard | API (securityevents export) | JSON (1 item por linha) | documentação | 2004 | Exemplo oficial é JSON inválido; campos por tipo (1–19) não documentados; o tipo da consulta não vem no objeto |
| `cortex-xdr-cef` | Palo Alto Networks | syslog (UDP/TCP/TLS) | CEF (alertas, auditoria de gestão e de agente) | documentação | 2004, 1008, 0 | Não há linha real de alerta publicada; severidade Critical/Info no CEF; unidade de `end` |
| `cortex-xdr-api-alert` | Palo Alto Networks | API (get_alerts / get_alerts_multi_events v2) | JSON (1 alerta por linha) | documentação | 2004 | Exemplos vêm de fixtures de terceiros; só o 1º evento de `events[]` é mapeado |
| `trend-vision-one-cef` | Trend Micro (TrendAI) | syslog (Syslog Connector) | CEF (900001–900004) | documentação | 2004, 3002, 0 | Nenhuma linha real publicada; marca no fio (TrendAI™ x Trend Micro); Workbench via CEF não traz host (UDM GENERIC_EVENT) |
| `trend-vision-one-api-alert` | Trend Micro (TrendAI) | API (/v3.0/workbench/alerts) | JSON (1 alerta por linha) | documentação | 2004 | Só 1º host/conta/filtro mapeados; prefixo `V9.` nas técnicas MITRE mantido |
| `axur-api-ticket` | Axur | API / webhook | JSON (ticket, webhook ticket.*, detecção de vazamento) | documentação | 2004 | Sem host local (UDM GENERIC_EVENT, como recomendado); webhook `exposure.*` com várias detecções precisa ser dividido em 1 por linha antes; senha/cartão/CVV descartados |
| `tenable-vuln-export` | Tenable | API (vulns export chunks) | JSON (1 achado por linha) | documentação | 2002 | `cve` = 1º CVE (lista completa em `cves`); Tenable.sc (CSV/analysis) não implementado |
