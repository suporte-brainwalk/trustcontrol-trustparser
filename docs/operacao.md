# Trust Parser — operação

Portal: https://trustparser.trustcontrol.nuvem.tec.br (filtro Brasil no nginx) · API: `/api/v1` (documentação em `/api/docs`)
Repositório: github.com/suporte-brainwalk/trustcontrol-trustparser (alias SSH `github-tc-trustparser`) · Implantado em 08/10/2026.

## Componentes (servidor Hetzner, `/root/docker-compose.yml`)

| Container | Papel | Limite RAM |
|---|---|---|
| `parser-app` | Flask (tela + API) e worker (parsing, envio, conectores, Estúdio IA, expurgo) — supervisord | 1,5 GB |
| `parser-ingest` | receptor syslog: 6514/TCP TLS, 514/TCP e 514/UDP (1514 no container) | 512 MB |
| `parser-db` | PostgreSQL 18 (`/srv/trustparser/postgres/data`) | — |
| `eva-orchestrator` / `eva-egress` | EVA (suporte por IA) — ver `docs/eva.md` | 1,5 GB / 256 MB |

Rede `trustparser_net` (172.29.0.0/24): nginx-proxy e postfix-mail também ligados a ela.
Segredos (600, fora do Git): `/root/trustparser/secrets/{parser.env, postgres.env, openrouter.env, eva.env, eva-mail.env}`.
`SECRETS_KEY` em `parser.env` cifra as credenciais de destinos e conectores (AES-256-GCM) — **perder essa chave = recadastrar credenciais**.

## Firewall do syslog
- Serviço `trustparser-fw` (systemd, antes do Docker): `deploy/host/trustparser-fw.sh loop`. A cada 30 s lê
  `flask fw-export` no parser-app e troca os ipsets `tp_tls`, `tp_tcp`, `tp_udp` (atômico). Regras em
  `iptables -t raw PREROUTING` na `eth0`: quem não está na lista é descartado antes de chegar ao container. IPv6 nessas portas: DROP.
- Se o parser-app estiver fora, mantém as listas atuais. `systemctl status trustparser-fw`, `ipset list tp_tls`.
- Firewall da Hetzner Cloud: 6514/tcp, 514/tcp, 514/udp abertos (liberado por Rogério em 08/10/2026).

## Certificado TLS
- `trustparser.trustcontrol.nuvem.tec.br` emitido via webroot (acme.sh no nginx-proxy). Renovação: host.crontab 03:15.
- `deploy/host/tls-sync.sh` (03:35) copia para `/srv/trustparser/tls` (uid 10001); o parser-ingest recarrega sozinho.
- `cert-watchdog.sh` confere 443 e 6514 (campos `parser=` e `syslogtls=` no log).

## Rotina
- Backup do banco: 02:50 → `/srv/trustparser/backups` (7 dias). Restauração: `pg_restore -d trustparser` no parser-db.
- Buffer: eventos 2 h; não entregues até 24 h; limite de disco 8 GB (Configurações). Métricas por minuto: 7 dias.
- Avisos operacionais: Configurações → Avisos (padrão: suporte.trustcontrol@ + administradores).
- Memória do servidor: swap 4 GB + earlyoom + `/root/nginx/mem-watchdog.sh` (incidente de 08/10/2026 01:24–01:33).

## Comandos úteis (`docker exec parser-app flask --app app:create_app …`)
| comando | uso |
|---|---|
| `seed` | garante parsers embutidos (atualiza os que mudaram no código), formatos nativos, tenant interno e lista da EVA |
| `invite-admin --email X --name Y` | convida administrador |
| `admin login-link --email X` | link de acesso de emergência (15 min) |
| `admin reset-mfa --email X` | zera o MFA |
| `fw-export` | estado desejado do firewall (JSON) |
| `parser-test <slug> <arquivo>` | cobertura de um parser sobre um arquivo |
| `api-chave-eva [--rotacionar]` | chave protegida de leitura da EVA |

## Atualizar a aplicação
```bash
cd /root/trustcontrol-trustparser && git pull --ff-only
free -m        # build só com ≥ 2,5 GB disponíveis, um de cada vez
docker build --target runtime -t trustparser-app:latest .
docker compose -f /root/docker-compose.yml up -d parser-app parser-ingest
```
Migrações (Alembic) e `seed` rodam no boot do parser-app.

## Testes
```bash
/root/trustparser/venv/bin/python -m pytest tests/unit tools/eva/tests -q -p no:cacheprovider --noconftest   # motor, 13 parsers, conectores, EVA
source /root/trustparser/dev.sh && PYTHONPATH=. /root/trustparser/venv/bin/python -m pytest tests/integration -q -p no:cacheprovider
```
Os testes de integração criam o banco descartável `trustparser_test`.
