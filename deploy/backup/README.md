# Backup do PostgreSQL (portal-db)

- **Quando:** todo dia às 02:30 (host crontab em `/root/nginx/host.crontab`).
- **Onde:** `/srv/trustcontrol/backups/postgres/` no disco da VM (entra no snapshot da Hetzner).
- **O quê:** `portal-AAAA-MM-DD_HHMM.dump` (pg_dump formato custom) + `portal-…globals.sql` (roles).
- **Verificação:** `pg_restore --list` lê o dump inteiro antes de ele ser considerado válido.
- **Retenção:** 7 dias; nunca apaga se sobrarem menos de 7 backups.
- **Falha:** e-mail para `suporte.trustcontrol@brainwalk.com.br` via `postfix-mail`. Log em `/var/log/portal-db-backup.log`.
- **Criptografia:** não aplicada (decisão 13/09/2026 — tratada depois na camada de virtualização da Hetzner).

## Executar manualmente
```bash
/root/trustcontrol-cybersec-news/deploy/backup/pg-backup.sh
```

## Restaurar
```bash
F=/srv/trustcontrol/backups/postgres/portal-AAAA-MM-DD_HHMM.dump
# em um banco novo (recomendado testar antes de substituir o principal):
docker exec portal-db createdb -U trustportal restore_test
docker exec -i portal-db pg_restore -U trustportal -d restore_test --no-owner < "$F"
# substituir o banco principal (parar a aplicação antes):
docker exec -i portal-db pg_restore -U trustportal -d trustportal --clean --if-exists --no-owner < "$F"
```
