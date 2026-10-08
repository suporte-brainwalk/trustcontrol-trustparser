#!/usr/bin/env bash
# Backup diário do PostgreSQL do Trust Parser.
# - pg_dump em formato custom (já comprimido) + globals (roles), gerados dentro do container parser-db
# - verificação: pg_restore --list precisa ler o arquivo inteiro sem erro
# - grava primeiro em .tmp e só renomeia quando verificado (nunca deixa backup pela metade)
# - retenção: mantém os backups dos últimos 7 dias; nunca apaga se restarem menos de 7 backups válidos
# - falha → e-mail de alerta via postfix-mail
# Agendado pelo host crontab (/root/nginx/host.crontab). Sem criptografia (tratada na camada Hetzner — decisão 13/09/2026).
set -uo pipefail

CONTAINER="${PG_CONTAINER:-parser-db}"
DEST="${PG_BACKUP_DIR:-/srv/trustparser/backups}"
KEEP_DAYS="${PG_BACKUP_KEEP_DAYS:-7}"
ALERT_TO="${PG_BACKUP_ALERT_TO:-suporte.trustcontrol@brainwalk.com.br}"
ALERT_FROM="${PG_BACKUP_ALERT_FROM:-trustparser@trustcontrol.nuvem.tec.br}"
STAMP="$(date +%F_%H%M)"
NAME="trustparser-${STAMP}"

log() { echo "$(date '+%F %T') $*"; }

fail() {
    log "FALHA: $*"
    rm -f "$DEST/$NAME.dump.tmp" "$DEST/$NAME.globals.sql.tmp"
    {
        printf 'From: %s\nTo: %s\nSubject: [ALERTA] Backup do PostgreSQL do Trust Parser falhou\n' "$ALERT_FROM" "$ALERT_TO"
        printf 'MIME-Version: 1.0\nContent-Type: text/plain; charset=UTF-8\n\n'
        printf 'O backup diário do banco do Trust Parser falhou em %s.\n\nMotivo: %s\n\n' "$(date '+%d/%m/%Y %H:%M')" "$*"
        printf 'Backups existentes em %s:\n' "$DEST"
        ls -lh "$DEST" 2>/dev/null | tail -n +2
        printf '\nExecutar manualmente: %s\n' "$0"
    } | /usr/bin/docker exec -i postfix-mail /usr/sbin/sendmail -t -f "$ALERT_FROM" || log "também falhou o envio do alerta"
    exit 1
}

mkdir -p "$DEST" && chmod 700 "$DEST" || fail "não foi possível preparar $DEST"
docker exec "$CONTAINER" pg_isready -q -U "$(docker exec "$CONTAINER" printenv POSTGRES_USER)" \
    || fail "container $CONTAINER indisponível"

DB="$(docker exec "$CONTAINER" printenv POSTGRES_DB)"
USER="$(docker exec "$CONTAINER" printenv POSTGRES_USER)"

# 1) dump do banco (formato custom, compressão nível 6)
docker exec "$CONTAINER" pg_dump -U "$USER" -d "$DB" -Fc -Z 6 --no-owner > "$DEST/$NAME.dump.tmp" \
    || fail "pg_dump retornou erro"
[ -s "$DEST/$NAME.dump.tmp" ] || fail "dump vazio"

# 2) roles/globais (pequeno, para restaurar permissões)
docker exec "$CONTAINER" pg_dumpall -U "$USER" --globals-only > "$DEST/$NAME.globals.sql.tmp" \
    || fail "pg_dumpall --globals-only retornou erro"

# 3) verificação: o catálogo do dump precisa ser lido por completo
docker exec -i "$CONTAINER" pg_restore --list < "$DEST/$NAME.dump.tmp" > /dev/null \
    || fail "verificação (pg_restore --list) falhou — dump corrompido"

mv -f "$DEST/$NAME.dump.tmp" "$DEST/$NAME.dump" && mv -f "$DEST/$NAME.globals.sql.tmp" "$DEST/$NAME.globals.sql" \
    || fail "não foi possível finalizar os arquivos"
chmod 600 "$DEST/$NAME".*
log "OK $NAME.dump ($(du -h "$DEST/$NAME.dump" | cut -f1))"

# 4) retenção: apaga backups com mais de KEEP_DAYS dias, preservando sempre os KEEP_DAYS mais recentes
rm -f "$DEST"/*.tmp
total=$(ls -1 "$DEST"/trustparser-*.dump 2>/dev/null | wc -l)
if [ "$total" -gt "$KEEP_DAYS" ]; then
    find "$DEST" -maxdepth 1 -name 'trustparser-*.dump' -mtime +$((KEEP_DAYS - 1)) -printf '%T@ %p\n' | sort -n | while read -r _ f; do
        remaining=$(ls -1 "$DEST"/trustparser-*.dump | wc -l)
        [ "$remaining" -le "$KEEP_DAYS" ] && break
        rm -f "$f" "${f%.dump}.globals.sql" && log "retenção: removido $(basename "$f")"
    done
fi
log "backups mantidos: $(ls -1 "$DEST"/trustparser-*.dump | wc -l)"
