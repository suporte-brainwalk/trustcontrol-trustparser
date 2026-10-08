#!/bin/bash
# Entrada em produção do Trust Parser (08/10/2026): remove dados de teste da implantação, liga a EVA para a lista de
# autorizados, convida os administradores e envia a pergunta do Wazuh (EVA → Raphael e Alberto, Rogério em cópia).
# Uso: bash /root/trustparser/golive.sh [--convites] [--wazuh]
set -euo pipefail
PSQL="docker exec -i parser-db psql -U trustparser -d trustparser -v ON_ERROR_STOP=1 -q"
FLASK="docker exec parser-app flask --app app:create_app"
STAMP=$(date +%F_%H%M)

if [[ " $* " != *" --sem-limpeza "* ]]; then
echo "== backup antes da limpeza"
bash /root/trustcontrol-trustparser/deploy/backup/pg-backup.sh

echo "== removendo dados de teste"
$PSQL <<'SQL'
delete from tenants where name in ('Cliente Smoke', 'Cliente API', 'Cliente Teste EVA');
delete from users where email like '%@exemplo.com.br';
delete from api_keys where not protected;
delete from events where tenant_id is null or tenant_id not in (select id from tenants);
delete from eva_threads;
delete from deliveries where recipient like '%@exemplo.com.br';
delete from settings where key in ('drift_alerted');
SQL
fi
$PSQL -tc "select 'tenants', count(*) from tenants union all select 'usuários', count(*) from users union all select 'fontes', count(*) from sources union all select 'IPs liberados', count(*) from allowed_ips union all select 'eventos', count(*) from events"

echo "== EVA: modo ativo (atende a lista de autorizados)"
$PSQL -c "insert into settings (key, value, updated_at) values ('eva_mode', '{\"v\": \"ativo\"}', now()) on conflict (key) do update set value = excluded.value, updated_at = now()"

if [[ " $* " == *" --convites "* ]]; then
  echo "== convites de administrador (24 h)"
  $FLASK invite-admin --email rogerio.crispim@brainwalk.com.br --name "Rogério Crispim"
  $FLASK invite-admin --email raphael.soares@trustcontrol.com.br --name "Raphael Soares"
  $FLASK invite-admin --email alberto.santos@trustcontrol.com.br --name "Alberto Santos"
fi

if [[ " $* " == *" --wazuh "* ]]; then
  echo "== EVA: pergunta sobre a versão do Wazuh"
  docker exec -w /root/trustcontrol-trustparser/tools/eva eva-orchestrator python -m scripts.pergunta_wazuh --enviar
fi
echo "== pronto ($STAMP)"
