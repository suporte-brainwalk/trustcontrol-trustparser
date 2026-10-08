#!/usr/bin/env bash
# Cria a caixa eva-trustparser@trustcontrol.nuvem.tec.br no postfix-mail existente, no mesmo molde da caixa trustlabs@
# (01/10/2026, /root/trustlabs/PLANO.md §9):
#   - senha só em arquivo 600 fora do Git (/root/trustparser/secrets/eva-mail.env), entregue ao postfix-mail por env_file;
#   - Dovecot: login de eva-trustparser@ aceito SOMENTE da trustparser_net (172.29.0.0/24) e do próprio container
#     (127.0.0.0/8); jarbas@ continua restrito a 127.0.0.0/8,172.16.0.0/13 (não inclui 172.29) — uma caixa não abre a outra;
#   - Postfix: sender_login da caixa (usuário autenticado só usa o próprio endereço); recebimento normal pela porta 25;
#   - postfix-mail ligado à trustparser_net: o orquestrador da EVA lê IMAP 993 / envia SMTP 25 e o parser-app envia os
#     e-mails da aplicação pela 25 (172.29.0.0/24 está em mynetworks via 172.16.0.0/12 e nos TrustedHosts do OpenDKIM:
#     relay sem autenticação só a partir das redes Docker internas, assinado com DKIM do domínio).
# Todo arquivo alterado ganha cópia .bak-2026-10-08 (ou ...b, ...c se já existir). Imagem anterior: jarbas-postfix-mail:pre-2026-10-08.
#
# Uso (root, no servidor):  bash deploy/eva/setup-mailbox.sh        ← NÃO roda nada sem confirmação explícita (digite "sim")
# Desfazer: restaurar os .bak-2026-10-08 listados ao fim, `docker tag jarbas-postfix-mail:pre-2026-10-08 jarbas-postfix-mail:latest`
#           e `docker compose -f /root/docker-compose.yml up -d --no-build --force-recreate postfix-mail`.
set -euo pipefail

MAIL_DIR=/root/mailserver
COMPOSE=/root/docker-compose.yml
SECRETS=/root/trustparser/secrets
MAIL_ENV=$SECRETS/eva-mail.env
EVA_ENV=$SECRETS/eva.env
EVA_ADDR=eva-trustparser@trustcontrol.nuvem.tec.br
EVA_NETS="172.29.0.0/24,127.0.0.0/8"
TP_NET=trustparser_net
STAMP=2026-10-08
ROLLBACK_IMAGE="jarbas-postfix-mail:pre-${STAMP}"
CHANGED=()

die() { echo "ERRO: $*" >&2; exit 1; }
backup() {  # cópia única por arquivo nesta execução, sem sobrescrever cópias anteriores
  local f=$1 b="$1.bak-${STAMP}" s
  [ -e "$f" ] || return 0
  for s in "" b c d e f; do
    if [ ! -e "${b}${s}" ]; then cp -p "$f" "${b}${s}"; CHANGED+=("$f -> ${b}${s}"); return 0; fi
  done
  die "cópias demais de $f"
}

[ "$(id -u)" = 0 ] || die "rode como root"
for f in "$MAIL_DIR/entrypoint.sh" "$MAIL_DIR/main.cf" "$COMPOSE"; do [ -f "$f" ] || die "não encontrei $f"; done
docker network inspect "$TP_NET" >/dev/null 2>&1 || die "a rede $TP_NET não existe (crie a infraestrutura do Trust Parser antes)"
SUBNET=$(docker network inspect "$TP_NET" --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}')
[ "$SUBNET" = "172.29.0.0/24" ] || die "a rede $TP_NET tem sub-rede $SUBNET (esperado 172.29.0.0/24)"
docker inspect postfix-mail >/dev/null 2>&1 || die "container postfix-mail não encontrado"

echo "Vai: criar a caixa $EVA_ADDR, alterar $MAIL_DIR/entrypoint.sh e $COMPOSE (postfix-mail na $TP_NET),"
echo "reconstruir e recriar o postfix-mail (alguns segundos sem SMTP/IMAP). Continuar? Digite 'sim':"
read -r ok; [ "$ok" = "sim" ] || die "cancelado"

# ---------------------------------------------------------------- 1. senha da caixa (600, fora do Git)
mkdir -p "$SECRETS"; chmod 700 "$SECRETS"
if [ ! -s "$MAIL_ENV" ]; then
  umask 077
  PASS=$(openssl rand -base64 32 | tr -d '\n')
  printf 'EVA_MAIL_ADDRESS=%s\nEVA_MAIL_PASSWORD=%s\nEVA_MAIL_NETS=%s\n' "$EVA_ADDR" "$PASS" "$EVA_NETS" > "$MAIL_ENV"
  chmod 600 "$MAIL_ENV"
  echo "senha gerada em $MAIL_ENV"
else
  echo "$MAIL_ENV já existe: mantendo a senha atual"
fi
PASS=$(sed -n 's/^EVA_MAIL_PASSWORD=//p' "$MAIL_ENV")
[ -n "$PASS" ] || die "EVA_MAIL_PASSWORD vazio em $MAIL_ENV"

# ---------------------------------------------------------------- 2. entrypoint do postfix-mail (idempotente)
if grep -q 'EVA_MAIL_ADDRESS' "$MAIL_DIR/entrypoint.sh"; then
  echo "entrypoint.sh já tem a caixa da EVA: sem alteração"
else
  backup "$MAIL_DIR/entrypoint.sh"
  python3 - "$MAIL_DIR/entrypoint.sh" <<'PY'
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()

def after(anchor, text):
    global s
    if s.count(anchor) != 1:
        sys.exit(f"âncora não encontrada (ou repetida) no entrypoint: {anchor[:70]!r}")
    s = s.replace(anchor, anchor + text, 1)

def before(anchor, text):
    global s
    if s.count(anchor) != 1:
        sys.exit(f"âncora não encontrada (ou repetida) no entrypoint: {anchor[:70]!r}")
    s = s.replace(anchor, text + anchor, 1)

after('JARBAS_ALLOW_NETS="${JARBAS_ALLOW_NETS:-127.0.0.0/8,172.16.0.0/13}"\n',
      '# Caixa da EVA (Trust Parser, 08/10/2026): login só a partir da trustparser_net e do próprio container.\n'
      'EVA_MAIL_ADDRESS="${EVA_MAIL_ADDRESS:-}"\n'
      'EVA_MAIL_PASSWORD="${EVA_MAIL_PASSWORD:-}"\n'
      'EVA_MAIL_NETS="${EVA_MAIL_NETS:-172.29.0.0/24,127.0.0.0/8}"\n')
after('    mkdir -p "${TL_MAILDIR}"/cur "${TL_MAILDIR}"/new "${TL_MAILDIR}"/tmp\nfi\n',
      'if [ -n "$EVA_MAIL_ADDRESS" ]; then\n'
      '    EVA_LOCAL_PART="${EVA_MAIL_ADDRESS%@*}"\n'
      '    EVA_MAILDIR="${VMAIL_ROOT}/${MAIL_DOMAIN}/${EVA_LOCAL_PART}/Maildir"\n'
      '    mkdir -p "${EVA_MAILDIR}"/cur "${EVA_MAILDIR}"/new "${EVA_MAILDIR}"/tmp\n'
      'fi\n')
after('[ -n "$TRUSTLABS_MAIL_ADDRESS" ] && echo "${TRUSTLABS_MAIL_ADDRESS} ${MAIL_DOMAIN}/${TL_LOCAL_PART}/Maildir/" >> /etc/postfix/vmailbox\n',
      '[ -n "$EVA_MAIL_ADDRESS" ] && echo "${EVA_MAIL_ADDRESS} ${MAIL_DOMAIN}/${EVA_LOCAL_PART}/Maildir/" >> /etc/postfix/vmailbox\n')
before('postmap /etc/postfix/sender_login\n',
       'if [ -n "$EVA_MAIL_PASSWORD" ] && [ -n "$EVA_MAIL_ADDRESS" ]; then\n'
       '    EVA_HASH="$(doveadm pw -s SHA512-CRYPT -p "${EVA_MAIL_PASSWORD}")"\n'
       '    echo "${EVA_MAIL_ADDRESS}:${EVA_HASH}:5000:5000::${VMAIL_ROOT}/${MAIL_DOMAIN}/${EVA_LOCAL_PART}::userdb_mail=maildir:${EVA_MAILDIR} allow_nets=${EVA_MAIL_NETS}" >> /etc/dovecot/users\n'
       '    echo "${EVA_MAIL_ADDRESS} ${EVA_MAIL_ADDRESS}" >> /etc/postfix/sender_login\n'
       'fi\n')
open(p, "w", encoding="utf-8").write(s)
print("entrypoint.sh: caixa da EVA incluída")
PY
  bash -n "$MAIL_DIR/entrypoint.sh" || die "entrypoint.sh ficou com erro de sintaxe (restaure o .bak)"
fi

# ---------------------------------------------------------------- 3. Postfix: envio das redes do Trust Parser
# 172.29.0.0/24 já está em mynetworks via 172.16.0.0/12 (e nos TrustedHosts do OpenDKIM). Só acrescenta se não estiver.
if ! python3 - "$MAIL_DIR/main.cf" <<'PY'
import ipaddress, re, sys
txt = open(sys.argv[1]).read()
m = re.search(r"^mynetworks\s*=\s*(.+)$", txt, flags=re.M)
nets = (m.group(1).split() if m else [])
tp = ipaddress.ip_network("172.29.0.0/24")
for n in nets:  # primeira correspondência vale (inclusive negações "!rede")
    neg = n.startswith("!")
    try:
        net = ipaddress.ip_network(n.lstrip("!"), strict=False)
    except ValueError:
        continue
    if tp.subnet_of(net):
        sys.exit(1 if neg else 0)
sys.exit(1)
PY
then
  backup "$MAIL_DIR/main.cf"
  sed -i -E 's|^(mynetworks\s*=\s*)(.*)$|\1\2 172.29.0.0/24|' "$MAIL_DIR/main.cf"
  echo "main.cf: 172.29.0.0/24 acrescentado em mynetworks"
else
  echo "main.cf: trustparser_net já pode enviar pela porta 25 (mynetworks) — sem alteração"
fi

# ---------------------------------------------------------------- 4. compose: env_file + rede trustparser_net no postfix-mail
backup "$COMPOSE"
python3 - "$COMPOSE" "$MAIL_ENV" <<'PY'
import re, sys
p, mail_env = sys.argv[1], sys.argv[2]
s = open(p, encoding="utf-8").read()
m = re.search(r"(?ms)^  postfix-mail:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|^\S)", s)
if not m:
    sys.exit("bloco postfix-mail não encontrado no compose")
blk = m.group(0)
new = blk
if mail_env not in new:
    anchor = "      - /root/trustlabs/secrets/mail.env\n"
    if anchor not in new:
        sys.exit("env_file do postfix-mail não encontrado")
    new = new.replace(anchor, anchor + f"      # Caixa exclusiva eva-trustparser@ (senha só neste arquivo 600; login aceito apenas da trustparser_net).\n      - {mail_env}\n", 1)
if not re.search(r"(?m)^      trustparser_net:", new):
    anchor = "        ipv4_address: 172.30.0.20\n"
    if anchor not in new:
        sys.exit("rede trustlabs_net do postfix-mail não encontrada")
    new = new.replace(anchor, anchor + "      # Trust Parser: EVA (IMAP 993 / SMTP 25) e e-mails do parser-app (SMTP 25).\n      trustparser_net: {}\n", 1)
s = s.replace(blk, new, 1)
if not re.search(r"(?m)^  trustparser_net:\n    external: true", s):
    s = s.rstrip("\n") + "\n  trustparser_net:\n    external: true\n"
open(p, "w", encoding="utf-8").write(s)
print("compose: postfix-mail com env_file da EVA e rede trustparser_net")
PY
if ! docker compose -f "$COMPOSE" config -q; then
  cp -p "$COMPOSE.bak-${STAMP}" "$COMPOSE" 2>/dev/null || true
  die "docker compose config recusou o arquivo; compose restaurado"
fi

# ---------------------------------------------------------------- 5. imagem de volta + build + recriação
if ! docker image inspect "$ROLLBACK_IMAGE" >/dev/null 2>&1; then
  docker tag jarbas-postfix-mail:latest "$ROLLBACK_IMAGE"
fi
docker compose -f "$COMPOSE" build postfix-mail
# --force-recreate: certificados são bind mounts de arquivo único (armadilha do inode) e o env_file mudou
docker compose -f "$COMPOSE" up -d --force-recreate postfix-mail
for _ in $(seq 1 30); do
  docker exec postfix-mail sh -c 'postfix status >/dev/null 2>&1 && doveadm who >/dev/null 2>&1' && break
  sleep 2
done

# ---------------------------------------------------------------- 6. verificações
fail=0
check() { if eval "$2"; then echo "  ok   $1"; else echo "  FALHA $1"; fail=1; fi; }
echo "Verificações:"
check "caixa existe no Dovecot" "docker exec postfix-mail doveadm user $EVA_ADDR >/dev/null 2>&1"
check "caixa no vmailbox do Postfix" "docker exec postfix-mail postmap -q $EVA_ADDR hash:/etc/postfix/vmailbox >/dev/null"
check "allow_nets restrito à trustparser_net" "docker exec postfix-mail grep -q '^$EVA_ADDR:.*allow_nets=$EVA_NETS' /etc/dovecot/users"
check "jarbas@ continua restrito (sem 172.29)" "docker exec postfix-mail grep -q '^jarbas@.*allow_nets=127.0.0.0/8,172.16.0.0/13' /etc/dovecot/users"
check "postfix-mail na trustparser_net" "docker inspect postfix-mail --format '{{json .NetworkSettings.Networks}}' | grep -q $TP_NET"
IMAP_TEST='import imaplib,os,ssl,sys
c=ssl.create_default_context(); c.check_hostname=False; c.verify_mode=ssl.CERT_NONE
try:
    m=imaplib.IMAP4_SSL("postfix-mail",993,ssl_context=c,timeout=20); m.login(sys.argv[1],os.environ["EVA_PW"]); m.logout(); print("LOGIN_OK")
except Exception as e: print("LOGIN_FAIL",type(e).__name__)'
export EVA_PW="$PASS"   # senha via ambiente (não aparece na linha de comando)
OUT_TP=$(docker run --rm --network "$TP_NET" -e EVA_PW python:3.12-slim python -c "$IMAP_TEST" "$EVA_ADDR" 2>&1 | tail -1 || true)
check "login IMAP da EVA a partir da trustparser_net" "[ \"\$OUT_TP\" = LOGIN_OK ]"
OUT_INT=$(docker run --rm --network custom_internal_net -e EVA_PW python:3.12-slim python -c "$IMAP_TEST" "$EVA_ADDR" 2>&1 | tail -1 || true)
check "login IMAP da EVA RECUSADO a partir de outra rede" "[ \"\$OUT_INT\" != LOGIN_OK ]"
SMTP_TEST='import smtplib
with smtplib.SMTP("postfix-mail",25,timeout=20) as s:
    s.ehlo("parser-app"); s.mail("soc.alertas@trustcontrol.com.br"); c,_=s.rcpt("eva-trustparser@trustcontrol.nuvem.tec.br"); s.rset(); print("RCPT",c)'
OUT_SMTP=$(docker run --rm --network "$TP_NET" python:3.12-slim python -c "$SMTP_TEST" 2>&1 | tail -1 || true)
check "SMTP 25 aceita da trustparser_net" "[ \"\$OUT_SMTP\" = 'RCPT 250' ]"

# ---------------------------------------------------------------- 7. senha para o orquestrador
if [ -f "$EVA_ENV" ]; then
  backup "$EVA_ENV"
  if grep -q '^EVA_MAIL_PASSWORD=' "$EVA_ENV"; then
    python3 - "$EVA_ENV" "$PASS" <<'PY'
import re, sys
p, pw = sys.argv[1], sys.argv[2]
s = open(p).read()
s = re.sub(r"(?m)^EVA_MAIL_PASSWORD=.*$", lambda m: "EVA_MAIL_PASSWORD=" + pw, s)
open(p, "w").write(s)
PY
  else
    printf 'EVA_MAIL_PASSWORD=%s\n' "$PASS" >> "$EVA_ENV"
  fi
else
  umask 077
  sed "s|^EVA_MAIL_PASSWORD=.*|EVA_MAIL_PASSWORD=${PASS}|" "$(dirname "$0")/eva.env.example" > "$EVA_ENV"
  echo "criado $EVA_ENV a partir do exemplo — complete DATABASE_URL e EVA_API_KEY"
fi
chmod 600 "$EVA_ENV"

echo
echo "Arquivos alterados (cópias):"; for c in "${CHANGED[@]}"; do echo "  $c"; done
echo "Imagem anterior do postfix-mail: $ROLLBACK_IMAGE"
[ "$fail" = 0 ] && echo "Caixa $EVA_ADDR pronta." || { echo "ATENÇÃO: verificações falharam (ver acima). Para voltar: restaure as cópias e recrie o postfix-mail com $ROLLBACK_IMAGE."; exit 1; }
