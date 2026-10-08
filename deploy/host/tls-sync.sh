#!/bin/sh
# Copia o certificado Let's Encrypt do trustparser.* (renovado pelo acme.sh no nginx-proxy) para o receptor syslog
# (usuário 10001, leitura só dele). O parser-ingest recarrega sozinho quando o arquivo muda.
set -e
D=trustparser.trustcontrol.nuvem.tec.br; SRC=/root/nginx/certs; DST=/srv/trustparser/tls
mkdir -p $DST
for f in fullchain.pem:$D.fullchain.pem key.pem:$D.key; do
  out=${f%%:*}; in=${f#*:}
  if ! cmp -s "$SRC/$in" "$DST/$out"; then install -o 10001 -g 10001 -m 600 "$SRC/$in" "$DST/$out.tmp" && mv "$DST/$out.tmp" "$DST/$out"; echo "$(date '+%F %T') atualizado $out"; fi
done
chown 10001:10001 $DST; chmod 700 $DST
