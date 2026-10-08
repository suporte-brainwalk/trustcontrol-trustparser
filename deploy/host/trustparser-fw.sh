#!/bin/bash
# Firewall do syslog do Trust Parser (host). Só IPs liberados na tela (Firewall do syslog) chegam às portas 6514/TCP (TLS),
# 514/TCP e 514/UDP. Regras em iptables -t raw PREROUTING (antes do DNAT do Docker e já no boot) + ipsets trocados de forma
# atômica. Uso: trustparser-fw.sh init   (regras com listas vazias = tudo bloqueado)
#              trustparser-fw.sh sync   (lê o estado desejado do parser-app e aplica)
set -euo pipefail
IFACE=${IFACE:-eth0}
declare -A PORT=( [tls]="tcp 6514" [tcp]="tcp 514" [udp]="udp 514" )

ensure_sets() {
  for k in tls tcp udp; do ipset create "tp_$k" hash:net family inet -exist; done
}

ensure_rules() {
  ensure_sets
  for k in tls tcp udp; do
    read -r proto port <<<"${PORT[$k]}"
    iptables -t raw -C PREROUTING -i "$IFACE" -p "$proto" --dport "$port" -m set ! --match-set "tp_$k" src -j DROP 2>/dev/null \
      || iptables -t raw -I PREROUTING -i "$IFACE" -p "$proto" --dport "$port" -m set ! --match-set "tp_$k" src -j DROP
    ip6tables -t raw -C PREROUTING -i "$IFACE" -p "$proto" --dport "$port" -j DROP 2>/dev/null \
      || ip6tables -t raw -I PREROUTING -i "$IFACE" -p "$proto" --dport "$port" -j DROP
  done
}

sync() {
  ensure_rules
  local json hash
  if ! json=$(timeout 60 docker exec parser-app flask --app app:create_app fw-export 2>/dev/null | tail -1); then
    echo "$(date '+%F %T') parser-app indisponível; mantendo as listas atuais"; return 0
  fi
  hash=$(printf '%s' "$json" | python3 -c 'import sys,json,hashlib;d=json.load(sys.stdin);print(hashlib.sha256(json.dumps(d,sort_keys=True).encode()).hexdigest()[:16])')
  for k in tls tcp udp; do
    ipset create "tp_${k}_new" hash:net family inet -exist
    ipset flush "tp_${k}_new"
    printf '%s' "$json" | python3 -c "
import sys,json,ipaddress
for c in json.load(sys.stdin).get('$k',[]):
    n=ipaddress.ip_network(c,strict=False)
    if n.version==4 and n.prefixlen>=8: print(n)" | while read -r cidr; do ipset add "tp_${k}_new" "$cidr" -exist; done
    ipset swap "tp_${k}_new" "tp_$k"
    ipset destroy "tp_${k}_new"
  done
  local last=/run/trustparser-fw.hash
  if [ "$(cat $last 2>/dev/null)" != "$hash" ]; then
    echo "$(date '+%F %T') aplicado hash=$hash tls=$(ipset list tp_tls | grep -c '^[0-9]') tcp=$(ipset list tp_tcp | grep -c '^[0-9]') udp=$(ipset list tp_udp | grep -c '^[0-9]')"
    echo "$hash" > $last
  fi
  docker exec parser-app flask --app app:create_app fw-applied --hash "$hash" --ok >/dev/null 2>&1 || true
}

case "${1:-sync}" in
  init) ensure_rules ;;
  sync) sync ;;
  loop) ensure_rules; while true; do sync || true; sleep 30; done ;;
  *) echo "uso: $0 init|sync|loop"; exit 2 ;;
esac
