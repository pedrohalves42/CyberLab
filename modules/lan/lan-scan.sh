#!/bin/bash

source "$HOME/CyberLab/core/bootstrap.sh"

OUT="$CYBERLAB_RESULTS/lan/lan-$(timestamp)"
mkdir -p "$OUT"/{discovery,ports,evidence,report}

lan_info() {
  IFACE="$(ip route | awk '/default/{print $5; exit}')"
  GW="$(ip route | awk '/default/{print $3; exit}')"
  IP="$(hostname -I | awk '{print $1}')"
  CIDR="$(ip -o -f inet addr show "$IFACE" 2>/dev/null | awk '{print $4}' | head -1)"

  echo "$IFACE" > "$OUT/interface.txt"
  echo "$GW" > "$OUT/gateway.txt"
  echo "$IP" > "$OUT/ip.txt"
  echo "$CIDR" > "$OUT/cidr.txt"

  echo "==== CYBERLAB LAN INFO ===="
  echo "Interface: $IFACE"
  echo "IP:        $IP"
  echo "Gateway:   $GW"
  echo "Rede:      $CIDR"
}

lan_validate() {
  if [ -z "$IFACE" ] || [ -z "$CIDR" ]; then
    echo "[ERRO] não foi possível detectar rede local"
    exit 1
  fi

  if ! grep -qx "192.168.1.0/24" "$CYBERLAB_CONFIG/scope.txt"; then
    warn "LAN não está explicitamente no escopo"
    echo "[BLOQUEADO] adicione 192.168.1.0/24 em:"
    echo "$CYBERLAB_CONFIG/scope.txt"
    exit 1
  fi
}

lan_discovery() {
  echo
  echo "==== 1/5 DISCOVERY ===="

  if command -v arp-scan >/dev/null 2>&1; then
    sudo arp-scan --interface="$IFACE" --localnet | tee "$OUT/discovery/arp-scan.txt" || true
  else
    echo "[MISS] arp-scan" | tee "$OUT/discovery/arp-scan.txt"
  fi

  nmap -sn "$CIDR" -oN "$OUT/discovery/nmap-discovery.txt"

  awk '/Nmap scan report/{print $NF}' "$OUT/discovery/nmap-discovery.txt" \
    | tr -d '()' \
    | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' \
    | sort -u > "$OUT/discovery/hosts.txt"

  echo
  echo "[+] Hosts encontrados:"
  cat "$OUT/discovery/hosts.txt"
}

lan_ports_fast() {
  echo
  echo "==== 2/5 PORTAS FAST ===="

  while read -r host; do
    [ -z "$host" ] && continue

    echo
    echo "==== $host ====" | tee -a "$OUT/ports/ports-fast.txt"
    nmap -T4 -F "$host" | tee -a "$OUT/ports/ports-fast.txt"

  done < "$OUT/discovery/hosts.txt"
}

lan_services() {
  echo
  echo "==== 3/5 SERVIÇOS ===="

  while read -r host; do
    [ -z "$host" ] && continue

    echo
    echo "==== $host ====" | tee -a "$OUT/ports/services.txt"
    nmap -sV -T3 --version-light "$host" | tee -a "$OUT/ports/services.txt"

  done < "$OUT/discovery/hosts.txt"
}

lan_web_probe() {
  echo
  echo "==== 4/5 WEB PROBE ===="

  > "$OUT/evidence/web-candidates.txt"

  grep -E '^[0-9]+/tcp +open +(http|https|http-alt|http-proxy|ssl/http)' "$OUT/ports/services.txt" \
    | awk '{print $1}' \
    | cut -d/ -f1 \
    | sort -u > "$OUT/evidence/web-ports.tmp" || true

  while read -r host; do
    [ -z "$host" ] && continue

    for port in 80 443 8080 8000 8443 3000 5000 9000; do
      if grep -q "$port/tcp" "$OUT/ports/services.txt"; then
        if [ "$port" = "443" ] || [ "$port" = "8443" ]; then
          echo "https://$host:$port" >> "$OUT/evidence/web-candidates.txt"
        else
          echo "http://$host:$port" >> "$OUT/evidence/web-candidates.txt"
        fi
      fi
    done
  done < "$OUT/discovery/hosts.txt"

  sort -u "$OUT/evidence/web-candidates.txt" -o "$OUT/evidence/web-candidates.txt"

  echo "[+] Candidatos web:"
  cat "$OUT/evidence/web-candidates.txt"

  > "$OUT/evidence/web-headers.txt"

  while read -r url; do
    [ -z "$url" ] && continue
    echo "===== $url =====" | tee -a "$OUT/evidence/web-headers.txt"
    curl -k -I -L --max-time 6 "$url" 2>/dev/null | tee -a "$OUT/evidence/web-headers.txt"
    echo | tee -a "$OUT/evidence/web-headers.txt"
  done < "$OUT/evidence/web-candidates.txt"
}

lan_report() {
  echo
  echo "==== 5/5 RELATÓRIO ===="

  HOSTS="$(wc -l < "$OUT/discovery/hosts.txt" 2>/dev/null || echo 0)"
  OPEN_PORTS="$(grep -c ' open ' "$OUT/ports/ports-fast.txt" 2>/dev/null || echo 0)"
  WEB="$(wc -l < "$OUT/evidence/web-candidates.txt" 2>/dev/null || echo 0)"

  REPORT="$OUT/report/lan-report.md"

  cat > "$REPORT" <<MD
# CyberLab LAN Report

**Data:** $(date)  
**Interface:** $IFACE  
**IP local:** $IP  
**Gateway:** $GW  
**Rede:** $CIDR  

## Resumo

- Hosts encontrados: $HOSTS
- Portas abertas identificadas: $OPEN_PORTS
- Serviços web candidatos: $WEB

## Hosts

\`\`\`
$(cat "$OUT/discovery/hosts.txt" 2>/dev/null)
\`\`\`

## Portas fast

\`\`\`
$(cat "$OUT/ports/ports-fast.txt" 2>/dev/null)
\`\`\`

## Serviços

\`\`\`
$(cat "$OUT/ports/services.txt" 2>/dev/null)
\`\`\`

## Web candidates

\`\`\`
$(cat "$OUT/evidence/web-candidates.txt" 2>/dev/null)
\`\`\`

## Recomendações

1. Validar dispositivos desconhecidos na rede.
2. Confirmar serviços administrativos expostos.
3. Revisar portas web internas.
4. Isolar dispositivos IoT/TV/câmeras em rede separada.
5. Manter evidências somente para ambiente próprio/autorizado.
MD

  echo "[✓] Relatório LAN: $REPORT"
  echo "$OUT" > "$CYBERLAB_RESULTS/lan/latest.txt"
}

case "$1" in
  scan|"")
    lan_info
    lan_validate
    lan_discovery
    lan_ports_fast
    lan_services
    lan_web_probe
    lan_report
    ;;
  latest)
    cat "$CYBERLAB_RESULTS/lan/latest.txt" 2>/dev/null || echo "Nenhum resultado LAN ainda."
    ;;
  report)
    latest="$(cat "$CYBERLAB_RESULTS/lan/latest.txt" 2>/dev/null)"
    [ -n "$latest" ] && cat "$latest/report/lan-report.md" || echo "Nenhum relatório LAN ainda."
    ;;
  *)
    echo "Uso: cyberlab lan {scan|latest|report}"
    ;;
esac
