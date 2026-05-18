#!/bin/bash

source "${CYBERLAB_HOME:-$HOME/CyberLab}/core/bootstrap.sh"

dns_status() {
  echo "==== CYBERLAB DNS STATUS ===="
  cat /etc/resolv.conf 2>/dev/null || true
}

dns_fix() {
  warn "Aplicando DNS temporário seguro"

  sudo bash -c 'cat > /etc/resolv.conf <<DNS
nameserver 127.0.0.53
nameserver 1.1.1.1
nameserver 8.8.8.8
options edns0 trust-ad
search .
DNS'

  info "DNS temporário aplicado"
  dns_status
}

dns_test() {
  echo "==== CYBERLAB DNS TEST ===="

  for host in google.com archive.ubuntu.com packages.linuxmint.com; do
    if getent hosts "$host" >/dev/null 2>&1; then
      echo "[OK] $host"
    else
      echo "[MISS] $host"
    fi
  done
}

case "$1" in
  status)
    dns_status
    ;;
  fix)
    dns_fix
    ;;
  test)
    dns_test
    ;;
  *)
    echo "Uso: cyberlab dns {status|fix|test}"
    ;;
esac
