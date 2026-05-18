#!/bin/bash

source "${CYBERLAB_HOME:-$HOME/CyberLab}/core/bootstrap.sh"

network_status() {
  echo "==== CYBERLAB NETWORK STATUS ===="
  echo
  echo "[Interfaces]"
  ip -brief addr 2>/dev/null || true
  echo

  echo "[Rotas]"
  ip route 2>/dev/null || true
  echo

  echo "[DNS]"
  grep -E '^nameserver' /etc/resolv.conf 2>/dev/null || echo "[WARN] Nenhum DNS visível"
  echo

  echo "[NetworkManager]"
  systemctl is-active NetworkManager 2>/dev/null || true
}

network_restart() {
  info "Reiniciando NetworkManager"
  sudo systemctl restart NetworkManager
  sleep 2
  network_status
}

network_test() {
  echo "==== CYBERLAB NETWORK TEST ===="

  if ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1; then
    echo "[OK] Internet por IP"
  else
    echo "[MISS] Sem internet por IP"
  fi

  if ping -c 1 -W 2 google.com >/dev/null 2>&1; then
    echo "[OK] DNS externo"
  else
    echo "[MISS] DNS externo falhou"
  fi
}

network_usb_detect() {
  echo "==== CYBERLAB USB/TETHER DETECT ===="

  ip -o addr show | awk -F': ' '{print $2}' | grep -E '^(enx|usb)' || {
    echo "[INFO] Nenhuma interface USB/tether detectada"
    return 1
  }
}

network_wifi_detect() {
  echo "==== CYBERLAB WIFI DETECT ===="

  ip -o link show | awk -F': ' '{print $2}' | grep -E '^(wl|wlan|wlp)' || {
    echo "[INFO] Nenhuma interface Wi-Fi detectada"
    return 1
  }
}

case "$1" in
  status)
    network_status
    ;;
  restart)
    network_restart
    ;;
  test)
    network_test
    ;;
  usb)
    network_usb_detect
    ;;
  wifi)
    network_wifi_detect
    ;;
  *)
    echo "Uso: cyberlab network {status|restart|test|usb|wifi}"
    ;;
esac
