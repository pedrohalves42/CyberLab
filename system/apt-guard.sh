#!/bin/bash

source "$HOME/CyberLab/core/bootstrap.sh"

apt_status() {
  echo "==== CYBERLAB APT STATUS ===="
  echo

  echo "[Locks]"
  ls -l /var/lib/apt/lists/lock /var/cache/apt/archives/lock /var/lib/dpkg/lock* 2>/dev/null || echo "[OK] Sem locks visíveis"
  echo

  echo "[Pacotes quebrados]"
  dpkg --audit || true
}

apt_fix() {
  warn "Reparando APT/DPKG"

  sudo rm -f /var/lib/apt/lists/lock
  sudo rm -f /var/cache/apt/archives/lock
  sudo rm -f /var/lib/dpkg/lock*
  sudo rm -f /var/lib/dpkg/lock-frontend

  sudo mkdir -p /var/lib/apt/lists/partial
  sudo chown -R root:root /var/lib/apt /var/cache/apt /var/lib/dpkg
  sudo chmod -R u+rwX,go+rX /var/lib/apt /var/cache/apt

  sudo dpkg --configure -a || true
  sudo apt --fix-broken install -y || true
  sudo apt clean || true
  sudo apt update --fix-missing || true

  info "APT/DPKG reparado"
}

case "$1" in
  status)
    apt_status
    ;;
  fix)
    apt_fix
    ;;
  *)
    echo "Uso: cyberlab apt {status|fix}"
    ;;
esac
