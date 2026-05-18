#!/bin/bash

source "${CYBERLAB_HOME:-$HOME/CyberLab}/core/bootstrap.sh"

kernel_status() {
  echo "==== CYBERLAB KERNEL STATUS ===="
  echo "Kernel atual: $(uname -r)"
  echo

  echo "[Kernels disponíveis]"
  ls /boot | grep -E 'vmlinuz|initrd' || true
  echo

  echo "[Pacotes kernel]"
  dpkg -l | grep -E 'linux-image|linux-headers|linux-generic' || true
}

kernel_hold() {
  warn "Travando metapacotes de kernel para evitar quebra de Wi-Fi/Broadcom"

  sudo apt-mark hold linux-image-generic 2>/dev/null || true
  sudo apt-mark hold linux-headers-generic 2>/dev/null || true
  sudo apt-mark hold linux-generic 2>/dev/null || true

  info "Kernel hold aplicado"
}

kernel_unhold() {
  warn "Removendo hold dos metapacotes de kernel"

  sudo apt-mark unhold linux-image-generic 2>/dev/null || true
  sudo apt-mark unhold linux-headers-generic 2>/dev/null || true
  sudo apt-mark unhold linux-generic 2>/dev/null || true

  info "Kernel hold removido"
}

kernel_risk_check() {
  echo "==== CYBERLAB KERNEL RISK CHECK ===="

  k="$(uname -r)"
  major="$(uname -r | cut -d. -f1,2)"

  echo "Kernel atual: $k"

  if echo "$major" | grep -Eq '^(6\.1[7-9]|6\.[7-9]|7\.)'; then
    echo "[RISCO] Kernel potencialmente problemático para Broadcom legacy"
    echo "Recomendado: manter kernel LTS compatível funcionando"
  else
    echo "[OK] Kernel dentro de faixa mais segura"
  fi
}

case "$1" in
  status)
    kernel_status
    ;;
  hold)
    kernel_hold
    ;;
  unhold)
    kernel_unhold
    ;;
  risk)
    kernel_risk_check
    ;;
  *)
    echo "Uso: cyberlab kernel {status|hold|unhold|risk}"
    ;;
esac
