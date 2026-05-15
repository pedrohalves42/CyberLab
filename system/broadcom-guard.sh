#!/bin/bash

source "$HOME/CyberLab/core/bootstrap.sh"

broadcom_detect() {
  lspci 2>/dev/null | grep -Ei 'Broadcom|BCM'
}

broadcom_status() {
  echo "==== CYBERLAB BROADCOM STATUS ===="
  echo

  echo "[Hardware]"
  broadcom_detect || echo "[INFO] Broadcom não detectado"
  echo

  echo "[Módulos carregados]"
  lsmod | grep -E 'wl|brcmsmac|brcmfmac|bcma|ssb' || echo "[INFO] Nenhum módulo Broadcom/Wi-Fi listado"
  echo

  echo "[DKMS]"
  dkms status 2>/dev/null | grep -Ei 'broadcom|bcmwl|bcm' || echo "[INFO] DKMS Broadcom não encontrado"
  echo

  echo "[Interfaces Wi-Fi]"
  ip -o link show | awk -F': ' '{print $2}' | grep -E '^(wl|wlan|wlp)' || echo "[INFO] Nenhuma interface Wi-Fi detectada"
}

broadcom_open_driver() {
  warn "Tentando driver aberto Broadcom"

  sudo modprobe -r wl brcmsmac brcmfmac bcma ssb 2>/dev/null || true
  sudo modprobe brcmsmac 2>/dev/null || true
  sudo modprobe brcmfmac 2>/dev/null || true
  sudo systemctl restart NetworkManager || true

  broadcom_status
}

broadcom_wl_driver() {
  warn "Tentando driver proprietário Broadcom WL"

  sudo modprobe -r brcmsmac brcmfmac bcma ssb wl 2>/dev/null || true
  sudo modprobe wl 2>/dev/null || {
    error "Falha ao carregar módulo wl"
    echo "[ERRO] wl não carregou. Verifique kernel/DKMS."
    return 1
  }

  sudo systemctl restart NetworkManager || true
  broadcom_status
}

case "$1" in
  status)
    broadcom_status
    ;;
  open)
    broadcom_open_driver
    ;;
  wl)
    broadcom_wl_driver
    ;;
  *)
    echo "Uso: cyberlab broadcom {status|open|wl}"
    ;;
esac
