#!/bin/bash

source "${CYBERLAB_HOME:-$HOME/CyberLab}/core/bootstrap.sh"

echo "==== CYBERLAB SYSTEM RECOVERY ===="
echo

info "Iniciando recovery seguro"

echo "[1/6] Status de rede"
bash "$CYBERLAB_SYSTEM/network.sh" status || true
echo

echo "[2/6] Corrigir DNS"
bash "$CYBERLAB_SYSTEM/dns.sh" fix || true
echo

echo "[3/6] Teste de DNS"
bash "$CYBERLAB_SYSTEM/dns.sh" test || true
echo

echo "[4/6] Reparar APT"
bash "$CYBERLAB_SYSTEM/apt-guard.sh" fix || true
echo

echo "[5/6] Kernel risk"
bash "$CYBERLAB_SYSTEM/kernel-guard.sh" risk || true
echo

echo "[6/6] Broadcom status"
bash "$CYBERLAB_SYSTEM/broadcom-guard.sh" status || true
echo

info "Recovery finalizado"
echo "[✓] Recovery finalizado"
