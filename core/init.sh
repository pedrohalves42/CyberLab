#!/bin/bash
set -euo pipefail

source "${CYBERLAB_HOME:-$HOME/CyberLab}/core/env.sh"

echo "============================================================"
echo " CyberLab — INIT"
echo "============================================================"

mkdir -p \
  "$CYBERLAB_BIN" \
  "$CYBERLAB_CORE" \
  "$CYBERLAB_MODULES" \
  "$CYBERLAB_RESULTS" \
  "$CYBERLAB_CONFIG" \
  "$CYBERLAB_CLIENTS" \
  "$CYBERLAB_LOGS" \
  "$CYBERLAB_STATE" \
  "$CYBERLAB_DATA" \
  "$CYBERLAB_QUEUE" \
  "$CYBERLAB_QUEUE/pending" \
  "$CYBERLAB_QUEUE/running" \
  "$CYBERLAB_QUEUE/completed" \
  "$CYBERLAB_QUEUE/failed"

if [ ! -f "$CYBERLAB_CONFIG/scope.txt" ]; then
  if [ -f "$CYBERLAB_CONFIG/scope.example.txt" ]; then
    cp "$CYBERLAB_CONFIG/scope.example.txt" "$CYBERLAB_CONFIG/scope.txt"
    echo "[OK] scope.txt criado a partir de scope.example.txt"
  else
    touch "$CYBERLAB_CONFIG/scope.txt"
    echo "[OK] scope.txt vazio criado"
  fi
else
  echo "[INFO] scope.txt já existe"
fi

if [ ! -f "$CYBERLAB_CONFIG/rbac.json" ]; then
  if [ -f "$CYBERLAB_CONFIG/rbac.example.json" ]; then
    cp "$CYBERLAB_CONFIG/rbac.example.json" "$CYBERLAB_CONFIG/rbac.json"
    echo "[OK] rbac.json criado a partir de rbac.example.json"
  else
    echo "[WARN] rbac.example.json não encontrado"
  fi
else
  echo "[INFO] rbac.json já existe"
fi

touch "$CYBERLAB_LOGS/cyberlab.log"

echo "[OK] Ambiente inicializado:"
echo "     $CYBERLAB_HOME"
