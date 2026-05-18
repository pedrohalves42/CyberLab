#!/bin/bash
set -u
source "${CYBERLAB_HOME:-$HOME/CyberLab}/core/bootstrap.sh"

CLIENT="$1"
TARGET="$2"
MODE="${3:-safe}"

if [ -z "$CLIENT" ] || [ -z "$TARGET" ]; then
  echo "Uso: cyberlab run-basic \"Cliente\" dominio.com safe"
  exit 1
fi

echo "==== CYBERLAB RUN BASIC ===="
echo "Cliente: $CLIENT"
echo "Alvo: $TARGET"
echo "Modo: $MODE"

cyberlab client add "$CLIENT" "$TARGET" || true
cyberlab client scope-add "$CLIENT" "$TARGET" || true

cyberlab client scan "$CLIENT" "$TARGET" "$MODE"

cyberlab threat "$TARGET" || true
cyberlab detect latest || true
cyberlab correlate latest || true

cyberlab intelligence || true
python3 "$CYBERLAB_MODULES/export/findings-export.py" || true
python3 "$CYBERLAB_MODULES/export/executive-summary.py" || true

cyberlab delivery generate "$CLIENT"
bash "$CYBERLAB_MODULES/ops/validate-delivery.sh" "$CLIENT"
bash "$CYBERLAB_MODULES/ops/cleanup.sh"

echo
echo "[OK] Operação finalizada."
echo "Delivery:"
cyberlab delivery latest "$CLIENT"
