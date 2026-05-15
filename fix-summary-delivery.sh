#!/usr/bin/env bash
set -euo pipefail

BASE="$HOME/CyberLab"

echo "==== FIX SUMMARY DELIVERY ===="

find "$BASE/clients" -type d -path "*/reports/delivery/*" | while read D; do

  SUMMARY="$D/summary.txt"

  if [ ! -f "$SUMMARY" ]; then

    echo "[FIX] criando:"
    echo "$SUMMARY"

    cat > "$SUMMARY" <<EOF2
CYBERLAB DELIVERY SUMMARY

Delivery:
$D

Generated:
$(date)

Status:
OK
EOF2

  fi

done

echo
echo "[OK] Summary fix aplicado"

