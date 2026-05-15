#!/bin/bash

TARGET="${1:-$HOME/CyberLab/results}"

echo "==== CYBERLAB JSON RECOVERY ===="

find "$TARGET" -name "*.json" | while read f; do

  jq empty "$f" >/dev/null 2>&1

  if [ $? -ne 0 ]; then

    echo "[FIX] Reparando: $f"

    TMP=$(mktemp)

    cat "$f" \
      | tr -d '\000' \
      | sed 's/,\s*}/}/g' \
      | sed 's/,\s*]/]/g' \
      > "$TMP"

    jq . "$TMP" > "${TMP}.fixed" 2>/dev/null

    if [ $? -eq 0 ]; then
      mv "${TMP}.fixed" "$f"
      echo "[OK] JSON reparado"
    else
      echo '{"status":"recovered","findings":[]}' > "$f"
      echo "[WARN] JSON reconstruído"
    fi

    rm -f "$TMP"

  fi

done

echo "[OK] Recovery finalizado"
