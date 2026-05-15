#!/bin/bash

find ~/CyberLab/results/threat -name "threat-summary.json" | while read f; do

  jq empty "$f" >/dev/null 2>&1

  if [ $? -ne 0 ]; then
    echo "[FIX] Corrigindo: $f"

    TMP="${f}.tmp"

    cat "$f" \
      | tr -d '\000' \
      | sed 's/,\s*}/}/g' \
      | sed 's/,\s*]/]/g' \
      > "$TMP"

    jq . "$TMP" > "${TMP}.2" 2>/dev/null

    if [ $? -eq 0 ]; then
      mv "${TMP}.2" "$f"
      echo "[OK] JSON reparado"
    else
      echo '{"status":"invalid","findings":[]}' > "$f"
      echo "[WARN] JSON recriado"
    fi

    rm -f "$TMP"
  fi

done

echo "[OK] Threat JSON FIX concluído"
