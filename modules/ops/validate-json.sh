#!/bin/bash
set -u

TARGET="${1:-$HOME/CyberLab/state/intelligence}"

BROKEN=0

find "$TARGET" -name "*.json" | while read -r f; do
  if jq empty "$f" >/dev/null 2>&1; then
    echo "[OK] $f"
  else
    echo "[BROKEN] $f"
    BROKEN=1
  fi
done
