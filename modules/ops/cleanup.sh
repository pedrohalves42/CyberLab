#!/bin/bash
source "$HOME/CyberLab/core/bootstrap.sh"

echo "==== CYBERLAB CLEANUP ===="
find "$CYBERLAB_HOME" -name "*.tmp" -delete 2>/dev/null || true
find "$CYBERLAB_HOME" -name "*.cache" -delete 2>/dev/null || true
find "$CYBERLAB_HOME" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

find "$CYBERLAB_HOME" -name "*.json" | while read f; do
  jq empty "$f" >/dev/null 2>&1 || echo "[BROKEN] $f"
done

echo "[OK] Cleanup finalizado"
