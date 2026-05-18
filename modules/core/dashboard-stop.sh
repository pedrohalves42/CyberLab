#!/bin/bash

source "${CYBERLAB_HOME:-$HOME/CyberLab}/core/bootstrap.sh"

echo "==== CYBERLAB DASHBOARD STOP ===="

PIDS="$(pgrep -f "$CYBERLAB_WEB/dashboard.py" || true)"

if [ -z "$PIDS" ]; then
  echo "[INFO] Dashboard já estava parado"
  exit 0
fi

echo "$PIDS" | while read -r pid; do
  [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
done

sleep 1

if pgrep -f "$CYBERLAB_WEB/dashboard.py" >/dev/null 2>&1; then
  echo "[WARN] Ainda ativo, forçando..."
  pkill -9 -f "$CYBERLAB_WEB/dashboard.py" 2>/dev/null || true
fi

echo "[OK] Dashboard parado"
