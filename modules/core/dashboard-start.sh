#!/bin/bash

set -u

source "$HOME/CyberLab/core/bootstrap.sh"

LOG="/tmp/cyberlab-dashboard.log"

echo "==== CYBERLAB DASHBOARD START ===="

if pgrep -f "$CYBERLAB_WEB/dashboard.py" >/dev/null 2>&1; then
  echo "[INFO] Dashboard já está rodando."
  echo "Abrir: http://127.0.0.1:9088"
  exit 0
fi

if [ ! -f "$CYBERLAB_WEB/dashboard.py" ]; then
  echo "[ERRO] dashboard.py não encontrado em:"
  echo "$CYBERLAB_WEB/dashboard.py"
  exit 1
fi

python3 - <<'PY'
try:
    import flask
    print("[OK] Flask instalado")
except Exception as e:
    print("[ERRO] Flask não instalado:", e)
    raise SystemExit(1)
PY

cd "$CYBERLAB_WEB" || exit 1

nohup python3 dashboard.py > "$LOG" 2>&1 &

sleep 2

if pgrep -f "$CYBERLAB_WEB/dashboard.py" >/dev/null 2>&1; then
  echo "[OK] Dashboard iniciado"
  echo "Abrir: http://127.0.0.1:9088"
else
  echo "[ERRO] Dashboard falhou"
  echo "Log:"
  cat "$LOG" 2>/dev/null || true
  exit 1
fi
