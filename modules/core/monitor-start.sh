#!/bin/bash

source "$HOME/CyberLab/core/bootstrap.sh"

SESSION="cyberlab-monitor"

echo "==== CYBERLAB MONITOR START ===="

if tmux has-session -t "$SESSION" 2>/dev/null; then
  echo "[INFO] Monitor já ativo"
  echo "Conectar: tmux attach -t $SESSION"
  exit 0
fi

if [ ! -f "$CYBERLAB_UI/monitor.sh" ]; then
  echo "[ERRO] monitor.sh não encontrado"
  exit 1
fi

tmux new-session -d -s "$SESSION" "bash '$CYBERLAB_UI/monitor.sh'"

echo "[OK] Monitor iniciado"
echo "Conectar: tmux attach -t $SESSION"
