#!/bin/bash

SESSION="cyberlab-monitor"

echo "==== CYBERLAB MONITOR STOP ===="

if tmux has-session -t "$SESSION" 2>/dev/null; then
  tmux kill-session -t "$SESSION"
  echo "[OK] Monitor parado"
else
  echo "[INFO] Monitor já estava parado"
fi
