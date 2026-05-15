#!/bin/bash

source "$HOME/CyberLab/core/bootstrap.sh"

SESSION="CYBERLAB-HUD"

TARGET="$1"
MODE="${2:-safe}"
CLIENT="${3:-LabInterno}"

if [ -z "$TARGET" ]; then
  echo "Uso:"
  echo "  cyberlab hud alvo.com safe Cliente"
  echo
  echo "Exemplo:"
  echo "  cyberlab hud cybshield.com.br safe CyberShield"
  exit 1
fi

TARGET="$(clean_target "$TARGET")"

if ! validate_target "$TARGET"; then
  exit 1
fi

if ! validate_mode "$MODE"; then
  exit 1
fi

check_scope "$TARGET" || exit 1

tmux kill-session -t "$SESSION" 2>/dev/null || true

tmux new-session -d -s "$SESSION" -n "CyberLab"

tmux send-keys -t "$SESSION":0.0 "clear; echo '==== CYBERLAB HUD ===='; echo 'Alvo: $TARGET'; echo 'Modo: $MODE'; echo 'Cliente: $CLIENT'; echo; cyberlab scan $TARGET $MODE '$CLIENT'" C-m

tmux split-window -h -t "$SESSION":0
tmux send-keys -t "$SESSION":0.1 "clear; echo '==== DASHBOARD ===='; echo 'Abrir: http://127.0.0.1:9088'; cyberlab dashboard" C-m

tmux split-window -v -t "$SESSION":0.1
tmux send-keys -t "$SESSION":0.2 "clear; echo '==== SYSTEM STATUS ===='; while true; do clear; cyberlab network status; echo; cyberlab kernel risk; echo; sleep 10; done" C-m

tmux select-pane -t "$SESSION":0.0
tmux split-window -v -t "$SESSION":0.0
tmux send-keys -t "$SESSION":0.3 "clear; echo '==== LOGS ===='; touch '$CYBERLAB_LOGS/cyberlab.log'; tail -f '$CYBERLAB_LOGS/cyberlab.log'" C-m

tmux select-layout -t "$SESSION":0 tiled

tmux attach-session -t "$SESSION"
