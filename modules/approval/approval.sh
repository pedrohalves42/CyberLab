#!/usr/bin/env bash
set -euo pipefail

BASE="$HOME/CyberLab"
CURRENT="$BASE/state/current-operation.txt"
OP="$(cat "$CURRENT" 2>/dev/null || true)"

if [ -z "$OP" ] || [ ! -d "$OP" ]; then
  echo "[ERRO] Nenhuma operação ativa."
  exit 1
fi

CMD="${1:-help}"

case "$CMD" in
  create)
    ACTION="${2:-}"
    [ -n "$ACTION" ] || { echo "[ERRO] Uso: cyberlab approval create active_mode"; exit 1; }

    mkdir -p "$OP/approval" "$OP/audit"
    TOKEN="$(date +%s)-$RANDOM-$RANDOM"

    cat > "$OP/approval/$ACTION.json" <<JSON
{
  "operation": "$(basename "$OP")",
  "action": "$ACTION",
  "approved": true,
  "approved_by": "${USER:-unknown}",
  "token": "$TOKEN",
  "created_at": "$(date -Iseconds)"
}
JSON

    echo "$(date -Iseconds) | approval_created | action=$ACTION | by=${USER:-unknown}" >> "$OP/audit/audit.log"

    echo "[OK] approval criado: $ACTION"
    echo "TOKEN=$TOKEN"
    ;;
  check)
    ACTION="${2:-}"
    FILE="$OP/approval/$ACTION.json"

    if [ ! -f "$FILE" ]; then
      echo "[BLOCKED] approval ausente: $ACTION"
      exit 1
    fi

    jq -e '.approved == true' "$FILE" >/dev/null
    echo "[OK] approval válido: $ACTION"
    ;;
  list)
    find "$OP/approval" -type f -name "*.json" 2>/dev/null | sort || true
    ;;
  *)
    echo "Uso:"
    echo "cyberlab approval create active_mode"
    echo "cyberlab approval check active_mode"
    echo "cyberlab approval list"
    ;;
esac
