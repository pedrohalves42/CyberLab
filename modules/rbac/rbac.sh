#!/usr/bin/env bash
set -euo pipefail

BASE="$HOME/CyberLab"
RBAC="$BASE/config/rbac.json"

CMD="${1:-help}"

case "$CMD" in
  show)
    jq . "$RBAC"
    ;;
  role)
    USERNAME="${2:-${USER:-unknown}}"
    jq -r --arg u "$USERNAME" '.users[$u] // .default_role' "$RBAC"
    ;;
  can)
    ACTION="${2:-}"
    USERNAME="${3:-${USER:-unknown}}"
    ROLE="$(jq -r --arg u "$USERNAME" '.users[$u] // .default_role' "$RBAC")"

    if jq -e --arg r "$ROLE" '.roles[$r][]? == "*"' "$RBAC" >/dev/null; then
      echo "[OK] permitido: $USERNAME/$ROLE -> $ACTION"
      exit 0
    fi

    if jq -e --arg r "$ROLE" --arg a "$ACTION" '.roles[$r][]? == $a' "$RBAC" >/dev/null; then
      echo "[OK] permitido: $USERNAME/$ROLE -> $ACTION"
      exit 0
    fi

    echo "[BLOCKED] negado: $USERNAME/$ROLE -> $ACTION"
    exit 1
    ;;
  *)
    echo "Uso:"
    echo "cyberlab rbac show"
    echo "cyberlab rbac role"
    echo "cyberlab rbac can active_mode"
    ;;
esac
