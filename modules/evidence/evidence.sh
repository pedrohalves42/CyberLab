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
  init)
    mkdir -p "$OP/evidence/timeline" "$OP/evidence/hashes" "$OP/evidence/chain"

    cat > "$OP/evidence/execution.json" <<JSON
{
  "operation": "$(basename "$OP")",
  "operator": "${USER:-unknown}",
  "created_at": "$(date -Iseconds)",
  "evidence_version": "1.0"
}
JSON

    echo "$(date -Iseconds) | evidence_initialized | operator=${USER:-unknown}" >> "$OP/evidence/timeline/timeline.log"
    echo "[OK] Evidence inicializada"
    ;;
  timeline)
    shift || true
    mkdir -p "$OP/evidence/timeline"
    echo "$(date -Iseconds) | ${*:-event}" >> "$OP/evidence/timeline/timeline.log"
    echo "[OK] timeline registrada"
    ;;
  show)
    find "$OP/evidence" -type f 2>/dev/null | sort || true
    ;;
  *)
    echo "Uso:"
    echo "cyberlab evidence init"
    echo "cyberlab evidence timeline \"mensagem\""
    echo "cyberlab evidence show"
    ;;
esac
