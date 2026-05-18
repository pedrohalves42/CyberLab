#!/usr/bin/env bash
set -euo pipefail

BASE="$CYBERLAB_HOME"
QUEUE="$BASE/queue"

mkdir -p "$QUEUE/pending" "$QUEUE/running" "$QUEUE/finished" "$QUEUE/failed"

CMD="${1:-help}"

case "$CMD" in
  add)
    CLIENT="${2:-}"
    TARGET="${3:-}"
    MODE="${4:-safe}"

    [ -n "$CLIENT" ] && [ -n "$TARGET" ] || { echo "[ERRO] Uso: cyberlab queue add \"Cliente\" dominio.com safe"; exit 1; }

    ID="job-$(date +%Y%m%d-%H%M%S)-$RANDOM"
    FILE="$QUEUE/pending/$ID.json"

    cat > "$FILE" <<JSON
{
  "job_id": "$ID",
  "client": "$CLIENT",
  "target": "$TARGET",
  "mode": "$MODE",
  "status": "pending",
  "created_at": "$(date -Iseconds)"
}
JSON

    echo "[OK] job criado:"
    echo "$FILE"
    ;;
  list)
    echo "==== PENDING ===="
    find "$QUEUE/pending" -type f -name "*.json" 2>/dev/null | sort || true
    echo
    echo "==== RUNNING ===="
    find "$QUEUE/running" -type f -name "*.json" 2>/dev/null | sort || true
    echo
    echo "==== FINISHED ===="
    find "$QUEUE/finished" -type f -name "*.json" 2>/dev/null | sort || true
    echo
    echo "==== FAILED ===="
    find "$QUEUE/failed" -type f -name "*.json" 2>/dev/null | sort || true
    ;;
  *)
    echo "Uso:"
    echo "cyberlab queue add \"Cliente\" dominio.com safe"
    echo "cyberlab queue list"
    ;;
esac
