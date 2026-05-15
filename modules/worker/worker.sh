#!/usr/bin/env bash
set -euo pipefail

BASE="$HOME/CyberLab"
QUEUE="$BASE/queue"

mkdir -p "$QUEUE/pending" "$QUEUE/running" "$QUEUE/finished" "$QUEUE/failed"

run_one(){
  JOB="$(find "$QUEUE/pending" -type f -name "*.json" 2>/dev/null | sort | head -n 1 || true)"

  if [ -z "$JOB" ]; then
    echo "[OK] fila vazia"
    exit 0
  fi

  ID="$(jq -r '.job_id' "$JOB")"
  CLIENT="$(jq -r '.client' "$JOB")"
  TARGET="$(jq -r '.target' "$JOB")"
  MODE="$(jq -r '.mode' "$JOB")"

  RUN="$QUEUE/running/$ID.json"
  FIN="$QUEUE/finished/$ID.json"
  FAIL="$QUEUE/failed/$ID.json"

  mv "$JOB" "$RUN"

  echo "==== CYBERLAB QUEUE WORKER ===="
  echo "Job:    $ID"
  echo "Client: $CLIENT"
  echo "Target: $TARGET"
  echo "Mode:   $MODE"
  echo

  if [ "$MODE" = "active" ]; then
    CMD=(cyberlab active run "$CLIENT" "$TARGET" active)
  else
    CMD=(cyberlab op run "$CLIENT" "$TARGET" safe)
  fi

  if "${CMD[@]}"; then
    jq '.status="finished" | .finished_at=now|todate' "$RUN" > "$FIN"
    rm -f "$RUN"
    echo "[OK] job finalizado: $ID"
  else
    jq '.status="failed" | .failed_at=now|todate' "$RUN" > "$FAIL"
    rm -f "$RUN"
    echo "[FAIL] job falhou: $ID"
    exit 1
  fi
}

loop(){
  INTERVAL="${1:-10}"

  echo "==== CYBERLAB WORKER LOOP ===="
  echo "Intervalo: $INTERVAL segundos"
  echo

  while true; do
    if find "$QUEUE/pending" -type f -name "*.json" 2>/dev/null | grep -q .; then
      bash "$BASE/modules/worker/worker.sh" run-one || true
    else
      echo "[$(date -Iseconds)] fila vazia"
    fi

    sleep "$INTERVAL"
  done
}

case "${1:-help}" in
  run-one)
    run_one
    ;;
  loop)
    shift
    loop "${1:-10}"
    ;;
  *)
    echo "Uso:"
    echo "cyberlab worker run-one"
    echo "cyberlab worker loop 10"
    ;;
esac
