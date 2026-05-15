#!/usr/bin/env bash
set -euo pipefail

BASE="$HOME/CyberLab"
OPS="$BASE/operations"
CURRENT="$BASE/state/current-operation.txt"

mkdir -p "$OPS" "$BASE/state"

[ "${1:-}" = "op" ] && shift || true

slugify() {
  echo "$1" | tr '[:upper:]' '[:lower:]' \
  | sed 's/[^a-z0-9]/-/g' \
  | sed 's/-\+/-/g' \
  | sed 's/^-//;s/-$//'
}

current_path() {
  cat "$CURRENT" 2>/dev/null || true
}

create_op() {
  CLIENT="${1:-}"
  TARGET="${2:-}"

  [ -z "$CLIENT" ] && {
    echo "[ERRO] Uso: cyberlab op create \"Cliente\" dominio.com"
    exit 1
  }

  SLUG="$(slugify "$CLIENT")"
  OP_ID="op-$(date +%Y%m%d-%H%M%S)-$SLUG"
  OP="$OPS/$OP_ID"

  mkdir -p \
    "$OP/state/intelligence" \
    "$OP/state/reports" \
    "$OP/evidence" \
    "$OP/delivery" \
    "$OP/logs"

  cat > "$OP/client.json" <<JSON
{
  "operation_id": "$OP_ID",
  "client": "$CLIENT",
  "client_slug": "$SLUG",
  "target": "$TARGET",
  "created_at": "$(date -Iseconds)"
}
JSON

  cat > "$OP/manifest.json" <<JSON
{
  "operation_id": "$OP_ID",
  "client": "$CLIENT",
  "client_slug": "$SLUG",
  "target": "$TARGET",
  "status": "created",
  "created_at": "$(date -Iseconds)"
}
JSON

  echo "$OP" > "$CURRENT"

  echo "[OK] Operação criada:"
  echo "$OP"
}

use_op() {
  ID="${1:-}"

  [ -z "$ID" ] && {
    echo "[ERRO] Uso: cyberlab op use op-id"
    exit 1
  }

  if [ -d "$OPS/$ID" ]; then
    echo "$OPS/$ID" > "$CURRENT"
  elif [ -d "$ID" ]; then
    echo "$ID" > "$CURRENT"
  else
    echo "[ERRO] Operação não encontrada: $ID"
    exit 1
  fi

  echo "[OK] Operação ativa:"
  cat "$CURRENT"
}

sync_op() {
  OP="$(current_path)"

  [ -z "$OP" ] || [ ! -d "$OP" ] && {
    echo "[ERRO] Nenhuma operação ativa"
    exit 1
  }

  mkdir -p "$OP/state/intelligence" "$OP/state/reports"

  cp "$BASE/state/intelligence/"*.json "$OP/state/intelligence/" 2>/dev/null || true
  cp "$BASE/state/reports/"* "$OP/state/reports/" 2>/dev/null || true

  LATEST_DELIVERY="$(cat "$BASE/clients/"*/reports/latest-delivery.txt 2>/dev/null | tail -n 1 || true)"
  if [ -n "$LATEST_DELIVERY" ] && [ -d "$LATEST_DELIVERY" ]; then
    rm -rf "$OP/delivery/latest"
    mkdir -p "$OP/delivery"
    cp -r "$LATEST_DELIVERY" "$OP/delivery/latest"
  fi

  python3 <<PY
import json, time
from pathlib import Path

op = Path("$OP")
client = {}
try:
    client = json.loads((op / "client.json").read_text())
except Exception:
    pass

manifest = {
    "operation_id": op.name,
    "client": client.get("client", ""),
    "client_slug": client.get("client_slug", ""),
    "target": client.get("target", ""),
    "status": "synced",
    "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    "paths": {
        "state": str(op / "state"),
        "reports": str(op / "state/reports"),
        "delivery": str(op / "delivery")
    }
}

(op / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2))
PY

  echo "[OK] Operação sincronizada:"
  echo "$OP"
}

run_op() {
  CLIENT="${1:-}"
  TARGET="${2:-}"
  MODE="${3:-safe}"

  [ -z "$CLIENT" ] || [ -z "$TARGET" ] && {
    echo "[ERRO] Uso: cyberlab op run \"Cliente\" dominio.com safe"
    exit 1
  }

  create_op "$CLIENT" "$TARGET"

  cyberlab run-basic "$CLIENT" "$TARGET" "$MODE"
  cyberlab intelligence
  cyberlab correlate
  cyberlab report
  cyberlab delivery generate "$CLIENT"

  sync_op
  cyberlab db sync || true

  echo "[OK] Operação completa finalizada"
}

case "${1:-help}" in
  create) shift; create_op "$@" ;;
  use) shift; use_op "$@" ;;
  current) current_path ;;
  list) find "$OPS" -maxdepth 1 -type d -name "op-*" | sort ;;
  sync) sync_op ;;
  run) shift; run_op "$@" ;;
  *)
    echo "Uso:"
    echo "cyberlab op create \"Cliente\" dominio.com"
    echo "cyberlab op use op-id"
    echo "cyberlab op current"
    echo "cyberlab op list"
    echo "cyberlab op sync"
    echo "cyberlab op run \"Cliente\" dominio.com safe"
    ;;
esac
