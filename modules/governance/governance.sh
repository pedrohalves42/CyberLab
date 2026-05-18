#!/usr/bin/env bash
set -euo pipefail

BASE="$CYBERLAB_HOME"
OPS="$BASE/operations"
CURRENT="$BASE/state/current-operation.txt"

mkdir -p "$OPS" "$BASE/state" "$BASE/audit"

slugify() {
  echo "$1" \
    | tr '[:upper:]' '[:lower:]' \
    | sed 's/[^a-z0-9]/-/g' \
    | sed 's/-\+/-/g' \
    | sed 's/^-//;s/-$//'
}

now() {
  date -Iseconds
}

current_op() {
  cat "$CURRENT" 2>/dev/null || true
}

require_current_op() {
  OP="$(current_op)"
  if [ -z "$OP" ] || [ ! -d "$OP" ]; then
    echo "[ERRO] Nenhuma operação ativa."
    echo "Use: cyberlab gov create \"Cliente\" dominio.com"
    exit 1
  fi
  echo "$OP"
}

audit_log() {
  OP="$1"
  ACTION="$2"
  STATUS="$3"
  MESSAGE="$4"

  mkdir -p "$OP/audit"

  LINE="$(now) | action=$ACTION | status=$STATUS | message=$MESSAGE"
  echo "$LINE" >> "$OP/audit/audit.log"
  echo "$LINE" >> "$BASE/audit/global-audit.log"
}

create_operation() {
  CLIENT="${1:-}"
  TARGET="${2:-}"

  if [ -z "$CLIENT" ] || [ -z "$TARGET" ]; then
    echo "[ERRO] Uso: cyberlab gov create \"Cliente\" dominio.com"
    exit 1
  fi

  SLUG="$(slugify "$CLIENT")"
  DATE_ID="$(date +%Y%m%d-%H%M%S)"
  OP_ID="op-$DATE_ID-$SLUG"
  OP="$OPS/$OP_ID"

  mkdir -p \
    "$OP/state/intelligence" \
    "$OP/state/reports" \
    "$OP/evidence" \
    "$OP/delivery" \
    "$OP/reports" \
    "$OP/audit" \
    "$OP/logs" \
    "$OP/tmp"

  cat > "$OP/metadata.json" <<JSON
{
  "operation_id": "$OP_ID",
  "client": "$CLIENT",
  "client_slug": "$SLUG",
  "target": "$TARGET",
  "created_at": "$(now)",
  "created_by": "${USER:-unknown}",
  "framework": "CyberLab",
  "governance_version": "1.0"
}
JSON

  cat > "$OP/scope.json" <<JSON
{
  "operation_id": "$OP_ID",
  "target": "$TARGET",
  "allowed_domains": [
    "$TARGET",
    "*.$TARGET"
  ],
  "allowed_ips": [],
  "denied_domains": [],
  "denied_ips": [],
  "third_party_policy": "deny_by_default",
  "created_at": "$(now)"
}
JSON

  cat > "$OP/policy.json" <<JSON
{
  "operation_id": "$OP_ID",
  "mode": "safe",
  "allowed_modules": {
    "scan": true,
    "threat": true,
    "finding": true,
    "intelligence": true,
    "correlate": true,
    "report": true,
    "delivery": true,
    "active_fuzzing": false,
    "exploit": false,
    "dos": false,
    "credential_attack": false
  },
  "limits": {
    "threads": 5,
    "rate_per_second": 5,
    "max_runtime_minutes": 60
  },
  "approval": {
    "required_for_active": true,
    "required_for_offensive": true,
    "required_for_redteam": true
  },
  "created_at": "$(now)"
}
JSON

  cat > "$OP/state.json" <<JSON
{
  "operation_id": "$OP_ID",
  "status": "created",
  "current_stage": "governance",
  "last_update": "$(now)"
}
JSON

  cat > "$OP/status.json" <<JSON
{
  "operation_id": "$OP_ID",
  "status": "ready",
  "safe_to_run": true,
  "message": "Governance initialized. Scope and policy created.",
  "updated_at": "$(now)"
}
JSON

  echo "$OP" > "$CURRENT"

  audit_log "$OP" "create_operation" "OK" "Operation created for $CLIENT / $TARGET"

  echo "[OK] Operação criada:"
  echo "$OP"
}

use_operation() {
  ID="${1:-}"

  if [ -z "$ID" ]; then
    echo "[ERRO] Uso: cyberlab gov use op-id"
    exit 1
  fi

  if [ -d "$OPS/$ID" ]; then
    OP="$OPS/$ID"
  elif [ -d "$ID" ]; then
    OP="$ID"
  else
    echo "[ERRO] Operação não encontrada: $ID"
    exit 1
  fi

  echo "$OP" > "$CURRENT"
  audit_log "$OP" "use_operation" "OK" "Operation selected"

  echo "[OK] Operação ativa:"
  echo "$OP"
}

list_operations() {
  find "$OPS" -maxdepth 1 -type d -name "op-*" | sort
}

status_operation() {
  OP="$(require_current_op)"

  echo "==== CYBERLAB GOVERNANCE STATUS ===="
  echo "Operação: $OP"
  echo

  echo "[metadata]"
  jq . "$OP/metadata.json" 2>/dev/null || cat "$OP/metadata.json"
  echo

  echo "[status]"
  jq . "$OP/status.json" 2>/dev/null || cat "$OP/status.json"
  echo

  echo "[policy]"
  jq . "$OP/policy.json" 2>/dev/null || cat "$OP/policy.json"
}

audit_operation() {
  OP="$(require_current_op)"

  echo "==== AUDIT LOG ===="
  if [ -f "$OP/audit/audit.log" ]; then
    cat "$OP/audit/audit.log"
  else
    echo "[WARN] Sem logs de auditoria ainda."
  fi
}

sync_operation() {
  OP="$(require_current_op)"

  mkdir -p \
    "$OP/state/intelligence" \
    "$OP/state/reports" \
    "$OP/reports"

  cp "$BASE/state/intelligence/"*.json "$OP/state/intelligence/" 2>/dev/null || true
  cp "$BASE/state/reports/"* "$OP/state/reports/" 2>/dev/null || true

  cat > "$OP/state.json" <<JSON
{
  "operation_id": "$(basename "$OP")",
  "status": "synced",
  "current_stage": "post-pipeline",
  "last_update": "$(now)"
}
JSON

  audit_log "$OP" "sync_operation" "OK" "Global state synchronized into operation"

  echo "[OK] Operação sincronizada:"
  echo "$OP"
}

close_operation() {
  OP="$(require_current_op)"

  cat > "$OP/status.json" <<JSON
{
  "operation_id": "$(basename "$OP")",
  "status": "closed",
  "safe_to_run": false,
  "message": "Operation closed by operator.",
  "updated_at": "$(now)"
}
JSON

  audit_log "$OP" "close_operation" "OK" "Operation closed"

  echo "[OK] Operação encerrada:"
  echo "$OP"
}

case "${1:-help}" in
  create)
    shift
    create_operation "$@"
    ;;
  use)
    shift
    use_operation "$@"
    ;;
  current)
    current_op
    ;;
  list)
    list_operations
    ;;
  status)
    status_operation
    ;;
  audit)
    audit_operation
    ;;
  sync)
    sync_operation
    ;;
  close)
    close_operation
    ;;
  *)
    echo "Uso:"
    echo "cyberlab gov create \"Cliente\" dominio.com"
    echo "cyberlab gov use op-id"
    echo "cyberlab gov current"
    echo "cyberlab gov list"
    echo "cyberlab gov status"
    echo "cyberlab gov audit"
    echo "cyberlab gov sync"
    echo "cyberlab gov close"
    ;;
esac
