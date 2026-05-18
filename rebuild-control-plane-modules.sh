#!/usr/bin/env bash
set -euo pipefail

BASE="$CYBERLAB_HOME"

echo "==== REBUILD CONTROL PLANE MODULES ===="

mkdir -p \
  "$BASE/modules/rbac" \
  "$BASE/modules/evidence" \
  "$BASE/modules/approval" \
  "$BASE/modules/control" \
  "$BASE/modules/queue" \
  "$BASE/config" \
  "$BASE/queue/pending" \
  "$BASE/queue/running" \
  "$BASE/queue/finished" \
  "$BASE/queue/failed"

cat > "$BASE/config/rbac.json" <<'JSON'
{
  "roles": {
    "admin": ["*"],
    "operator": ["safe_run", "scan", "threat", "finding", "intelligence", "correlate", "report", "delivery", "quality"],
    "auditor": ["read", "audit", "quality", "evidence"],
    "viewer": ["read"]
  },
  "users": {
    "ph": "admin"
  },
  "default_role": "viewer"
}
JSON

cat > "$BASE/modules/rbac/rbac.sh" <<'RBAC'
#!/usr/bin/env bash
set -euo pipefail

BASE="$CYBERLAB_HOME"
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
RBAC

cat > "$BASE/modules/evidence/evidence.sh" <<'EVIDENCE'
#!/usr/bin/env bash
set -euo pipefail

BASE="$CYBERLAB_HOME"
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
EVIDENCE

cat > "$BASE/modules/approval/approval.sh" <<'APPROVAL'
#!/usr/bin/env bash
set -euo pipefail

BASE="$CYBERLAB_HOME"
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
APPROVAL

cat > "$BASE/modules/control/control.sh" <<'CONTROL'
#!/usr/bin/env bash
set -euo pipefail

BASE="$CYBERLAB_HOME"
CURRENT="$BASE/state/current-operation.txt"
OP="$(cat "$CURRENT" 2>/dev/null || true)"
CMD="${1:-help}"

case "$CMD" in
  signature)
    [ -n "$OP" ] && [ -d "$OP" ] || { echo "[ERRO] operação ativa ausente"; exit 1; }

    mkdir -p "$OP/evidence"

    POLICY_HASH="$(sha256sum "$OP/policy.json" | awk '{print $1}')"
    SCOPE_HASH="$(sha256sum "$OP/scope.json" | awk '{print $1}')"

    cat > "$OP/evidence/runtime-signature.json" <<JSON
{
  "operation": "$(basename "$OP")",
  "operator": "${USER:-unknown}",
  "policy_hash": "$POLICY_HASH",
  "scope_hash": "$SCOPE_HASH",
  "generated_at": "$(date -Iseconds)"
}
JSON

    echo "[OK] runtime signature criada"
    ;;
  active-gate)
    ACTION="${2:-active_mode}"

    echo "==== CYBERLAB ACTIVE CONTROL GATE ===="

    cyberlab rbac can active_mode
    cyberlab approval check "$ACTION"
    cyberlab policy validate
    cyberlab runtime validate 5 5

    echo "[OK] Active Gate liberado com controle"
    ;;
  *)
    echo "Uso:"
    echo "cyberlab control signature"
    echo "cyberlab control active-gate active_mode"
    ;;
esac
CONTROL

cat > "$BASE/modules/queue/queue.sh" <<'QUEUE'
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
QUEUE

chmod +x \
  "$BASE/modules/rbac/rbac.sh" \
  "$BASE/modules/evidence/evidence.sh" \
  "$BASE/modules/approval/approval.sh" \
  "$BASE/modules/control/control.sh" \
  "$BASE/modules/queue/queue.sh"

echo "[OK] módulos control plane recriados"
