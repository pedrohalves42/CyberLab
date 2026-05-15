#!/usr/bin/env bash
set -euo pipefail

BASE="$HOME/CyberLab"
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
