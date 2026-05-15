#!/usr/bin/env bash

set -euo pipefail

BASE="$HOME/CyberLab"

###############################################################################
# HELPERS
###############################################################################

current_operation() {
    cat "$BASE/.current_operation" 2>/dev/null || true
}

set_current_operation() {
    echo "$1" > "$BASE/.current_operation"
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "[ERRO] comando não encontrado: $1"
        exit 1
    }
}

ensure_file() {
    [ -f "$1" ] || {
        echo "[ERRO] arquivo ausente:"
        echo "$1"
        exit 1
    }
}

###############################################################################
# GOVERNANCE
###############################################################################

gov_create() {
    local CLIENT="$1"
    local TARGET="$2"

    cyberlab gov create "$CLIENT" "$TARGET" >/dev/null
}

gov_use_latest() {

    local OP

    OP="$(cyberlab gov list | tail -n 1)"

    if [ -z "$OP" ]; then
        echo "[ERRO] nenhuma operação encontrada"
        exit 1
    fi

    set_current_operation "$OP"

    echo "$OP"
}

###############################################################################
# POLICY
###############################################################################

policy_prepare() {

    local MODE="$1"

    cyberlab policy mode "$MODE" >/dev/null
    cyberlab policy validate >/dev/null
}

###############################################################################
# RUNTIME
###############################################################################

runtime_prepare() {

    cyberlab runtime validate 5 5 >/dev/null
}

###############################################################################
# PIPELINE
###############################################################################

run_pipeline() {

    local CLIENT="$1"
    local TARGET="$2"
    local MODE="$3"

    echo
    echo "==== CYBERLAB OPERATION WRAPPER ===="
    echo
    echo "Cliente: $CLIENT"
    echo "Target:  $TARGET"
    echo "Modo:    $MODE"
    echo

    ###########################################################################
    # GOVERNANCE
    ###########################################################################

    echo "[1/10] Governance"

    gov_create "$CLIENT" "$TARGET"

    OP="$(gov_use_latest)"

    echo "[OK] operação:"
    echo "$OP"

    ###########################################################################
    # SCOPE
    ###########################################################################

    echo
    echo "[2/10] Scope"

    cyberlab scope check "$TARGET"

    ###########################################################################
    # POLICY
    ###########################################################################

    echo
    echo "[3/10] Policy"

    policy_prepare "$MODE"

    ###########################################################################
    # RUNTIME
    ###########################################################################

    echo
    echo "[4/10] Runtime"

    runtime_prepare

    ###########################################################################
    # SCAN
    ###########################################################################

    echo
    echo "[5/10] Scan"

    cyberlab scan "$TARGET" "$MODE"

    ###########################################################################
    # THREAT
    ###########################################################################

    echo
    echo "[6/10] Threat"

    cyberlab threat "$TARGET"

    ###########################################################################
    # FINDING
    ###########################################################################

    echo
    echo "[7/10] Finding"

    cyberlab finding

    ###########################################################################
    # INTELLIGENCE
    ###########################################################################

    echo
    echo "[8/10] Intelligence"

    cyberlab intelligence

    ###########################################################################
    # CORRELATE
    ###########################################################################

    echo
    echo "[9/10] Correlate"

    cyberlab correlate

    ###########################################################################
    # REPORT + DELIVERY
    ###########################################################################

    echo
    echo "[10/10] Report + Delivery"

    cyberlab report

    cyberlab delivery generate "$CLIENT"

    ###########################################################################
    # VALIDATION
    ###########################################################################

    echo
    echo "==== FINAL VALIDATION ===="

    DELIVERY="$(cyberlab delivery latest "$CLIENT")"

    if [ -z "$DELIVERY" ]; then
        echo "[ERRO] delivery não encontrado"
        exit 1
    fi

    echo "[OK] Delivery:"
    echo "$DELIVERY"

    ensure_file "$DELIVERY/json/findings-scored.json"
    ensure_file "$DELIVERY/json/risk-summary.json"
    ensure_file "$DELIVERY/json/analytics.json"
    ensure_file "$DELIVERY/json/remediation-plan.json"

    echo "[OK] JSONs principais"

    if grep -R "\[BROKEN\]" "$DELIVERY" >/dev/null 2>&1; then
        echo "[ERRO] pacote contém itens BROKEN"
        exit 1
    fi

    echo "[OK] pacote íntegro"

    echo
    echo "==== OPERATION FINALIZADA ===="
    echo
    echo "[OK] Cliente:"
    echo "$CLIENT"
    echo
    echo "[OK] Target:"
    echo "$TARGET"
    echo
    echo "[OK] Delivery:"
    echo "$DELIVERY"
    echo
}

###############################################################################
# STATUS
###############################################################################

op_status() {

    local OP

    OP="$(current_operation)"

    echo "==== CYBERLAB OP STATUS ===="

    if [ -z "$OP" ]; then
        echo "[ERRO] nenhuma operação ativa"
        exit 1
    fi

    echo
    echo "Operação:"
    echo "$OP"
    echo

    if [ -f "$OP/metadata.json" ]; then
        cat "$OP/metadata.json"
    fi
}

###############################################################################
# MAIN
###############################################################################

SUB="${1:-}"

case "$SUB" in

    run)

        CLIENT="${2:-}"
        TARGET="${3:-}"
        MODE="${4:-safe}"

        if [ -z "$CLIENT" ] || [ -z "$TARGET" ]; then
            echo "Uso:"
            echo "cyberlab op run \"Cliente\" dominio.com safe"
            exit 1
        fi

        run_pipeline "$CLIENT" "$TARGET" "$MODE"
        ;;

    status)

        op_status
        ;;

    *)

        echo "Uso:"
        echo "cyberlab op run \"Cliente\" dominio.com safe"
        echo "cyberlab op status"
        ;;
esac
