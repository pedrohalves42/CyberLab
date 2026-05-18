#!/bin/bash
set -euo pipefail

source "${CYBERLAB_HOME:-$HOME/CyberLab}/core/bootstrap.sh"

REPORT="$CYBERLAB_HOME/state/cleanup/latest_cleanup_report.md"
MANIFEST="$CYBERLAB_HOME/state/cleanup/latest_cleanup_manifest.json"

echo "=============================================================="
echo " CyberLab — Cleanup Status"
echo "=============================================================="

if [ -f "$REPORT" ]; then
    cat "$REPORT"
else
    echo "[WARN] Nenhum relatório de limpeza encontrado."
fi

echo ""
if [ -f "$MANIFEST" ]; then
    echo "[INFO] Manifesto JSON: $MANIFEST"
fi
