#!/usr/bin/env bash
set -euo pipefail

source "$HOME/CyberLab/core/bootstrap.sh"

SCAN_DIR="${1:-}"

echo "=============================================================="
echo " CyberLab — Camada 4C.1"
echo " Polimento editorial e preparação para PDFs finais"
echo "=============================================================="
echo ""

if [ -n "$SCAN_DIR" ]; then
    python3 "$HOME/CyberLab/core/client_final_delivery/editorial_polisher.py" "$SCAN_DIR"
else
    python3 "$HOME/CyberLab/core/client_final_delivery/editorial_polisher.py"
fi
