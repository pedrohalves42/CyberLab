#!/bin/bash
set -euo pipefail

source "$HOME/CyberLab/core/bootstrap.sh"

SCAN_DIR="${1:-}"

echo "=============================================================="
echo " CyberLab — Camada 4B"
echo " Tradução dos achados para linguagem de cliente final"
echo "=============================================================="

cd "$HOME/CyberLab"

if [ -n "$SCAN_DIR" ]; then
    python3 "$HOME/CyberLab/core/client_final_delivery/client_language_translator.py" \
        --scan-dir "$SCAN_DIR"
else
    python3 "$HOME/CyberLab/core/client_final_delivery/client_language_translator.py"
fi
