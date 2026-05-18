#!/bin/bash
set -euo pipefail

source "${CYBERLAB_HOME:-$HOME/CyberLab}/core/bootstrap.sh" 2>/dev/null || true
source "$CYBERLAB_HOME/.venv/bin/activate" 2>/dev/null || true

SCAN_DIR="${1:-}"

echo "============================================================"
echo " CyberLab — Camada 4D"
echo " Publicação de PDFs finais do cliente"
echo "============================================================"

if [ -n "$SCAN_DIR" ]; then
    python3 "$CYBERLAB_HOME/core/client_final_delivery/final_pdf_publisher.py" "$SCAN_DIR"
else
    python3 "$CYBERLAB_HOME/core/client_final_delivery/final_pdf_publisher.py"
fi
