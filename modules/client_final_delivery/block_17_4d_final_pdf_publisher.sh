#!/bin/bash
set -euo pipefail

source "$HOME/CyberLab/core/bootstrap.sh" 2>/dev/null || true
source "$HOME/CyberLab/.venv/bin/activate" 2>/dev/null || true

SCAN_DIR="${1:-}"

echo "============================================================"
echo " CyberLab — Camada 4D"
echo " Publicação de PDFs finais do cliente"
echo "============================================================"

if [ -n "$SCAN_DIR" ]; then
    python3 "$HOME/CyberLab/core/client_final_delivery/final_pdf_publisher.py" "$SCAN_DIR"
else
    python3 "$HOME/CyberLab/core/client_final_delivery/final_pdf_publisher.py"
fi
