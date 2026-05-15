#!/bin/bash
set -euo pipefail

source "$HOME/CyberLab/core/bootstrap.sh"

cd "$CYBERLAB_HOME"

echo "============================================================"
echo " CyberLab — Camada 4A"
echo " Consolidação e classificação final de achados"
echo "============================================================"

python3 "$CYBERLAB_HOME/core/client_final_delivery/findings_consolidator.py"

echo ""
echo "[OK] Camada 4A finalizada."
