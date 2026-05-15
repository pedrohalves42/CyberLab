#!/bin/bash
set -euo pipefail

source "$HOME/CyberLab/core/bootstrap.sh"

LATEST_SCAN="${1:-}"

if [ -z "$LATEST_SCAN" ]; then
    echo "[ERRO] Informe a pasta oficial do scan."
    echo "Uso: block_17_4a1_client_calibration.sh /caminho/do/scan"
    exit 1
fi

echo "============================================================"
echo " CyberLab — Camada 4A.1"
echo " Calibração de risco real, revisão manual e prevenção"
echo "============================================================"

python3 "$CYBERLAB_HOME/core/client_final_delivery/findings_client_calibrator.py" \
    "$LATEST_SCAN"
