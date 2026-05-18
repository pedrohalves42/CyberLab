#!/bin/bash
set -euo pipefail

source "${CYBERLAB_HOME:-$HOME/CyberLab}/core/bootstrap.sh"

echo "========================================================================"
echo " CyberLab — Camada 4C"
echo " Montagem dos relatórios finais-base para entrega ao cliente"
echo "========================================================================"
echo ""

python3 "$CYBERLAB_HOME/core/client_final_delivery/final_report_assembler.py"
