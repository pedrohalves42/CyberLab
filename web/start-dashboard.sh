#!/bin/bash

source "${CYBERLAB_HOME:-$HOME/CyberLab}/core/bootstrap.sh"

echo "==== CYBERLAB DASHBOARD ===="
echo "Abrir: http://127.0.0.1:9088"
echo

python3 "$CYBERLAB_WEB/dashboard.py"
