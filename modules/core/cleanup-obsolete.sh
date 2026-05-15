#!/bin/bash
set -euo pipefail

source "$HOME/CyberLab/core/bootstrap.sh"

MODE="${1:-dry-run}"

python3 "$CYBERLAB_HOME/modules/core/cleanup-obsolete.py" "$MODE"
