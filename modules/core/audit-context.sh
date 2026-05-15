#!/bin/bash
set -euo pipefail

CYBERLAB_HOME="${HOME}/CyberLab"
PYTHON_BIN="${CYBERLAB_HOME}/.venv/bin/python3"

if [ ! -x "$PYTHON_BIN" ]; then
  PYTHON_BIN="python3"
fi

# Compatibilidade: caso o dispatcher repasse o nome do comando
if [ "${1:-}" = "audit-context" ] || [ "${1:-}" = "context" ]; then
  shift || true
fi

if [ "$#" -eq 0 ]; then
  set -- show
fi

exec "$PYTHON_BIN" "$CYBERLAB_HOME/core/audit_context.py" "$@"
