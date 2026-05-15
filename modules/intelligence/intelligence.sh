#!/bin/bash
source "$HOME/CyberLab/core/bootstrap.sh"

INPUT="${1:-}"

if [ -z "$INPUT" ]; then
  INPUT="$CYBERLAB_STATE/intelligence/findings-scored.json"
fi

if [ ! -f "$INPUT" ]; then
  echo "[INFO] Findings não encontrado. Rodando intelligence antigo para gerar base..."
  python3 "$CYBERLAB_MODULES/findings/findings-engine.py" 2>/dev/null || true
  python3 "$CYBERLAB_MODULES/intelligence/false-positive-engine.py" 2>/dev/null || true
  python3 "$CYBERLAB_MODULES/risk/risk-engine.py" 2>/dev/null || true
  INPUT="$CYBERLAB_STATE/intelligence/findings-scored.json"
fi

if [ ! -f "$INPUT" ]; then
  echo "[ERRO] Nenhum findings-scored.json encontrado."
  exit 1
fi

bash "$CYBERLAB_MODULES/intelligence/intelligence-pipeline.sh" "$INPUT"
