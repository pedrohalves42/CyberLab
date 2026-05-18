#!/usr/bin/env bash
set -euo pipefail

BASE="$CYBERLAB_HOME"
PY="$BASE/core/client_final_delivery/technical_severity_integrity_fix.py"
CTX="$BASE/state/audit/current_audit_context.json"

echo "========================================================================"
echo " CyberLab — Camada 4C.2"
echo " Integridade de severidade técnica antes da publicação final"
echo "========================================================================"
echo ""

SCAN_DIR="${1:-}"

if [ -z "$SCAN_DIR" ]; then
  SCAN_DIR="$(
    python3 - <<'PY'
import json
from pathlib import Path

p = Path.home() / "CyberLab/state/audit/current_audit_context.json"

if not p.exists():
    print("")
    raise SystemExit(0)

try:
    data = json.loads(p.read_text(encoding="utf-8"))
except Exception:
    print("")
    raise SystemExit(0)

scan = (
    data.get("scan_dir")
    or data.get("paths", {}).get("scan_dir")
    or ""
)

print(scan)
PY
  )"
fi

if [ -z "$SCAN_DIR" ]; then
  echo "[ERRO] Não foi possível identificar a pasta oficial do scan."
  echo "Uso:"
  echo "  bash modules/client_final_delivery/block_17_4c2_technical_severity_integrity_fix.sh /caminho/do/scan"
  exit 1
fi

if [ ! -d "$SCAN_DIR" ]; then
  echo "[ERRO] Pasta do scan não encontrada:"
  echo "  $SCAN_DIR"
  exit 1
fi

if [ ! -f "$PY" ]; then
  echo "[ERRO] Core da Camada 4C.2 não encontrado:"
  echo "  $PY"
  exit 1
fi

echo "[OK] Scan oficial: $SCAN_DIR"
echo ""

python3 "$PY" "$SCAN_DIR"

echo ""
echo "[OK] Wrapper da Camada 4C.2 concluído."
