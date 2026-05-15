#!/bin/bash

source "$HOME/CyberLab/core/bootstrap.sh"

CMD="${1:-latest}"

latest_web="$(cat "$CYBERLAB_RESULTS/web/latest.txt" 2>/dev/null || true)"
latest_detection="$(cat "$CYBERLAB_RESULTS/detection/latest.txt" 2>/dev/null || true)"
latest_correlation="$(cat "$CYBERLAB_RESULTS/correlation/latest.txt" 2>/dev/null || true)"
latest_threat="$(cat "$CYBERLAB_RESULTS/threat/latest.txt" 2>/dev/null || true)"

OUT="$CYBERLAB_RESULTS/report/report-$(date +%Y-%m-%d_%H-%M-%S)"
mkdir -p "$OUT"

REPORT="$OUT/cyberlab-report.md"

{
echo "# CyberLab Unified Report"
echo
echo "**Data:** $(date)"
echo "**Host:** $(hostname)"
echo
echo "## Últimos Resultados"
echo
echo "- Web: ${latest_web:-N/A}"
echo "- Threat: ${latest_threat:-N/A}"
echo "- Detection: ${latest_detection:-N/A}"
echo "- Correlation: ${latest_correlation:-N/A}"
echo
echo "## Threat Report"
echo
if [ -f "$latest_threat/report/threat-report.md" ]; then
  cat "$latest_threat/report/threat-report.md"
else
  echo "Threat report não encontrado."
fi
echo
echo "## Detection Report"
echo
if [ -f "$latest_detection/report/detection-report.md" ]; then
  cat "$latest_detection/report/detection-report.md"
else
  echo "Detection report não encontrado."
fi
echo
echo "## Correlation Report"
echo
if [ -f "$latest_correlation/report/correlation-report.md" ]; then
  cat "$latest_correlation/report/correlation-report.md"
else
  echo "Correlation report não encontrado."
fi
} > "$REPORT"

echo "$OUT" > "$CYBERLAB_RESULTS/report/latest.txt"

echo "[OK] Relatório unificado gerado:"
echo "$REPORT"
