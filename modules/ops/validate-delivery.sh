#!/bin/bash
source "$HOME/CyberLab/core/bootstrap.sh"

CLIENT="$1"
[ -z "$CLIENT" ] && echo "Uso: validate-delivery Cliente" && exit 1

DIR="$(cyberlab delivery latest "$CLIENT" 2>/dev/null)"
[ ! -d "$DIR" ] && echo "[ERRO] Delivery não encontrado" && exit 1

echo "==== VALIDANDO ENTREGA ===="
for f in \
 "$DIR/summary.txt" \
 "$DIR/manifest.json" \
 "$DIR/validation.txt" \
 "$DIR/reports/report.pdf" \
 "$DIR/reports/report.html" \
 "$DIR/reports/executive-report.md" \
 "$DIR/reports/technical-report.md" \
 "$DIR/json/summary.json" \
 "$DIR/json/risk-summary.json"; do
  [ -f "$f" ] && echo "[OK] $f" || echo "[MISS] $f"
done

echo
echo "[JSON]"
find "$DIR" -name "*.json" | while read j; do
  jq empty "$j" >/dev/null 2>&1 && echo "[OK] $j" || echo "[BROKEN] $j"
done
