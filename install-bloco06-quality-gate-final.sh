#!/usr/bin/env bash
set -euo pipefail

BASE="$CYBERLAB_HOME"

echo "==== CYBERLAB BLOCO 06 — QUALITY GATE FINAL ===="

mkdir -p \
  "$BASE/modules/quality" \
  "$BASE/state/quality" \
  "$BASE/logs"

cat > "$BASE/modules/quality/quality-gate.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

BASE="$CYBERLAB_HOME"
CURRENT="$BASE/state/current-operation.txt"

now() {
  date -Iseconds
}

audit_log() {
  OP="${1:-}"
  ACTION="$2"
  STATUS="$3"
  MESSAGE="$4"

  [ -n "$OP" ] && mkdir -p "$OP/audit"
  mkdir -p "$BASE/audit"

  LINE="$(now) | action=$ACTION | status=$STATUS | message=$MESSAGE"

  [ -n "$OP" ] && echo "$LINE" >> "$OP/audit/audit.log"
  echo "$LINE" >> "$BASE/audit/global-audit.log"
}

current_op() {
  cat "$CURRENT" 2>/dev/null || true
}

client_slug() {
  echo "$1" \
    | tr '[:upper:]' '[:lower:]' \
    | sed 's/[^a-z0-9]/-/g' \
    | sed 's/-\+/-/g' \
    | sed 's/^-//;s/-$//'
}

latest_delivery() {
  CLIENT="$1"
  SLUG="$(client_slug "$CLIENT")"
  cat "$BASE/clients/$SLUG/reports/latest-delivery.txt" 2>/dev/null || true
}

check_file() {
  FILE="$1"
  LABEL="$2"

  if [ -f "$FILE" ]; then
    echo "[OK] $LABEL"
    return 0
  else
    echo "[MISS] $LABEL -> $FILE"
    return 1
  fi
}

check_json() {
  FILE="$1"
  LABEL="$2"

  if [ ! -f "$FILE" ]; then
    echo "[MISS] $LABEL -> $FILE"
    return 1
  fi

  if jq empty "$FILE" >/dev/null 2>&1; then
    echo "[OK] JSON válido: $LABEL"
    return 0
  else
    echo "[BROKEN] JSON inválido: $LABEL -> $FILE"
    return 1
  fi
}

hash_file() {
  FILE="$1"

  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$FILE" | awk '{print $1}'
  else
    shasum -a 256 "$FILE" | awk '{print $1}'
  fi
}

quality_gate() {
  CLIENT="${1:-}"

  if [ -z "$CLIENT" ]; then
    echo "[ERRO] Uso: cyberlab quality gate \"Cliente\""
    exit 1
  fi

  DELIVERY="$(latest_delivery "$CLIENT")"

  if [ -z "$DELIVERY" ] || [ ! -d "$DELIVERY" ]; then
    echo "[ERRO] Delivery não encontrado para: $CLIENT"
    exit 1
  fi

  OP="$(current_op || true)"
  REPORT="$DELIVERY/quality-gate.txt"
  MANIFEST="$DELIVERY/quality-manifest.json"

  FAIL=0

  echo "==== CYBERLAB QUALITY GATE FINAL ====" | tee "$REPORT"
  echo "Cliente: $CLIENT" | tee -a "$REPORT"
  echo "Delivery: $DELIVERY" | tee -a "$REPORT"
  echo "Data: $(now)" | tee -a "$REPORT"
  echo | tee -a "$REPORT"

  echo "[1/7] Arquivos obrigatórios" | tee -a "$REPORT"

  REQUIRED_FILES=(
    "$DELIVERY/summary.txt|summary.txt"
    "$DELIVERY/manifest.json|manifest.json"
    "$DELIVERY/validation.txt|validation.txt"
    "$DELIVERY/json/findings-scored.json|findings-scored.json"
    "$DELIVERY/json/risk-summary.json|risk-summary.json"
    "$DELIVERY/json/analytics.json|analytics.json"
    "$DELIVERY/json/remediation-plan.json|remediation-plan.json"
  )

  for item in "${REQUIRED_FILES[@]}"; do
    FILE="${item%%|*}"
    LABEL="${item##*|}"
    check_file "$FILE" "$LABEL" | tee -a "$REPORT" || FAIL=1
  done

  echo | tee -a "$REPORT"
  echo "[2/7] JSON obrigatório" | tee -a "$REPORT"

  REQUIRED_JSON=(
    "$DELIVERY/manifest.json|manifest.json"
    "$DELIVERY/json/findings-scored.json|findings-scored.json"
    "$DELIVERY/json/risk-summary.json|risk-summary.json"
    "$DELIVERY/json/analytics.json|analytics.json"
    "$DELIVERY/json/remediation-plan.json|remediation-plan.json"
  )

  for item in "${REQUIRED_JSON[@]}"; do
    FILE="${item%%|*}"
    LABEL="${item##*|}"
    check_json "$FILE" "$LABEL" | tee -a "$REPORT" || FAIL=1
  done

  echo | tee -a "$REPORT"
  echo "[3/7] Verificando BROKEN/MISS críticos" | tee -a "$REPORT"

  if grep -R "\[BROKEN\]" "$DELIVERY" >/dev/null 2>&1; then
    echo "[FAIL] Encontrado BROKEN no delivery" | tee -a "$REPORT"
    FAIL=1
  else
    echo "[OK] Nenhum BROKEN encontrado" | tee -a "$REPORT"
  fi

  if grep -R "\[MISS\]" "$DELIVERY/validation.txt" >/dev/null 2>&1; then
    echo "[WARN] Existem MISS no validation.txt" | tee -a "$REPORT"
  else
    echo "[OK] validation.txt sem MISS" | tee -a "$REPORT"
  fi

  echo | tee -a "$REPORT"
  echo "[4/7] ZIP final" | tee -a "$REPORT"

  SLUG="$(client_slug "$CLIENT")"
  ZIP="$(ls -1 "$BASE/clients/$SLUG/reports"/cyberlab_"$SLUG"_*.zip 2>/dev/null | tail -n 1 || true)"

  if [ -n "$ZIP" ] && [ -f "$ZIP" ]; then
    echo "[OK] ZIP encontrado: $ZIP" | tee -a "$REPORT"
  else
    echo "[FAIL] ZIP não encontrado" | tee -a "$REPORT"
    FAIL=1
  fi

  echo | tee -a "$REPORT"
  echo "[5/7] Score operacional" | tee -a "$REPORT"

  SCORE="$(jq -r '.score // 0' "$DELIVERY/json/risk-summary.json" 2>/dev/null || echo 0)"
  LEVEL="$(jq -r '.level // "INDEFINIDO"' "$DELIVERY/json/risk-summary.json" 2>/dev/null || echo INDEFINIDO)"
  FINDINGS="$(jq -r '.findings_count // (.findings | length) // 0' "$DELIVERY/json/findings-scored.json" 2>/dev/null || echo 0)"

  echo "[OK] Score: $SCORE" | tee -a "$REPORT"
  echo "[OK] Nível: $LEVEL" | tee -a "$REPORT"
  echo "[OK] Findings: $FINDINGS" | tee -a "$REPORT"

  echo | tee -a "$REPORT"
  echo "[6/7] Hashes" | tee -a "$REPORT"

  HASH_SUMMARY=""
  HASH_RISK=""
  HASH_FINDINGS=""
  HASH_ZIP=""

  [ -f "$DELIVERY/summary.txt" ] && HASH_SUMMARY="$(hash_file "$DELIVERY/summary.txt")"
  [ -f "$DELIVERY/json/risk-summary.json" ] && HASH_RISK="$(hash_file "$DELIVERY/json/risk-summary.json")"
  [ -f "$DELIVERY/json/findings-scored.json" ] && HASH_FINDINGS="$(hash_file "$DELIVERY/json/findings-scored.json")"
  [ -n "$ZIP" ] && [ -f "$ZIP" ] && HASH_ZIP="$(hash_file "$ZIP")"

  echo "[OK] summary: $HASH_SUMMARY" | tee -a "$REPORT"
  echo "[OK] risk-summary: $HASH_RISK" | tee -a "$REPORT"
  echo "[OK] findings-scored: $HASH_FINDINGS" | tee -a "$REPORT"
  echo "[OK] zip: $HASH_ZIP" | tee -a "$REPORT"

  echo | tee -a "$REPORT"
  echo "[7/7] Manifesto de qualidade" | tee -a "$REPORT"

  STATUS="PASSED"
  if [ "$FAIL" -ne 0 ]; then
    STATUS="FAILED"
  fi

  cat > "$MANIFEST" <<JSON
{
  "client": "$CLIENT",
  "delivery": "$DELIVERY",
  "zip": "$ZIP",
  "status": "$STATUS",
  "score": "$SCORE",
  "level": "$LEVEL",
  "findings": "$FINDINGS",
  "hashes": {
    "summary": "$HASH_SUMMARY",
    "risk_summary": "$HASH_RISK",
    "findings_scored": "$HASH_FINDINGS",
    "zip": "$HASH_ZIP"
  },
  "generated_at": "$(now)"
}
JSON

  jq empty "$MANIFEST" >/dev/null

  echo "[OK] quality-manifest.json criado" | tee -a "$REPORT"

  if [ "$STATUS" = "FAILED" ]; then
    echo | tee -a "$REPORT"
    echo "==== QUALITY GATE FAILED ====" | tee -a "$REPORT"
    audit_log "$OP" "quality_gate" "FAILED" "$CLIENT"
    exit 1
  fi

  echo | tee -a "$REPORT"
  echo "==== QUALITY GATE PASSED ====" | tee -a "$REPORT"
  audit_log "$OP" "quality_gate" "OK" "$CLIENT"

  echo
  echo "[OK] Delivery aprovado para envio:"
  echo "$DELIVERY"
}

case "${1:-help}" in
  gate)
    shift
    quality_gate "$@"
    ;;
  *)
    echo "Uso:"
    echo "cyberlab quality gate \"Cliente\""
    ;;
esac
SCRIPT

chmod +x "$BASE/modules/quality/quality-gate.sh"

python3 <<'PY'
from pathlib import Path

p = Path.home() / "CyberLab/bin/cyberlab"
s = p.read_text()

block = '''quality)
    bash "$CYBERLAB_HOME/modules/quality/quality-gate.sh" "$@"
    ;;
'''

if "quality)" not in s:
    idx = s.rfind("*)")
    if idx != -1:
        s = s[:idx] + block + "\n" + s[idx:]
    else:
        s += "\n" + block

p.write_text(s)
PY

chmod +x "$BASE/bin/cyberlab"

echo
echo "[OK] Bloco 06 Quality Gate Final instalado"
echo
echo "Validação:"
echo "source "${CYBERLAB_HOME:-$HOME/CyberLab}/core/bootstrap.sh""
echo "hash -r"
echo "cyberlab quality gate \"CyberShield\""
