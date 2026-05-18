#!/bin/bash
set -e

BASE="$CYBERLAB_HOME"

echo "==== REBUILD CYBERLAB CORE CLEAN ===="

mkdir -p "$BASE/core" "$BASE/data/policies" "$BASE/logs" "$BASE/state/intelligence"

# Backup
for f in \
"$BASE/core/delivery.sh" \
"$BASE/install-operacao-basica.sh" \
"$BASE/install-bloco17-intelligence.sh" \
"$BASE/install-bloco18-finalize.sh" \
"$BASE/data/policies/risk-policy.json"
do
  [ -f "$f" ] && cp "$f" "$f.bak.$(date +%Y%m%d_%H%M%S)"
done

# 1) risk-policy.json limpo
cat > "$BASE/data/policies/risk-policy.json" <<'JSON'
{
  "policy_name": "CyberLab Risk Policy",
  "version": "clean-unified",
  "official_score_source": "risk-summary.json",
  "official_findings_source": "findings-scored.json",
  "official_analytics_source": "analytics.json",
  "severity_weights": {
    "critical": 35,
    "high": 20,
    "medium": 8,
    "low": 2,
    "info": 0
  },
  "levels": {
    "low": 0,
    "medium": 30,
    "high": 60,
    "critical": 80
  }
}
JSON

# 2) delivery.sh limpo
cat > "$BASE/core/delivery.sh" <<'EOS'
#!/bin/bash
set -u

source "${CYBERLAB_HOME:-$HOME/CyberLab}/core/bootstrap.sh"

CMD="${1:-generate}"
CLIENT="${2:-}"

slugify() {
  echo "$1" | tr '[:upper:]' '[:lower:]' \
  | sed 's/[^a-z0-9]/-/g' \
  | sed 's/-\+/-/g' \
  | sed 's/^-//;s/-$//'
}

latest_delivery() {
  CLIENT="$1"
  SLUG="$(slugify "$CLIENT")"
  DIR="$CYBERLAB_HOME/clients/$SLUG/reports/delivery"
  find "$DIR" -maxdepth 1 -type d 2>/dev/null | sort | tail -n 1
}

generate_delivery() {
  if [ -z "$CLIENT" ]; then
    echo "[ERRO] Informe o cliente"
    echo "Uso: cyberlab delivery generate \"Cliente\""
    exit 1
  fi

  CLIENT_SLUG="$(slugify "$CLIENT")"
  DATE_ID="$(date +%Y-%m-%d_%H-%M-%S)"
  CLIENT_DIR="$CYBERLAB_HOME/clients/$CLIENT_SLUG"
  OUT="$CLIENT_DIR/reports/delivery/$DATE_ID"
  ZIP="$CLIENT_DIR/reports/cyberlab_${CLIENT_SLUG}_${DATE_ID}.zip"
  VALIDATION="$OUT/validation.txt"

  mkdir -p "$OUT/json" "$OUT/reports" "$OUT/evidence" "$CLIENT_DIR/reports"

  echo "[+] Montando pacote de entrega"
  echo "[+] Cliente: $CLIENT"
  echo "[+] Saída: $OUT"

  cyberlab intelligence >/dev/null 2>&1 || true

  # JSON oficiais únicos
  for f in findings-scored risk-summary analytics remediation-plan timeline assets; do
    SRC="$CYBERLAB_HOME/state/intelligence/$f.json"
    [ -f "$SRC" ] && cp "$SRC" "$OUT/json/$f.json"
  done

  # Evidências do último web scan
  LATEST_WEB="$(cat "$CYBERLAB_HOME/results/web/latest.txt" 2>/dev/null || true)"
  if [ -n "$LATEST_WEB" ] && [ -d "$LATEST_WEB" ]; then
    cp -r "$LATEST_WEB" "$OUT/evidence/web" 2>/dev/null || true
    cp "$LATEST_WEB/report/report.pdf" "$OUT/reports/report.pdf" 2>/dev/null || true
    cp "$LATEST_WEB/report/report.html" "$OUT/reports/report.html" 2>/dev/null || true
    cp "$LATEST_WEB/report/report.md" "$OUT/reports/technical-report.md" 2>/dev/null || true
  fi

  cat > "$OUT/manifest.json" <<JSON
{
  "client": "$CLIENT",
  "client_slug": "$CLIENT_SLUG",
  "generated_at": "$(date -Iseconds)",
  "package": "$ZIP",
  "engine": "CyberLab Unified Clean"
}
JSON

  {
    echo "==== CYBERLAB DELIVERY VALIDATION ===="
    echo "Cliente: $CLIENT"
    echo "Saída: $OUT"
    echo
    echo "[JSON]"
    find "$OUT/json" -name "*.json" | while read f; do
      jq empty "$f" >/dev/null 2>&1 && echo "[OK] $f" || echo "[BROKEN] $f"
    done
    echo
    echo "[FILES]"
    find "$OUT" -type f | sort
  } > "$VALIDATION"

  (
    cd "$OUT/.." || exit 1
    zip -r "$ZIP" "$DATE_ID" >/dev/null
  )

  echo "$OUT" > "$CLIENT_DIR/reports/latest-delivery.txt"

  echo
  echo "[OK] Delivery gerado:"
  echo "$OUT"
  echo
  echo "[OK] ZIP:"
  echo "$ZIP"
  echo
  echo "[OK] Validação:"
  echo "$VALIDATION"
}

case "$CMD" in
  generate)
    generate_delivery
    ;;
  latest)
    latest_delivery "$CLIENT"
    ;;
  *)
    echo "Uso:"
    echo "cyberlab delivery generate \"Cliente\""
    echo "cyberlab delivery latest \"Cliente\""
    ;;
esac
EOS

# 3) install-operacao-basica.sh limpo
cat > "$BASE/install-operacao-basica.sh" <<'EOS'
#!/bin/bash
set -e

BASE="$CYBERLAB_HOME"

echo "==== CYBERLAB OPERAÇÃO BÁSICA CLEAN ===="

mkdir -p "$BASE"/{bin,core,clients,config,data,logs,modules,reports,results,state,tmp,ui,web}
mkdir -p "$BASE/state/intelligence"
mkdir -p "$BASE/results/web" "$BASE/results/threat" "$BASE/results/detection" "$BASE/results/correlation" "$BASE/results/redteam"
mkdir -p "$BASE/data/policies"

chmod -R u+rwX "$BASE"

echo "[OK] Estrutura básica validada"
echo "[OK] Sem arquivos versionados legados"
EOS

# 4) install-bloco17-intelligence.sh limpo
cat > "$BASE/install-bloco17-intelligence.sh" <<'EOS'
#!/bin/bash
set -e

BASE="$CYBERLAB_HOME"

echo "==== CYBERLAB BLOCO 17 INTELLIGENCE CLEAN ===="

mkdir -p "$BASE/modules/intelligence" "$BASE/state/intelligence" "$BASE/logs/intelligence"

cat > "$BASE/modules/intelligence/repair-final-json.sh" <<'SCRIPT'
#!/bin/bash
set -u

STATE="$CYBERLAB_HOME/state/intelligence"
mkdir -p "$STATE"

F="$STATE/findings-scored.json"
R="$STATE/risk-summary.json"
A="$STATE/analytics.json"

if ! jq empty "$F" >/dev/null 2>&1; then
cat > "$F" <<JSON
{
  "generated_at": "$(date -Iseconds)",
  "engine": "CyberLab Intelligence Clean",
  "count": 0,
  "findings": []
}
JSON
fi

TOTAL=$(jq '.findings | length // 0' "$F" 2>/dev/null || echo 0)
CRITICAL=$(jq '[.findings[]? | select((.severity|tostring|ascii_upcase)=="CRITICAL" or (.severity|tostring|ascii_upcase)=="CRÍTICO")] | length' "$F" 2>/dev/null || echo 0)
HIGH=$(jq '[.findings[]? | select((.severity|tostring|ascii_upcase)=="HIGH" or (.severity|tostring|ascii_upcase)=="ALTO")] | length' "$F" 2>/dev/null || echo 0)
MEDIUM=$(jq '[.findings[]? | select((.severity|tostring|ascii_upcase)=="MEDIUM" or (.severity|tostring|ascii_upcase)=="MÉDIO" or (.severity|tostring|ascii_upcase)=="MEDIO")] | length' "$F" 2>/dev/null || echo 0)
LOW=$(jq '[.findings[]? | select((.severity|tostring|ascii_upcase)=="LOW" or (.severity|tostring|ascii_upcase)=="BAIXO")] | length' "$F" 2>/dev/null || echo 0)

SCORE=$((CRITICAL*35 + HIGH*20 + MEDIUM*8 + LOW*2))
[ "$SCORE" -gt 100 ] && SCORE=100

LEVEL="BAIXO"
[ "$SCORE" -ge 30 ] && LEVEL="MÉDIO"
[ "$SCORE" -ge 60 ] && LEVEL="ALTO"
[ "$SCORE" -ge 80 ] && LEVEL="CRÍTICO"

jq -n \
  --arg generated_at "$(date -Iseconds)" \
  --arg engine "CyberLab Intelligence Clean" \
  --arg level "$LEVEL" \
  --argjson score "$SCORE" \
  --argjson findings_count "$TOTAL" \
  --argjson critical "$CRITICAL" \
  --argjson high "$HIGH" \
  --argjson medium "$MEDIUM" \
  --argjson low "$LOW" \
  '{generated_at:$generated_at,engine:$engine,score:$score,level:$level,findings_count:$findings_count,critical:$critical,high:$high,medium:$medium,low:$low}' > "$R"

jq -n \
  --arg generated_at "$(date -Iseconds)" \
  --arg level "$LEVEL" \
  --argjson total_findings "$TOTAL" \
  --argjson critical "$CRITICAL" \
  --argjson high "$HIGH" \
  --argjson medium "$MEDIUM" \
  --argjson low "$LOW" \
  --argjson score "$SCORE" \
  '{generated_at:$generated_at,total_findings:$total_findings,critical:$critical,high:$high,medium:$medium,low:$low,score:$score,level:$level}' > "$A"

echo "[OK] JSON intelligence reparado"
SCRIPT

chmod +x "$BASE/modules/intelligence/repair-final-json.sh"

echo "[OK] Bloco 17 Intelligence Clean instalado"
EOS

# 5) install-bloco18-finalize.sh limpo
cat > "$BASE/install-bloco18-finalize.sh" <<'EOS'
#!/bin/bash
set -e

BASE="$CYBERLAB_HOME"

echo "==== CYBERLAB BLOCO 18 FINALIZE CLEAN ===="

mkdir -p "$BASE/modules/intelligence" "$BASE/state/intelligence"

cat > "$BASE/modules/intelligence/run-intelligence.sh" <<'SCRIPT'
#!/bin/bash
set -u

BASE="$CYBERLAB_HOME"
STATE="$BASE/state/intelligence"
mkdir -p "$STATE"

echo "==== CYBERLAB ENTERPRISE INTELLIGENCE CLEAN ===="

INPUT="$STATE/findings-scored.json"

if [ ! -f "$INPUT" ]; then
cat > "$INPUT" <<JSON
{
  "generated_at": "$(date -Iseconds)",
  "engine": "CyberLab Intelligence Clean",
  "count": 0,
  "findings": []
}
JSON
fi

TMP="$(mktemp)"

jq '
def norm_sev:
  (.severity // .risk // .level // "INFO" | tostring | ascii_upcase);

def pscore:
  if norm_sev == "CRITICAL" or norm_sev == "CRÍTICO" then 100
  elif norm_sev == "HIGH" or norm_sev == "ALTO" then 80
  elif norm_sev == "MEDIUM" or norm_sev == "MÉDIO" or norm_sev == "MEDIO" then 55
  elif norm_sev == "LOW" or norm_sev == "BAIXO" then 25
  else 5 end;

(
  if type == "object" and (.findings|type) == "array" then .findings
  elif type == "array" then .
  else []
  end
)
| map(select(type=="object"))
| map(
  .severity_original = (.severity // .risk // .level // "INFO")
  | .severity = norm_sev
  | .confidence = (
      if pscore >= 100 then 95
      elif pscore >= 80 then 85
      elif pscore >= 55 then 70
      elif pscore >= 25 then 50
      else 35 end
    )
  | .priority_score = pscore
  | .business_impact = (
      if pscore >= 100 then "Risco crítico que exige validação imediata."
      elif pscore >= 80 then "Risco alto que deve ser priorizado."
      elif pscore >= 55 then "Exposição moderada com recomendação de correção preventiva."
      elif pscore >= 25 then "Baixo impacto, recomendado para hardening."
      else "Informativo técnico." end
    )
  | .recommendation = "Validar tecnicamente e aplicar hardening proporcional ao risco."
)
| unique_by((.title // .item // .description // ""), (.asset // .host // .target // ""), .severity)
| sort_by(-.priority_score)
| {
  generated_at: now,
  engine: "CyberLab Enterprise Intelligence Clean",
  count: length,
  findings: .
}
' "$INPUT" > "$TMP"

if jq empty "$TMP" >/dev/null 2>&1; then
  mv "$TMP" "$INPUT"
else
  rm -f "$TMP"
  echo "[ERRO] Intelligence falhou"
  exit 1
fi

bash "$BASE/modules/intelligence/repair-final-json.sh"

echo "[OK] Intelligence Clean concluído"
SCRIPT

chmod +x "$BASE/modules/intelligence/run-intelligence.sh"

cat > "$BASE/modules/intelligence/intelligence-pipeline.sh" <<'SCRIPT'
#!/bin/bash
bash "$CYBERLAB_HOME/modules/intelligence/run-intelligence.sh"
SCRIPT

chmod +x "$BASE/modules/intelligence/intelligence-pipeline.sh"

echo "[OK] Bloco 18 Finalize Clean instalado"
EOS

chmod +x \
"$BASE/core/delivery.sh" \
"$BASE/install-operacao-basica.sh" \
"$BASE/install-bloco17-intelligence.sh" \
"$BASE/install-bloco18-finalize.sh"

# Remover legados físicos
find "$BASE" -name "*-v17.json" -delete
find "$BASE" -name "*-v18.json" -delete
find "$BASE" -name "*-v20.json" -delete

echo "[OK] Rebuild finalizado"
echo
echo "Agora rode:"
echo "bash ~/CyberLab/install-operacao-basica.sh"
echo "bash ~/CyberLab/install-bloco17-intelligence.sh"
echo "bash ~/CyberLab/install-bloco18-finalize.sh"
echo "source "${CYBERLAB_HOME:-$HOME/CyberLab}/core/bootstrap.sh""
echo "hash -r"
echo "cyberlab intelligence"
echo "cyberlab delivery generate \"Loja Maromba\""
