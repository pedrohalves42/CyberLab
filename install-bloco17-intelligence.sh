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
