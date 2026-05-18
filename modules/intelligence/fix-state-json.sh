#!/bin/bash
set -u

STATE="$CYBERLAB_HOME/state/intelligence"
FINDINGS="$STATE/findings-scored.json"

mkdir -p "$STATE"

if ! jq empty "$FINDINGS" >/dev/null 2>&1; then
  echo "[ERRO] findings-scored.json inválido"
  exit 1
fi

TOTAL=$(jq '.findings | length' "$FINDINGS")
CRITICAL=$(jq '[.findings[] | select(.severity=="CRITICAL" or .severity=="CRÍTICO")] | length' "$FINDINGS")
HIGH=$(jq '[.findings[] | select(.severity=="HIGH" or .severity=="ALTO")] | length' "$FINDINGS")
MEDIUM=$(jq '[.findings[] | select(.severity=="MEDIUM" or .severity=="MÉDIO" or .severity=="MEDIO")] | length' "$FINDINGS")
LOW=$(jq '[.findings[] | select(.severity=="LOW" or .severity=="BAIXO")] | length' "$FINDINGS")

SCORE=$((CRITICAL*35 + HIGH*20 + MEDIUM*8 + LOW*2))
[ "$SCORE" -gt 100 ] && SCORE=100

LEVEL="BAIXO"
[ "$SCORE" -ge 30 ] && LEVEL="MÉDIO"
[ "$SCORE" -ge 60 ] && LEVEL="ALTO"
[ "$SCORE" -ge 80 ] && LEVEL="CRÍTICO"

jq -n \
  --arg generated_at "$(date -Iseconds)" \
  --arg engine "CyberLab Enterprise Intelligence v20 FIX" \
  --arg level "$LEVEL" \
  --argjson score "$SCORE" \
  --argjson findings_count "$TOTAL" \
  --argjson critical "$CRITICAL" \
  --argjson high "$HIGH" \
  --argjson medium "$MEDIUM" \
  --argjson low "$LOW" \
  '{
    generated_at: $generated_at,
    engine: $engine,
    score: $score,
    level: $level,
    findings_count: $findings_count,
    critical: $critical,
    high: $high,
    medium: $medium,
    low: $low
  }' > "$STATE/risk-summary.json"

jq -n \
  --arg generated_at "$(date -Iseconds)" \
  --arg level "$LEVEL" \
  --argjson total_findings "$TOTAL" \
  --argjson critical "$CRITICAL" \
  --argjson high "$HIGH" \
  --argjson medium "$MEDIUM" \
  --argjson low "$LOW" \
  --argjson score "$SCORE" \
  '{
    generated_at: $generated_at,
    total_findings: $total_findings,
    critical: $critical,
    high: $high,
    medium: $medium,
    low: $low,
    score: $score,
    level: $level
  }' > "$STATE/analytics.json"

echo "[OK] risk-summary.json recriado"
echo "[OK] analytics.json recriado"
echo "[OK] Score: $SCORE | Nível: $LEVEL | Findings: $TOTAL"
