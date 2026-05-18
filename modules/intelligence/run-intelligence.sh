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
