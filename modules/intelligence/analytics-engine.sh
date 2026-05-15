#!/bin/bash

INPUT=~/CyberLab/state/intelligence/findings-scored.json
OUT=~/CyberLab/state/intelligence/analytics.json

TOTAL=$(jq length "$INPUT")

HIGH=$(jq '[.[] | select(.severity=="HIGH")] | length' "$INPUT")
MEDIUM=$(jq '[.[] | select(.severity=="MEDIUM")] | length' "$INPUT")
LOW=$(jq '[.[] | select(.severity=="LOW")] | length' "$INPUT")

cat > "$OUT" <<EOF
{
  "generated_at":"$(date)",
  "total_findings":$TOTAL,
  "high":$HIGH,
  "medium":$MEDIUM,
  "low":$LOW
}
EOF

echo "[OK] Analytics criado"
