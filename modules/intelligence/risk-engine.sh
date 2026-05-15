#!/bin/bash

INPUT="$1"

OUTPUT="$2"

CRITICAL=$(jq '[.findings[] | select(.severity=="critical")] | length' "$INPUT")
HIGH=$(jq '[.findings[] | select(.severity=="high")] | length' "$INPUT")
MEDIUM=$(jq '[.findings[] | select(.severity=="medium")] | length' "$INPUT")
LOW=$(jq '[.findings[] | select(.severity=="low")] | length' "$INPUT")

SCORE=$((CRITICAL*35 + HIGH*20 + MEDIUM*8 + LOW*2))

if [ "$SCORE" -gt 100 ]; then
  SCORE=100
fi

LEVEL="LOW"

if [ "$SCORE" -ge 80 ]; then
  LEVEL="CRITICAL"
elif [ "$SCORE" -ge 60 ]; then
  LEVEL="HIGH"
elif [ "$SCORE" -ge 30 ]; then
  LEVEL="MEDIUM"
fi

cat > "$OUTPUT" <<JSON
{
  "score": $SCORE,
  "risk": "$LEVEL",
  "critical": $CRITICAL,
  "high": $HIGH,
  "medium": $MEDIUM,
  "low": $LOW
}
JSON

echo "[OK] Risk score calculado"
