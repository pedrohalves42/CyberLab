#!/bin/bash

INPUT="$1"

TMP=$(mktemp)

jq '
if .findings then
.findings |= unique_by(
.title,
.severity,
.category,
.asset,
.source
)
else .
end
' "$INPUT" > "$TMP" 2>/dev/null

if [ $? -eq 0 ]; then
  mv "$TMP" "$INPUT"
  echo "[OK] Deduplicação concluída"
else
  rm -f "$TMP"
  echo "[ERRO] Deduplicação falhou"
fi
