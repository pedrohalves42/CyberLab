#!/bin/bash

INPUT="$1"

TMP=$(mktemp)

jq '
if .findings then

.findings |= map(

. + {

confidence:

(

if .source == "nuclei"
then 95

elif .source == "whatweb"
then 90

elif .source == "manual"
then 99

elif .severity == "critical"
then 85

elif .severity == "high"
then 75

elif .severity == "medium"
then 60

else 45 end

)

}

)

else .
end
' "$INPUT" > "$TMP"

mv "$TMP" "$INPUT"

echo "[OK] Confidence aplicado"
