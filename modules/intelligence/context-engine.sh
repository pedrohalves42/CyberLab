#!/bin/bash

INPUT="$1"

TMP=$(mktemp)

jq '
if .findings then

.findings |= map(

. + {

business_impact:

(

if .severity == "critical"
then "Possível comprometimento severo"

elif .severity == "high"
then "Risco elevado à operação"

elif .severity == "medium"
then "Necessita mitigação preventiva"

else "Baixo impacto operacional"

end

)

}

)

else .
end
' "$INPUT" > "$TMP"

mv "$TMP" "$INPUT"

echo "[OK] Contexto aplicado"
