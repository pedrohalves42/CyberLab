#!/bin/bash

INPUT="$1"

TMP=$(mktemp)

jq '
if .findings then

.findings |= map(

if (.title|test("missing header";"i"))
then .severity="low"

elif (.title|test("wordpress version";"i"))
then .severity="medium"

elif (.title|test("exposed admin";"i"))
then .severity="high"

else .

end

)

else .
end
' "$INPUT" > "$TMP"

mv "$TMP" "$INPUT"

echo "[OK] Severidade refinada"
