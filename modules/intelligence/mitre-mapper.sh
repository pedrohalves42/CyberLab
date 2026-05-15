#!/bin/bash

FILE=~/CyberLab/state/intelligence/findings-scored.json

TMP=$(mktemp)

jq '
map(
    .mitre = (
        if (.title|ascii_downcase|test("xss")) then "T1059"
        elif (.title|ascii_downcase|test("sql")) then "T1190"
        elif (.title|ascii_downcase|test("exposed")) then "T1595"
        elif (.title|ascii_downcase|test("admin")) then "T1078"
        else "T1592"
        end
    )
)
' "$FILE" > "$TMP"

mv "$TMP" "$FILE"

echo "[OK] MITRE mapping aplicado"
