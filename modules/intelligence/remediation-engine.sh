#!/bin/bash

FILE=~/CyberLab/state/intelligence/findings-scored.json

TMP=$(mktemp)

jq '
map(
    .recommendation = (
        if (.title|ascii_downcase|test("hsts")) then
            "Implementar header Strict-Transport-Security"
        elif (.title|ascii_downcase|test("csp")) then
            "Adicionar Content-Security-Policy"
        elif (.title|ascii_downcase|test("x-powered-by")) then
            "Ocultar tecnologia exposta"
        elif (.title|ascii_downcase|test("directory")) then
            "Desabilitar indexação de diretórios"
        elif (.title|ascii_downcase|test("wordpress")) then
            "Atualizar plugins e hardening WordPress"
        else
            "Aplicar hardening de segurança"
        end
    )
)
' "$FILE" > "$TMP"

mv "$TMP" "$FILE"

echo "[OK] Recomendações aplicadas"
