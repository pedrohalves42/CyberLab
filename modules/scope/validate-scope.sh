#!/bin/bash
set -u

source "${CYBERLAB_HOME:-$HOME/CyberLab}/core/env.sh"

SCOPE_FILE="${1:-$CYBERLAB_CONFIG/scope.txt}"

echo "============================================================"
echo " CYBERLAB — VALIDATE SCOPE"
echo "============================================================"
echo "Arquivo: $SCOPE_FILE"
echo ""

if [ ! -f "$SCOPE_FILE" ]; then
  echo "[FAIL] Arquivo de escopo não encontrado."
  exit 1
fi

FAIL=0
VALID=0

line_no=0

while IFS= read -r raw || [ -n "$raw" ]; do
  line_no=$((line_no+1))

  line="$(echo "$raw" | sed 's/#.*$//' | xargs)"

  [ -z "$line" ] && continue

  if echo "$line" | grep -Eq '^https?://'; then
    echo "[FAIL] Linha $line_no: protocolo não permitido → $line"
    FAIL=$((FAIL+1))
    continue
  fi

  if echo "$line" | grep -Eq '/$'; then
    echo "[FAIL] Linha $line_no: barra final não permitida → $line"
    FAIL=$((FAIL+1))
    continue
  fi

  if echo "$line" | grep -q '\*'; then
    echo "[FAIL] Linha $line_no: wildcard não suportado → $line"
    FAIL=$((FAIL+1))
    continue
  fi

  if echo "$line" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$'; then
    python3 - "$line" <<'PY' >/dev/null 2>&1
import ipaddress
import sys
ipaddress.ip_network(sys.argv[1], strict=False)
PY

    if [ "$?" -eq 0 ]; then
      echo "[OK] Linha $line_no: rede CIDR válida → $line"
      VALID=$((VALID+1))
    else
      echo "[FAIL] Linha $line_no: CIDR inválido → $line"
      FAIL=$((FAIL+1))
    fi
    continue
  fi

  if echo "$line" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    python3 - "$line" <<'PY' >/dev/null 2>&1
import ipaddress
import sys
ipaddress.ip_address(sys.argv[1])
PY

    if [ "$?" -eq 0 ]; then
      echo "[OK] Linha $line_no: IP válido → $line"
      VALID=$((VALID+1))
    else
      echo "[FAIL] Linha $line_no: IP inválido → $line"
      FAIL=$((FAIL+1))
    fi
    continue
  fi

  if echo "$line" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$|^localhost$'; then
    echo "[OK] Linha $line_no: domínio válido → $line"
    VALID=$((VALID+1))
    continue
  fi

  echo "[FAIL] Linha $line_no: entrada inválida → $line"
  FAIL=$((FAIL+1))

done < "$SCOPE_FILE"

echo ""
echo "============================================================"
echo " RESUMO DO ESCOPO"
echo "============================================================"
echo "Entradas válidas: $VALID"
echo "Falhas: $FAIL"

if [ "$FAIL" -gt 0 ]; then
  echo "[FAIL] Escopo contém entradas inválidas."
  exit 1
fi

echo "[OK] Escopo válido."
exit 0
