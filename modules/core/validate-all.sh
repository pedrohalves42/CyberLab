#!/bin/bash
set -u

source "${CYBERLAB_HOME:-$HOME/CyberLab}/core/env.sh"

echo "============================================================"
echo " CYBERLAB VALIDATE ALL — STRUCTURAL QUALITY GATE"
echo "============================================================"

FAIL=0
WARN=0

ok() {
  echo "[OK] $*"
}

warn() {
  echo "[WARN] $*"
  WARN=$((WARN+1))
}

fail() {
  echo "[FAIL] $*"
  FAIL=$((FAIL+1))
}

check_file() {
  if [ -f "$1" ]; then
    ok "$1"
  else
    fail "Arquivo ausente: $1"
  fi
}

check_dir() {
  if [ -d "$1" ]; then
    ok "$1"
  else
    fail "Diretório ausente: $1"
  fi
}

echo ""
echo "=== [1] Diretórios essenciais ==="
for d in \
  "$CYBERLAB_HOME" \
  "$CYBERLAB_BIN" \
  "$CYBERLAB_CORE" \
  "$CYBERLAB_MODULES" \
  "$CYBERLAB_CONFIG"; do
  check_dir "$d"
done

echo ""
echo "=== [2] Arquivos essenciais ==="
check_file "$CYBERLAB_BIN/cyberlab"
check_file "$CYBERLAB_CORE/env.sh"
check_file "$CYBERLAB_CORE/bootstrap.sh"
check_file "$CYBERLAB_CORE/init.sh"
check_file "$CYBERLAB_MODULES/core/validate-all.sh"
check_file "$CYBERLAB_MODULES/core/sync-all.sh"

echo ""
echo "=== [3] Sintaxe do dispatcher ==="
if bash -n "$CYBERLAB_BIN/cyberlab" 2>/dev/null; then
  ok "bin/cyberlab sintaticamente válido"
else
  fail "bin/cyberlab com erro de sintaxe"
fi

echo ""
echo "=== [4] Sintaxe dos scripts shell ativos ==="
while IFS= read -r -d '' shfile; do
  if bash -n "$shfile" 2>/dev/null; then
    ok "Shell válido: ${shfile#$CYBERLAB_HOME/}"
  else
    fail "Shell inválido: ${shfile#$CYBERLAB_HOME/}"
  fi
done < <(
  find "$CYBERLAB_HOME" \
    \( \
      -path "$CYBERLAB_HOME/.venv" -o \
      -path "$CYBERLAB_HOME/results" -o \
      -path "$CYBERLAB_HOME/clients" -o \
      -path "$CYBERLAB_HOME/quarantine" -o \
      -path "$CYBERLAB_HOME/archive" -o \
      -path "$CYBERLAB_HOME/tools/setoolkit" -o \
      -path "$CYBERLAB_HOME/tools/wordlists/SecLists" \
    \) -prune \
    -o \
    -type f -name "*.sh" -print0 2>/dev/null
)

echo ""
echo "=== [5] Compilação Python ==="
if python3 -m compileall -q \
  "$CYBERLAB_CORE" \
  "$CYBERLAB_MODULES" \
  "$CYBERLAB_WEB" \
  "$CYBERLAB_HOME/tools" \
  2>/dev/null; then
  ok "Python compilável"
else
  fail "Falha ao compilar arquivos Python"
fi

echo ""
echo "=== [6] Arquivos JSON de configuração/código ==="
JSON_COUNT=0

while IFS= read -r -d '' jsonfile; do
  JSON_COUNT=$((JSON_COUNT+1))
  if command -v jq >/dev/null 2>&1; then
    if jq empty "$jsonfile" >/dev/null 2>&1; then
      ok "JSON válido: ${jsonfile#$CYBERLAB_HOME/}"
    else
      fail "JSON inválido: ${jsonfile#$CYBERLAB_HOME/}"
    fi
  else
    warn "jq não encontrado; JSON não validado: ${jsonfile#$CYBERLAB_HOME/}"
  fi
done < <(
  find "$CYBERLAB_HOME" \
    \( \
      -path "$CYBERLAB_HOME/.venv" -o \
      -path "$CYBERLAB_HOME/results" -o \
      -path "$CYBERLAB_HOME/clients" -o \
      -path "$CYBERLAB_HOME/quarantine" -o \
      -path "$CYBERLAB_HOME/archive" -o \
      -path "$CYBERLAB_HOME/tools/setoolkit" -o \
      -path "$CYBERLAB_HOME/tools/wordlists/SecLists" -o \
      -path "$CYBERLAB_HOME/state" -o \
      -path "$CYBERLAB_HOME/queue/pending" -o \
      -path "$CYBERLAB_HOME/queue/running" -o \
      -path "$CYBERLAB_HOME/queue/completed" -o \
      -path "$CYBERLAB_HOME/queue/failed" \
    \) -prune \
    -o \
    -type f -name "*.json" -print0 2>/dev/null
)

if [ "$JSON_COUNT" -eq 0 ]; then
  warn "Nenhum JSON estrutural encontrado para validar"
fi

echo ""
echo "=== [7] Ferramentas essenciais e opcionais ==="

for tool in bash python3 git curl jq; do
  if command -v "$tool" >/dev/null 2>&1; then
    ok "Ferramenta essencial disponível: $tool"
  else
    fail "Ferramenta essencial ausente: $tool"
  fi
done

for tool in nmap nuclei httpx subfinder dnsx katana naabu docker; do
  if command -v "$tool" >/dev/null 2>&1; then
    ok "Ferramenta opcional disponível: $tool"
  else
    warn "Ferramenta opcional ausente: $tool"
  fi
done

echo ""
echo "=== [8] Mapeamento básico de comandos do dispatcher ==="

for cmd in \
  init help menu status health doctor validate-all sync sync-all \
  audit recon deliver maintain lab \
  block16 client-audit-final-approved \
  client-final-delivery block17-final block17; do

  if grep -Eq "^[[:space:]]*([^#[:space:]]+\\|)*${cmd}(\\|[^)]*)?\\)" "$CYBERLAB_BIN/cyberlab"; then
    ok "Comando mapeado: cyberlab $cmd"
  else
    warn "Comando não localizado diretamente no dispatcher: cyberlab $cmd"
  fi
done

echo ""
echo "============================================================"
echo " RESUMO DO VALIDATE ALL"
echo "============================================================"
echo "Falhas: $FAIL"
echo "Avisos: $WARN"

if [ "$FAIL" -gt 0 ]; then
  echo "[FAIL] Validação estrutural reprovada."
  exit 1
fi

echo "[OK] Validação estrutural aprovada."
exit 0
