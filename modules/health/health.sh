#!/bin/bash
set -u

source "${CYBERLAB_HOME:-$HOME/CyberLab}/core/bootstrap.sh"

FAIL=0
WARN=0

ok() {
  echo "[OK] $1"
}

warn() {
  echo "[WARN] $1"
  WARN=$((WARN + 1))
}

fail() {
  echo "[FAIL] $1"
  FAIL=$((FAIL + 1))
}

check_file_health() {
  local file="$1"
  local label="$2"

  if [ -f "$file" ]; then
    ok "$label presente: $file"
  else
    fail "$label ausente: $file"
  fi
}

check_dir_health() {
  local dir="$1"
  local label="$2"

  if [ -d "$dir" ]; then
    ok "$label presente: $dir"
  else
    fail "$label ausente: $dir"
  fi
}

check_command_health() {
  local cmd="$1"

  if command -v "$cmd" >/dev/null 2>&1; then
    ok "Ferramenta disponível: $cmd"
  else
    warn "Ferramenta ausente: $cmd"
  fi
}

echo "============================================================"
echo " CYBERLAB HEALTH — SAÚDE OPERACIONAL"
echo "============================================================"
echo "Home:     $CYBERLAB_HOME"
echo "Data:     $(date '+%Y-%m-%d %H:%M:%S %z')"
echo "Usuário:  ${USER:-desconhecido}"
echo "============================================================"

echo ""
echo "=== [1] Estrutura essencial ==="

check_dir_health "$CYBERLAB_HOME" "Raiz do CyberLab"
check_dir_health "$CYBERLAB_BIN" "Diretório bin"
check_dir_health "$CYBERLAB_CORE" "Diretório core"
check_dir_health "$CYBERLAB_MODULES" "Diretório modules"
check_dir_health "$CYBERLAB_CONFIG" "Diretório config"
check_dir_health "$CYBERLAB_RESULTS" "Diretório results"
check_dir_health "$CYBERLAB_STATE" "Diretório state"

echo ""
echo "=== [2] Arquivos críticos ==="

check_file_health "$CYBERLAB_BIN/cyberlab" "Dispatcher"
check_file_health "$CYBERLAB_CORE/env.sh" "Env"
check_file_health "$CYBERLAB_CORE/bootstrap.sh" "Bootstrap"
check_file_health "$CYBERLAB_MODULES/core/validate-all.sh" "Validate-all"
check_file_health "$CYBERLAB_MODULES/core/sync-all.sh" "Sync-all"
check_file_health "$CYBERLAB_MODULES/health/health.sh" "Health"

echo ""
echo "=== [3] Estado operacional ==="

if [ -f "$CYBERLAB_STATE/latest.json" ]; then
  if command -v jq >/dev/null 2>&1; then
    if jq empty "$CYBERLAB_STATE/latest.json" >/dev/null 2>&1; then
      ok "state/latest.json presente e válido"
    else
      warn "state/latest.json existe, mas JSON parece inválido"
    fi
  else
    warn "jq ausente; não foi possível validar state/latest.json"
  fi
else
  warn "state/latest.json ainda não foi gerado"
fi

if [ -f "$CYBERLAB_CONFIG/scope.txt" ]; then
  if [ -s "$CYBERLAB_CONFIG/scope.txt" ]; then
    ok "Escopo local presente e não vazio"
  else
    warn "Escopo local existe, mas está vazio"
  fi
else
  warn "Escopo local config/scope.txt ausente"
fi

echo ""
echo "=== [4] Ferramentas-base ==="

for tool in bash python3 jq curl git; do
  check_command_health "$tool"
done

echo ""
echo "=== [5] Módulos críticos do fluxo atual ==="

check_file_health "$CYBERLAB_MODULES/web/web-scan.sh" "Web Scan"
check_file_health "$CYBERLAB_MODULES/active/active.sh" "Active Mode"
check_file_health "$CYBERLAB_MODULES/layer6/block_6a_surface_expansion.sh" "Camada 6A"
check_file_health "$CYBERLAB_CORE/layer6/surface_expansion_engine.py" "Engine da Camada 6A"

echo ""
echo "============================================================"
echo " RESUMO DO HEALTH"
echo "============================================================"
echo "Falhas: $FAIL"
echo "Avisos: $WARN"

if [ "$FAIL" -gt 0 ]; then
  echo "[FAIL] Saúde operacional reprovada."
  exit 1
fi

if [ "$WARN" -gt 0 ]; then
  echo "[WARN] Saúde operacional aprovada com avisos."
  exit 0
fi

echo "[OK] Saúde operacional aprovada."
exit 0
