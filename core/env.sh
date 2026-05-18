#!/bin/bash

# ============================================================
# CyberLab — Environment Loader
# ============================================================
# Responsabilidade:
#   - Exportar variáveis de caminho
#   - Fornecer funções utilitárias
#   - NÃO criar diretórios
#   - NÃO criar arquivos
# ============================================================

export CYBERLAB_HOME="${CYBERLAB_HOME:-$HOME/CyberLab}"

export CYBERLAB_BIN="$CYBERLAB_HOME/bin"
export CYBERLAB_CORE="$CYBERLAB_HOME/core"
export CYBERLAB_MODULES="$CYBERLAB_HOME/modules"
export CYBERLAB_RESULTS="$CYBERLAB_HOME/results"
export CYBERLAB_CONFIG="$CYBERLAB_HOME/config"
export CYBERLAB_CLIENTS="$CYBERLAB_HOME/clients"
export CYBERLAB_LOGS="$CYBERLAB_HOME/logs"
export CYBERLAB_WEB="$CYBERLAB_HOME/web"
export CYBERLAB_UI="$CYBERLAB_HOME/ui"
export CYBERLAB_STATE="$CYBERLAB_HOME/state"
export CYBERLAB_DATA="$CYBERLAB_HOME/data"
export CYBERLAB_QUEUE="$CYBERLAB_HOME/queue"

export PATH="$CYBERLAB_BIN:$PATH"

timestamp() {
  date +"%Y-%m-%d_%H-%M-%S"
}

clean_target() {
  echo "${1:-}" \
    | sed 's#https://##' \
    | sed 's#http://##' \
    | sed 's#/.*##' \
    | xargs
}

slugify() {
  echo "${1:-}" \
    | tr '[:upper:]' '[:lower:]' \
    | sed 's/[^a-z0-9]/-/g' \
    | sed 's/-\+/-/g' \
    | sed 's/^-//;s/-$//'
}

validate_target() {
  local target="${1:-}"

  if [ -z "$target" ]; then
    echo "[ERRO] alvo vazio"
    return 1
  fi

  if echo "$target" | grep -Eq '^[a-zA-Z0-9.-]+$|^[0-9.]+$'; then
    return 0
  fi

  echo "[ERRO] alvo inválido: $target"
  return 1
}

check_scope() {
  local target
  local scope_file

  target="$(clean_target "${1:-}")"
  scope_file="$CYBERLAB_CONFIG/scope.txt"

  if [ "$target" = "localhost" ] || [ "$target" = "127.0.0.1" ]; then
    return 0
  fi

  if [ ! -f "$scope_file" ]; then
    echo "[BLOQUEADO] arquivo de escopo não encontrado: $scope_file"
    return 1
  fi

  if grep -qx "$target" "$scope_file" 2>/dev/null; then
    echo "[$(date '+%F %T')] [INFO] Alvo autorizado: $target"
    return 0
  fi

  echo "[BLOQUEADO] fora do escopo autorizado: $target"
  return 1
}

cyberlog() {
  local message
  message="[$(date '+%F %T')] $*"

  if [ -d "$CYBERLAB_LOGS" ]; then
    echo "$message" | tee -a "$CYBERLAB_LOGS/cyberlab.log"
  else
    echo "$message"
  fi
}
