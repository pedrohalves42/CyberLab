#!/bin/bash

validate_target() {
  target="$(clean_target "$1")"

  if [ -z "$target" ]; then
    echo "[ERRO] alvo vazio"
    return 1
  fi

  if [[ "$target" =~ [[:space:]] ]]; then
    echo "[ERRO] alvo inválido: contém espaços"
    return 1
  fi

  if [[ "$target" =~ ^https?:// ]]; then
    echo "[ERRO] informe apenas domínio/IP, sem http:// ou https://"
    return 1
  fi

  return 0
}

validate_mode() {
  mode="$1"

  case "$mode" in
    safe|max|lab)
      return 0
      ;;
    *)
      echo "[ERRO] modo inválido: $mode"
      echo "Use: safe, max ou lab"
      return 1
      ;;
  esac
}
