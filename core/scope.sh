#!/bin/bash

scope_file="$CYBERLAB_CONFIG/scope.txt"

in_scope() {
  raw="$1"
  target="$(clean_target "$raw")"

  [ -z "$target" ] && return 1
  [ ! -f "$scope_file" ] && return 1

  if [[ "$target" == "localhost" || "$target" == "127.0.0.1" ]]; then
    return 0
  fi

  if grep -qx "$target" "$scope_file"; then
    return 0
  fi

  if [[ "$target" =~ ^192\.168\.1\.[0-9]+$ ]] && grep -qx "192.168.1.0/24" "$scope_file"; then
    return 0
  fi

  while read -r pattern; do
    [[ -z "$pattern" ]] && continue
    [[ "$pattern" =~ ^# ]] && continue

    if [[ "$pattern" == \*.* ]]; then
      base="${pattern#*.}"
      if [[ "$target" == "$base" || "$target" == *".$base" ]]; then
        return 0
      fi
    fi
  done < "$scope_file"

  return 1
}

check_scope() {
  target="$(clean_target "$1")"

  if in_scope "$target"; then
    info "Alvo autorizado: $target"
    return 0
  else
    error "Alvo fora do escopo autorizado: $target"
    echo "[BLOQUEADO] fora do escopo autorizado: $target"
    return 1
  fi
}
