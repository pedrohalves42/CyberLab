#!/bin/bash

source "$HOME/CyberLab/core/bootstrap.sh"

slugify() {
  echo "$1" \
    | tr '[:upper:]' '[:lower:]' \
    | sed 's/[^a-z0-9]/-/g' \
    | sed 's/-\+/-/g' \
    | sed 's/^-//;s/-$//'
}

client_dir() {
  slug="$(slugify "$1")"
  echo "$CYBERLAB_CLIENTS/$slug"
}

client_add() {
  name="$1"
  domain="$2"

  if [ -z "$name" ] || [ -z "$domain" ]; then
    echo "Uso: cyberlab client add \"Cliente\" dominio.com"
    exit 1
  fi

  slug="$(slugify "$name")"
  dir="$CYBERLAB_CLIENTS/$slug"

  mkdir -p "$dir"/{scope,reports,notes,assets}

  cat > "$dir/client.json" <<JSON
{
  "name": "$name",
  "slug": "$slug",
  "created_at": "$(date)",
  "primary_domain": "$domain"
}
JSON

  echo "$domain" > "$dir/scope/scope.txt"

  if ! grep -qx "$domain" "$CYBERLAB_CONFIG/scope.txt"; then
    echo "$domain" >> "$CYBERLAB_CONFIG/scope.txt"
  fi

  echo "[✓] Cliente criado: $name"
  echo "[✓] Diretório: $dir"
  echo "[✓] Escopo adicionado: $domain"
}

client_list() {
  echo "==== CYBERLAB CLIENTS ===="

  for dir in "$CYBERLAB_CLIENTS"/*; do
    [ -d "$dir" ] || continue
    [ -f "$dir/client.json" ] || continue

    name="$(jq -r '.name' "$dir/client.json" 2>/dev/null)"
    domain="$(jq -r '.primary_domain' "$dir/client.json" 2>/dev/null)"

    echo "- $name | $domain | $dir"
  done
}

client_show() {
  name="$1"
  dir="$(client_dir "$name")"

  if [ ! -d "$dir" ]; then
    echo "[ERRO] Cliente não encontrado: $name"
    exit 1
  fi

  echo "==== CLIENTE ===="
  cat "$dir/client.json"
  echo
  echo "==== ESCOPO ===="
  cat "$dir/scope/scope.txt"
}

client_scope_add() {
  name="$1"
  target="$2"
  dir="$(client_dir "$name")"

  if [ ! -d "$dir" ]; then
    echo "[ERRO] Cliente não encontrado: $name"
    exit 1
  fi

  if [ -z "$target" ]; then
    echo "Uso: cyberlab client scope-add Cliente alvo.com"
    exit 1
  fi

  echo "$target" >> "$dir/scope/scope.txt"

  if ! grep -qx "$target" "$CYBERLAB_CONFIG/scope.txt"; then
    echo "$target" >> "$CYBERLAB_CONFIG/scope.txt"
  fi

  echo "[✓] Escopo adicionado ao cliente e global: $target"
}

client_scan() {
  name="$1"
  target="$2"
  mode="${3:-safe}"

  if [ -z "$name" ] || [ -z "$target" ]; then
    echo "Uso: cyberlab client scan Cliente alvo.com safe"
    exit 1
  fi

  dir="$(client_dir "$name")"

  if [ ! -d "$dir" ]; then
    echo "[ERRO] Cliente não encontrado: $name"
    exit 1
  fi

  if ! grep -qx "$target" "$dir/scope/scope.txt"; then
    echo "[BLOQUEADO] alvo não está no escopo do cliente: $target"
    echo "Adicione com:"
    echo "cyberlab client scope-add \"$name\" $target"
    exit 1
  fi

  cyberlab scan "$target" "$mode" "$name"

  latest="$(cat "$CYBERLAB_RESULTS/web/latest.txt" 2>/dev/null)"

  if [ -n "$latest" ]; then
    mkdir -p "$dir/reports"
    echo "$latest" >> "$dir/reports/history.txt"
    echo "$latest" > "$dir/reports/latest.txt"
  fi
}

client_latest() {
  name="$1"
  dir="$(client_dir "$name")"

  if [ ! -f "$dir/reports/latest.txt" ]; then
    echo "Nenhum relatório para este cliente."
    exit 1
  fi

  cat "$dir/reports/latest.txt"
}

client_report() {
  name="$1"
  dir="$(client_dir "$name")"

  if [ ! -f "$dir/reports/latest.txt" ]; then
    echo "Nenhum relatório para este cliente."
    exit 1
  fi

  latest="$(cat "$dir/reports/latest.txt")"
  cyberlab report "$latest"
}

case "$1" in
  add)
    client_add "$2" "$3"
    ;;
  list)
    client_list
    ;;
  show)
    client_show "$2"
    ;;
  scope-add)
    client_scope_add "$2" "$3"
    ;;
  scan)
    client_scan "$2" "$3" "$4"
    ;;
  latest)
    client_latest "$2"
    ;;
  report)
    client_report "$2"
    ;;
  *)
    echo "Uso:"
    echo "  cyberlab client add \"Cliente\" dominio.com"
    echo "  cyberlab client list"
    echo "  cyberlab client show \"Cliente\""
    echo "  cyberlab client scope-add \"Cliente\" alvo.com"
    echo "  cyberlab client scan \"Cliente\" alvo.com safe"
    echo "  cyberlab client latest \"Cliente\""
    echo "  cyberlab client report \"Cliente\""
    ;;
esac
