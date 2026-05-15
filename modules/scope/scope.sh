#!/usr/bin/env bash
set -euo pipefail

BASE="$HOME/CyberLab"

CURRENT="$BASE/state/current-operation.txt"

now() {
  date -Iseconds
}

current_op() {
  cat "$CURRENT" 2>/dev/null || true
}

require_current_op() {
  OP="$(current_op)"

  if [ -z "$OP" ] || [ ! -d "$OP" ]; then
    echo "[ERRO] Nenhuma operação ativa."
    echo "Use: cyberlab gov create \"Cliente\" dominio.com"
    exit 1
  fi

  echo "$OP"
}

audit_log() {
  OP="$1"
  ACTION="$2"
  STATUS="$3"
  MESSAGE="$4"

  mkdir -p "$OP/audit"

  echo "$(now) | action=$ACTION | status=$STATUS | message=$MESSAGE" \
    >> "$OP/audit/audit.log"
}

normalize_domain() {
  echo "$1" \
    | tr '[:upper:]' '[:lower:]' \
    | sed 's#https\?://##' \
    | sed 's#/.*##' \
    | sed 's/:.*//'
}

is_subdomain_of() {
  CHILD="$1"
  PARENT="$2"

  [[ "$CHILD" == "$PARENT" ]] && return 0
  [[ "$CHILD" == *".$PARENT" ]] && return 0

  return 1
}

check_scope() {
  TARGET_RAW="${1:-}"

  if [ -z "$TARGET_RAW" ]; then
    echo "[ERRO] Uso: cyberlab scope check alvo.com"
    exit 1
  fi

  OP="$(require_current_op)"

  TARGET="$(normalize_domain "$TARGET_RAW")"

  SCOPE="$OP/scope.json"

  if [ ! -f "$SCOPE" ]; then
    echo "[ERRO] scope.json ausente"
    exit 1
  fi

  ROOT_DOMAIN="$(jq -r '.target' "$SCOPE")"

  if [ -z "$ROOT_DOMAIN" ] || [ "$ROOT_DOMAIN" = "null" ]; then
    echo "[ERRO] target inválido no scope.json"
    exit 1
  fi

  ROOT_DOMAIN="$(normalize_domain "$ROOT_DOMAIN")"

  BLOCKED=0
  REASON=""

  # Match direto
  if is_subdomain_of "$TARGET" "$ROOT_DOMAIN"; then
    BLOCKED=0
  else
    BLOCKED=1
    REASON="target fora do domínio autorizado"
  fi

  # denied domains
  DENIED="$(jq -r '.denied_domains[]?' "$SCOPE" 2>/dev/null || true)"

  for d in $DENIED; do
    d="$(normalize_domain "$d")"

    if is_subdomain_of "$TARGET" "$d"; then
      BLOCKED=1
      REASON="domínio explicitamente bloqueado"
    fi
  done

  # third-party deny
  POLICY="$(jq -r '.third_party_policy' "$SCOPE")"

  if [ "$POLICY" = "deny_by_default" ]; then
    if ! is_subdomain_of "$TARGET" "$ROOT_DOMAIN"; then
      BLOCKED=1
      REASON="third-party target bloqueado"
    fi
  fi

  # typo-like validation
  if [[ "$TARGET" =~ googleusercontent|cloudfront|azurewebsites|amazonaws ]]; then
    BLOCKED=1
    REASON="cloud/third-party asset bloqueado"
  fi

  # localhost/internal
  if [[ "$TARGET" =~ localhost|127\.|0\.0\.0\.0 ]]; then
    BLOCKED=1
    REASON="localhost/internal proibido"
  fi

  mkdir -p "$OP/state/scope"

  if [ "$BLOCKED" -eq 1 ]; then

    cat > "$OP/state/scope/last-check.json" <<JSON
{
  "allowed": false,
  "target": "$TARGET",
  "reason": "$REASON",
  "checked_at": "$(now)"
}
JSON

    audit_log "$OP" "scope_check" "BLOCKED" "$TARGET :: $REASON"

    echo "[BLOCKED] $TARGET"
    echo "Motivo: $REASON"

    exit 1
  fi

  cat > "$OP/state/scope/last-check.json" <<JSON
{
  "allowed": true,
  "target": "$TARGET",
  "scope_match": "$ROOT_DOMAIN",
  "checked_at": "$(now)"
}
JSON

  audit_log "$OP" "scope_check" "OK" "$TARGET autorizado"

  echo "[OK] alvo autorizado"
  echo "Target: $TARGET"
  echo "Scope: $ROOT_DOMAIN"
}

show_scope() {
  OP="$(require_current_op)"

  echo "==== CYBERLAB SCOPE ===="
  jq . "$OP/scope.json"
}

add_denied_domain() {
  DOMAIN="${1:-}"

  if [ -z "$DOMAIN" ]; then
    echo "[ERRO] Uso: cyberlab scope deny dominio.com"
    exit 1
  fi

  OP="$(require_current_op)"

  TMP="$(mktemp)"

  jq --arg d "$DOMAIN" '
    .denied_domains += [$d]
    | .denied_domains |= unique
  ' "$OP/scope.json" > "$TMP"

  mv "$TMP" "$OP/scope.json"

  audit_log "$OP" "scope_deny" "OK" "$DOMAIN"

  echo "[OK] domínio bloqueado:"
  echo "$DOMAIN"
}

allow_ip_range() {
  RANGE="${1:-}"

  if [ -z "$RANGE" ]; then
    echo "[ERRO] Uso: cyberlab scope allow-ip 172.16.0.0/24"
    exit 1
  fi

  OP="$(require_current_op)"

  TMP="$(mktemp)"

  jq --arg r "$RANGE" '
    .allowed_ips += [$r]
    | .allowed_ips |= unique
  ' "$OP/scope.json" > "$TMP"

  mv "$TMP" "$OP/scope.json"

  audit_log "$OP" "scope_allow_ip" "OK" "$RANGE"

  echo "[OK] range autorizado:"
  echo "$RANGE"
}

case "${1:-help}" in

  check)
    shift
    check_scope "$@"
    ;;

  show)
    show_scope
    ;;

  deny)
    shift
    add_denied_domain "$@"
    ;;

  allow-ip)
    shift
    allow_ip_range "$@"
    ;;

  *)
    echo "Uso:"
    echo "cyberlab scope check alvo.com"
    echo "cyberlab scope show"
    echo "cyberlab scope deny dominio.com"
    echo "cyberlab scope allow-ip 172.16.0.0/24"
    ;;
esac
