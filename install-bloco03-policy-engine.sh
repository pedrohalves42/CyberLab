#!/usr/bin/env bash
set -euo pipefail

BASE="$HOME/CyberLab"

echo "==== CYBERLAB BLOCO 03 — POLICY ENGINE ===="

mkdir -p \
  "$BASE/modules/policy" \
  "$BASE/state/policy" \
  "$BASE/logs"

cat > "$BASE/modules/policy/policy.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

BASE="$HOME/CyberLab"
CURRENT="$BASE/state/current-operation.txt"

now(){ date -Iseconds; }

current_op(){
  cat "$CURRENT" 2>/dev/null || true
}

require_current_op(){
  OP="$(current_op)"
  if [ -z "$OP" ] || [ ! -d "$OP" ]; then
    echo "[ERRO] Nenhuma operação ativa."
    echo "Use: cyberlab gov create \"Cliente\" dominio.com"
    exit 1
  fi
  echo "$OP"
}

audit_log(){
  OP="$1"
  ACTION="$2"
  STATUS="$3"
  MESSAGE="$4"

  mkdir -p "$OP/audit" "$BASE/audit"
  LINE="$(now) | action=$ACTION | status=$STATUS | message=$MESSAGE"
  echo "$LINE" >> "$OP/audit/audit.log"
  echo "$LINE" >> "$BASE/audit/global-audit.log"
}

show_policy(){
  OP="$(require_current_op)"
  echo "==== CYBERLAB POLICY ===="
  jq . "$OP/policy.json"
}

set_mode(){
  MODE="${1:-}"

  case "$MODE" in
    safe|audit|internal|offensive-admin) ;;
    *)
      echo "[ERRO] Modo inválido."
      echo "Modos permitidos: safe, audit, internal, offensive-admin"
      exit 1
      ;;
  esac

  OP="$(require_current_op)"
  TMP="$(mktemp)"

  if [ "$MODE" = "safe" ]; then
    jq '
      .mode="safe"
      | .allowed_modules.scan=true
      | .allowed_modules.threat=true
      | .allowed_modules.finding=true
      | .allowed_modules.intelligence=true
      | .allowed_modules.correlate=true
      | .allowed_modules.report=true
      | .allowed_modules.delivery=true
      | .allowed_modules.active_fuzzing=false
      | .allowed_modules.exploit=false
      | .allowed_modules.dos=false
      | .allowed_modules.credential_attack=false
      | .limits.threads=5
      | .limits.rate_per_second=5
      | .limits.max_runtime_minutes=60
    ' "$OP/policy.json" > "$TMP"

  elif [ "$MODE" = "audit" ]; then
    jq '
      .mode="audit"
      | .allowed_modules.scan=true
      | .allowed_modules.threat=true
      | .allowed_modules.finding=true
      | .allowed_modules.intelligence=true
      | .allowed_modules.correlate=true
      | .allowed_modules.report=true
      | .allowed_modules.delivery=true
      | .allowed_modules.active_fuzzing=false
      | .allowed_modules.exploit=false
      | .allowed_modules.dos=false
      | .allowed_modules.credential_attack=false
      | .limits.threads=8
      | .limits.rate_per_second=10
      | .limits.max_runtime_minutes=90
    ' "$OP/policy.json" > "$TMP"

  elif [ "$MODE" = "internal" ]; then
    jq '
      .mode="internal"
      | .allowed_modules.scan=true
      | .allowed_modules.threat=true
      | .allowed_modules.finding=true
      | .allowed_modules.intelligence=true
      | .allowed_modules.correlate=true
      | .allowed_modules.report=true
      | .allowed_modules.delivery=true
      | .allowed_modules.active_fuzzing=true
      | .allowed_modules.exploit=false
      | .allowed_modules.dos=false
      | .allowed_modules.credential_attack=false
      | .limits.threads=10
      | .limits.rate_per_second=15
      | .limits.max_runtime_minutes=120
    ' "$OP/policy.json" > "$TMP"

  elif [ "$MODE" = "offensive-admin" ]; then
    jq '
      .mode="offensive-admin"
      | .allowed_modules.scan=true
      | .allowed_modules.threat=true
      | .allowed_modules.finding=true
      | .allowed_modules.intelligence=true
      | .allowed_modules.correlate=true
      | .allowed_modules.report=true
      | .allowed_modules.delivery=true
      | .allowed_modules.active_fuzzing=true
      | .allowed_modules.exploit=false
      | .allowed_modules.dos=false
      | .allowed_modules.credential_attack=false
      | .limits.threads=10
      | .limits.rate_per_second=10
      | .limits.max_runtime_minutes=120
    ' "$OP/policy.json" > "$TMP"
  fi

  mv "$TMP" "$OP/policy.json"

  audit_log "$OP" "policy_set_mode" "OK" "$MODE"

  echo "[OK] Policy mode definido:"
  echo "$MODE"
}

check_module(){
  MODULE="${1:-}"

  if [ -z "$MODULE" ]; then
    echo "[ERRO] Uso: cyberlab policy check scan"
    exit 1
  fi

  OP="$(require_current_op)"
  POLICY="$OP/policy.json"

  if [ ! -f "$POLICY" ]; then
    echo "[ERRO] policy.json ausente"
    exit 1
  fi

  ALLOWED="$(jq -r --arg m "$MODULE" '.allowed_modules[$m] // false' "$POLICY")"

  if [ "$ALLOWED" != "true" ]; then
    audit_log "$OP" "policy_check_$MODULE" "BLOCKED" "Módulo bloqueado pela policy"
    echo "[BLOCKED] módulo não permitido pela policy: $MODULE"
    exit 1
  fi

  audit_log "$OP" "policy_check_$MODULE" "OK" "Módulo permitido"
  echo "[OK] módulo permitido: $MODULE"
}

validate(){
  OP="$(require_current_op)"

  echo "==== CYBERLAB POLICY VALIDATION ===="

  jq empty "$OP/policy.json" >/dev/null
  jq empty "$OP/scope.json" >/dev/null
  jq empty "$OP/metadata.json" >/dev/null
  jq empty "$OP/status.json" >/dev/null

  MODE="$(jq -r '.mode' "$OP/policy.json")"

  case "$MODE" in
    safe|audit|internal|offensive-admin)
      echo "[OK] mode: $MODE"
      ;;
    *)
      echo "[ERRO] modo inválido: $MODE"
      exit 1
      ;;
  esac

  for m in scan threat finding intelligence correlate report delivery; do
    V="$(jq -r --arg m "$m" '.allowed_modules[$m] // false' "$OP/policy.json")"
    if [ "$V" = "true" ]; then
      echo "[OK] módulo habilitado: $m"
    else
      echo "[WARN] módulo desabilitado: $m"
    fi
  done

  for m in exploit dos credential_attack; do
    V="$(jq -r --arg m "$m" '.allowed_modules[$m] // false' "$OP/policy.json")"
    if [ "$V" = "true" ]; then
      echo "[ERRO] módulo proibido habilitado: $m"
      exit 1
    else
      echo "[OK] módulo proibido bloqueado: $m"
    fi
  done

  THREADS="$(jq -r '.limits.threads' "$OP/policy.json")"
  RATE="$(jq -r '.limits.rate_per_second' "$OP/policy.json")"
  RUNTIME="$(jq -r '.limits.max_runtime_minutes' "$OP/policy.json")"

  if [ "$THREADS" -gt 20 ]; then
    echo "[ERRO] threads acima do limite seguro"
    exit 1
  fi

  if [ "$RATE" -gt 30 ]; then
    echo "[ERRO] rate acima do limite seguro"
    exit 1
  fi

  if [ "$RUNTIME" -gt 240 ]; then
    echo "[ERRO] runtime acima do limite seguro"
    exit 1
  fi

  audit_log "$OP" "policy_validate" "OK" "Policy validada"

  echo "[OK] Policy validada com sucesso"
}

guarded_run(){
  CLIENT="${1:-}"
  TARGET="${2:-}"
  MODE="${3:-safe}"

  if [ -z "$CLIENT" ] || [ -z "$TARGET" ]; then
    echo "[ERRO] Uso: cyberlab guarded-run \"Cliente\" dominio.com safe"
    exit 1
  fi

  OP="$(require_current_op)"

  echo "==== CYBERLAB GUARDED RUN ===="
  echo "Cliente: $CLIENT"
  echo "Target: $TARGET"
  echo "Mode: $MODE"

  set_mode "$MODE"
  validate

  cyberlab scope check "$TARGET"
  check_module scan
  cyberlab scan "$TARGET" "$MODE"

  check_module threat
  cyberlab threat "$TARGET"

  check_module finding
  cyberlab finding

  check_module intelligence
  cyberlab intelligence

  check_module correlate
  cyberlab correlate

  check_module report
  cyberlab report

  check_module delivery
  cyberlab delivery generate "$CLIENT"

  cyberlab gov sync || true
  cyberlab db sync || true

  audit_log "$OP" "guarded_run" "OK" "$CLIENT / $TARGET / $MODE"

  echo "[OK] Guarded run finalizado"
}

case "${1:-help}" in
  show)
    show_policy
    ;;
  mode)
    shift
    set_mode "$@"
    ;;
  check)
    shift
    check_module "$@"
    ;;
  validate)
    validate
    ;;
  guarded-run)
    shift
    guarded_run "$@"
    ;;
  *)
    echo "Uso:"
    echo "cyberlab policy show"
    echo "cyberlab policy mode safe|audit|internal|offensive-admin"
    echo "cyberlab policy check scan"
    echo "cyberlab policy validate"
    echo "cyberlab guarded-run \"Cliente\" dominio.com safe"
    ;;
esac
SCRIPT

chmod +x "$BASE/modules/policy/policy.sh"

python3 <<'PY'
from pathlib import Path

p = Path.home() / "CyberLab/bin/cyberlab"
s = p.read_text()

policy_block = '''
policy)
    bash "$HOME/CyberLab/modules/policy/policy.sh" "$@"
    ;;
'''

guarded_block = '''
guarded-run)
    bash "$HOME/CyberLab/modules/policy/policy.sh" guarded-run "$@"
    ;;
'''

def insert_block(s, name, block):
    if f"{name})" in s:
        return s
    idx = s.rfind("*)")
    if idx != -1:
        return s[:idx] + block + "\n" + s[idx:]
    return s + "\n" + block

s = insert_block(s, "policy", policy_block)
s = insert_block(s, "guarded-run", guarded_block)

p.write_text(s)
PY

chmod +x "$BASE/bin/cyberlab"

echo
echo "[OK] BLOCO 03 Policy Engine instalado"
echo
echo "Validação recomendada:"
echo "source ~/CyberLab/core/bootstrap.sh"
echo "hash -r"
echo "cyberlab policy show"
echo "cyberlab policy mode safe"
echo "cyberlab policy validate"
echo "cyberlab policy check scan"
echo "cyberlab guarded-run \"Loja Maromba\" lojamaromba.com safe"
