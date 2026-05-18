#!/usr/bin/env bash
set -euo pipefail

BASE="$CYBERLAB_HOME"

echo "==== FIX BLOCO 04 — RUNTIME CLEAN ===="

mkdir -p \
  "$BASE/modules/runtime/state/locks" \
  "$BASE/modules/runtime/state/pids" \
  "$BASE/modules/runtime/state/logs"

cat > "$BASE/modules/runtime/runtime.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

BASE="$CYBERLAB_HOME"
STATE="$BASE/modules/runtime/state"
LOCKDIR="$STATE/locks"
PIDDIR="$STATE/pids"
LOGDIR="$STATE/logs"

mkdir -p "$LOCKDIR" "$PIDDIR" "$LOGDIR"

runtime_log() {
  echo "[$(date -Iseconds)] $*" >> "$LOGDIR/runtime.log"
}

runtime_validate_limits() {
  THREADS="${1:-5}"
  RATE="${2:-5}"

  if [ "$THREADS" -gt 20 ]; then
    echo "[BLOCKED] threads acima do limite seguro"
    exit 1
  fi

  if [ "$RATE" -gt 25 ]; then
    echo "[BLOCKED] rate acima do limite seguro"
    exit 1
  fi

  runtime_log "validate threads=$THREADS rate=$RATE"
  echo "[OK] Runtime limits validados"
}

runtime_lock() {
  OP="${1:-default}"
  LOCKFILE="$LOCKDIR/$OP.lock"

  if [ -f "$LOCKFILE" ]; then
    echo "[BLOCKED] operação já em execução: $OP"
    exit 1
  fi

  echo "$$" > "$LOCKFILE"
  runtime_log "lock op=$OP pid=$$"
  echo "[OK] lock criado: $OP"
}

runtime_unlock() {
  OP="${1:-default}"
  LOCKFILE="$LOCKDIR/$OP.lock"

  rm -f "$LOCKFILE"
  runtime_log "unlock op=$OP"
  echo "[OK] lock removido: $OP"
}

runtime_status() {
  echo "==== CYBERLAB RUNTIME STATUS ===="
  echo "[locks]"
  find "$LOCKDIR" -type f -name "*.lock" 2>/dev/null || true
  echo
  echo "[pids]"
  find "$PIDDIR" -type f -name "*.pid" 2>/dev/null || true
}

case "${1:-help}" in
  validate)
    shift
    runtime_validate_limits "$@"
    ;;
  lock)
    shift
    runtime_lock "$@"
    ;;
  unlock)
    shift
    runtime_unlock "$@"
    ;;
  status)
    runtime_status
    ;;
  *)
    echo "Uso:"
    echo "cyberlab runtime validate 5 5"
    echo "cyberlab runtime lock op-teste"
    echo "cyberlab runtime unlock op-teste"
    echo "cyberlab runtime status"
    ;;
esac
SCRIPT

chmod +x "$BASE/modules/runtime/runtime.sh"

python3 <<'PY'
from pathlib import Path

p = Path.home() / "CyberLab/bin/cyberlab"
s = p.read_text()

block = '''runtime)
    bash "$CYBERLAB_HOME/modules/runtime/runtime.sh" "$@"
    ;;
'''

# remove blocos runtime quebrados antigos
parts = s.splitlines()
clean = []
skip = False

for line in parts:
    if line.strip() == "runtime)":
        skip = True
        continue
    if skip and line.strip() == ";;":
        skip = False
        continue
    if not skip:
        clean.append(line)

s = "\n".join(clean) + "\n"

idx = s.rfind("*)")
if idx != -1:
    s = s[:idx] + block + "\n" + s[idx:]
else:
    s += "\n" + block

p.write_text(s)
PY

chmod +x "$BASE/bin/cyberlab"

echo "[OK] Bloco 04 Runtime corrigido"
