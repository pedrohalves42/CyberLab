#!/bin/bash

set -u

source "$HOME/CyberLab/core/bootstrap.sh"

echo
echo "========================================"
echo " CYBERLAB DOCTOR"
echo "========================================"
echo

ERRORS=0

check_file() {
  f="$1"
  if [ -f "$f" ]; then
    echo "[OK] $f"
  else
    echo "[MISS] $f"
    ERRORS=$((ERRORS+1))
  fi
}

check_dir() {
  d="$1"
  if [ -d "$d" ]; then
    echo "[OK] $d"
  else
    echo "[MISS] $d"
    ERRORS=$((ERRORS+1))
  fi
}

echo "[Dirs]"
check_dir "$CYBERLAB_HOME"
check_dir "$CYBERLAB_BIN"
check_dir "$CYBERLAB_CORE"
check_dir "$CYBERLAB_MODULES"
check_dir "$CYBERLAB_RESULTS"
check_dir "$CYBERLAB_CONFIG"
check_dir "$CYBERLAB_CLIENTS"
check_dir "$CYBERLAB_WEB"
check_dir "$CYBERLAB_UI"

echo
echo "[Files]"
check_file "$CYBERLAB_BIN/cyberlab"
check_file "$CYBERLAB_CORE/bootstrap.sh"
check_file "$CYBERLAB_WEB/dashboard.py"
check_file "$CYBERLAB_UI/menu.sh"
check_file "$CYBERLAB_UI/monitor.sh"
check_file "$CYBERLAB_MODULES/core/labup.sh"
check_file "$CYBERLAB_MODULES/core/sync.sh"

echo
echo "[Python]"
python3 --version || ERRORS=$((ERRORS+1))

python3 - <<'PY'
mods = ["flask", "json", "pathlib", "subprocess"]
for m in mods:
    try:
        __import__(m)
        print("[OK]", m)
    except Exception:
        print("[MISS]", m)
PY

echo
echo "[Tools]"
for t in nmap curl jq dig whois tmux docker python3 git; do
  if command -v "$t" >/dev/null 2>&1; then
    echo "[OK] $t"
  else
    echo "[MISS] $t"
    ERRORS=$((ERRORS+1))
  fi
done

echo
echo "[Resumo]"
if [ "$ERRORS" -eq 0 ]; then
  echo "[OK] Nenhum erro estrutural crítico encontrado"
else
  echo "[WARN] Erros encontrados: $ERRORS"
fi
