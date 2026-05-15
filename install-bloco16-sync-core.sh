#!/bin/bash

set -u

CYBERLAB_HOME="$HOME/CyberLab"

mkdir -p \
  "$CYBERLAB_HOME/core" \
  "$CYBERLAB_HOME/bin" \
  "$CYBERLAB_HOME/modules/core" \
  "$CYBERLAB_HOME/state" \
  "$CYBERLAB_HOME/logs" \
  "$CYBERLAB_HOME/results" \
  "$CYBERLAB_HOME/config" \
  "$CYBERLAB_HOME/clients"

echo "==== CYBERLAB BLOCO 16 SYNC CORE ===="

cat > "$CYBERLAB_HOME/core/bootstrap.sh" <<'EOS'
#!/bin/bash

export CYBERLAB_HOME="$HOME/CyberLab"
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

mkdir -p \
  "$CYBERLAB_BIN" \
  "$CYBERLAB_CORE" \
  "$CYBERLAB_MODULES" \
  "$CYBERLAB_RESULTS" \
  "$CYBERLAB_CONFIG" \
  "$CYBERLAB_CLIENTS" \
  "$CYBERLAB_LOGS" \
  "$CYBERLAB_STATE"

touch "$CYBERLAB_CONFIG/scope.txt"
touch "$CYBERLAB_LOGS/cyberlab.log"

export PATH="$CYBERLAB_BIN:$PATH"

timestamp() {
  date +"%Y-%m-%d_%H-%M-%S"
}

clean_target() {
  echo "$1" \
    | sed 's#https://##' \
    | sed 's#http://##' \
    | sed 's#/.*##' \
    | xargs
}

slugify() {
  echo "$1" \
    | tr '[:upper:]' '[:lower:]' \
    | sed 's/[^a-z0-9]/-/g' \
    | sed 's/-\+/-/g' \
    | sed 's/^-//;s/-$//'
}

validate_target() {
  target="$1"

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
  target="$(clean_target "$1")"

  if grep -qx "$target" "$CYBERLAB_CONFIG/scope.txt" 2>/dev/null; then
    echo "[$(date '+%F %T')] [INFO] Alvo autorizado: $target"
    return 0
  fi

  if [ "$target" = "localhost" ] || [ "$target" = "127.0.0.1" ]; then
    return 0
  fi

  echo "[BLOQUEADO] fora do escopo autorizado: $target"
  return 1
}

cyberlog() {
  echo "[$(date '+%F %T')] $*" | tee -a "$CYBERLAB_LOGS/cyberlab.log"
}
EOS

chmod +x "$CYBERLAB_HOME/core/bootstrap.sh"

cat > "$CYBERLAB_HOME/modules/core/sync-all.sh" <<'EOS'
#!/bin/bash

set -u

source "$HOME/CyberLab/core/bootstrap.sh"

LOG="$CYBERLAB_LOGS/sync-all.log"

exec > >(tee -a "$LOG") 2>&1

echo
echo "========================================"
echo " CYBERLAB UNIFIED SYNC CORE"
echo "========================================"
echo "Data: $(date)"
echo

mkdir -p \
  "$CYBERLAB_RESULTS/web" \
  "$CYBERLAB_RESULTS/lan" \
  "$CYBERLAB_RESULTS/threat" \
  "$CYBERLAB_RESULTS/detection" \
  "$CYBERLAB_RESULTS/correlation" \
  "$CYBERLAB_RESULTS/redteam" \
  "$CYBERLAB_STATE"

echo "[1/9] Estrutura base OK"

echo
echo "[2/9] Verificando módulos"

MODULES=(
  "$CYBERLAB_CORE/bootstrap.sh"
  "$CYBERLAB_BIN/cyberlab"
  "$CYBERLAB_CORE/client.sh"
  "$CYBERLAB_CORE/delivery.sh"
  "$CYBERLAB_MODULES/web/web-scan.sh"
  "$CYBERLAB_MODULES/lan/lan-scan.sh"
  "$CYBERLAB_MODULES/threat/threat-engine.sh"
  "$CYBERLAB_MODULES/detection/detection-engine.sh"
  "$CYBERLAB_MODULES/correlation/correlation.sh"
  "$CYBERLAB_MODULES/redteam/redteam.sh"
  "$CYBERLAB_UI/menu.sh"
  "$CYBERLAB_UI/monitor.sh"
  "$CYBERLAB_WEB/dashboard.py"
)

for f in "${MODULES[@]}"; do
  if [ -f "$f" ]; then
    echo "[OK] $f"
  else
    echo "[MISS] $f"
  fi
done

echo
echo "[3/9] Corrigindo permissões"

chmod -R 755 "$CYBERLAB_BIN" 2>/dev/null || true
chmod -R 755 "$CYBERLAB_CORE" 2>/dev/null || true
chmod -R 755 "$CYBERLAB_MODULES" 2>/dev/null || true
chmod -R 755 "$CYBERLAB_UI" 2>/dev/null || true
chmod -R 755 "$CYBERLAB_WEB" 2>/dev/null || true

echo "[OK] Permissões corrigidas"

echo
echo "[4/9] Sincronizando latest.txt"

sync_latest() {
  name="$1"
  base="$CYBERLAB_RESULTS/$name"
  mkdir -p "$base"

  latest="$(find "$base" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | tail -1)"

  if [ -n "$latest" ]; then
    echo "$latest" > "$base/latest.txt"
    echo "[OK] latest $name => $latest"
  else
    echo "[INFO] sem resultado para $name"
  fi
}

sync_latest web
sync_latest lan
sync_latest threat
sync_latest detection
sync_latest correlation
sync_latest redteam

echo
echo "[5/9] Criando estado central latest.json"

cat > "$CYBERLAB_STATE/latest.json" <<JSON
{
  "generated_at": "$(date)",
  "host": "$(hostname)",
  "user": "$USER",
  "kernel": "$(uname -r)",
  "latest": {
    "web": "$(cat "$CYBERLAB_RESULTS/web/latest.txt" 2>/dev/null)",
    "lan": "$(cat "$CYBERLAB_RESULTS/lan/latest.txt" 2>/dev/null)",
    "threat": "$(cat "$CYBERLAB_RESULTS/threat/latest.txt" 2>/dev/null)",
    "detection": "$(cat "$CYBERLAB_RESULTS/detection/latest.txt" 2>/dev/null)",
    "correlation": "$(cat "$CYBERLAB_RESULTS/correlation/latest.txt" 2>/dev/null)",
    "redteam": "$(cat "$CYBERLAB_RESULTS/redteam/latest.txt" 2>/dev/null)"
  }
}
JSON

jq . "$CYBERLAB_STATE/latest.json" >/dev/null 2>&1 \
  && echo "[OK] latest.json válido" \
  || echo "[WARN] latest.json inválido"

echo
echo "[6/9] Verificando clientes"

if [ -d "$CYBERLAB_CLIENTS" ]; then
  find "$CYBERLAB_CLIENTS" -maxdepth 2 -name client.json -print 2>/dev/null || true
else
  echo "[INFO] nenhum cliente"
fi

echo
echo "[7/9] Verificando ferramentas principais"

TOOLS=(
  bash zsh git curl wget jq python3 pip3 nmap whois dig tmux docker
  arp-scan gobuster whatweb nikto wafw00f nuclei subfinder httpx katana naabu
)

for t in "${TOOLS[@]}"; do
  if command -v "$t" >/dev/null 2>&1; then
    echo "[OK] $t"
  else
    echo "[MISS] $t"
  fi
done

echo
echo "[8/9] Verificando dashboard"

if pgrep -f "$CYBERLAB_WEB/dashboard.py" >/dev/null 2>&1; then
  echo "[OK] Dashboard ativo"
else
  echo "[INFO] Dashboard parado"
fi

echo
echo "[9/9] Finalizado"

echo
echo "========================================"
echo " CYBERLAB SINCRONIZADO"
echo "========================================"
echo "Estado: $CYBERLAB_STATE/latest.json"
echo "Log:    $LOG"
echo
EOS

chmod +x "$CYBERLAB_HOME/modules/core/sync-all.sh"

cat > "$CYBERLAB_HOME/modules/core/validate-all.sh" <<'EOS'
#!/bin/bash

set -u

source "$HOME/CyberLab/core/bootstrap.sh"

echo
echo "========================================"
echo " CYBERLAB VALIDATE ALL"
echo "========================================"

FAIL=0

check_file() {
  if [ -f "$1" ]; then
    echo "[OK] $1"
  else
    echo "[FAIL] $1"
    FAIL=$((FAIL+1))
  fi
}

check_dir() {
  if [ -d "$1" ]; then
    echo "[OK] $1"
  else
    echo "[FAIL] $1"
    FAIL=$((FAIL+1))
  fi
}

echo
echo "[Diretórios]"

check_dir "$CYBERLAB_HOME"
check_dir "$CYBERLAB_BIN"
check_dir "$CYBERLAB_CORE"
check_dir "$CYBERLAB_MODULES"
check_dir "$CYBERLAB_RESULTS"
check_dir "$CYBERLAB_CONFIG"
check_dir "$CYBERLAB_CLIENTS"
check_dir "$CYBERLAB_LOGS"
check_dir "$CYBERLAB_STATE"

echo
echo "[Arquivos essenciais]"

check_file "$CYBERLAB_CORE/bootstrap.sh"
check_file "$CYBERLAB_BIN/cyberlab"
check_file "$CYBERLAB_MODULES/core/sync-all.sh"

echo
echo "[Comandos CyberLab]"

for cmd in status health tools labup sync sync-all validate-all client delivery threat detect correlate redteam dashboard dashboard-start; do
  if cyberlab "$cmd" --help >/dev/null 2>&1 || cyberlab "$cmd" >/dev/null 2>&1; then
    echo "[OK/MAP] cyberlab $cmd"
  else
    echo "[WARN] verificar comando: cyberlab $cmd"
  fi
done

echo
echo "[JSON]"

find "$CYBERLAB_HOME" -name "*.json" 2>/dev/null | while read -r j; do
  jq empty "$j" >/dev/null 2>&1 \
    && echo "[OK] $j" \
    || echo "[BROKEN] $j"
done

echo
echo "[Resumo]"

if [ "$FAIL" -eq 0 ]; then
  echo "[OK] Estrutura base validada"
else
  echo "[WARN] Falhas estruturais: $FAIL"
fi
EOS

chmod +x "$CYBERLAB_HOME/modules/core/validate-all.sh"

python3 - <<'PY'
from pathlib import Path

p = Path.home() / "CyberLab/bin/cyberlab"

if not p.exists():
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("""#!/bin/bash
source "$HOME/CyberLab/core/bootstrap.sh"

case "$1" in
  status)
    echo "CyberLab Unified"
    echo "Home: $CYBERLAB_HOME"
    echo "User: $USER"
    echo "Kernel: $(uname -r)"
    ;;
  *)
    echo "Uso: cyberlab {status|sync-all|validate-all}"
    ;;
esac
""")

s = p.read_text()

insert = r'''
  sync-all)
    bash "$CYBERLAB_MODULES/core/sync-all.sh"
    ;;

  validate-all)
    bash "$CYBERLAB_MODULES/core/validate-all.sh"
    ;;
'''

if '  sync-all)' not in s:
    if 'case "$1" in' in s:
        s = s.replace('case "$1" in', 'case "$1" in\n' + insert)
    else:
        s += '\ncase "$1" in\n' + insert + '\nesac\n'

if 'cyberlab sync-all' not in s:
    s = s.replace(
        'echo "Uso:',
        'echo "  cyberlab sync-all"\necho "  cyberlab validate-all"\necho "Uso:'
    )

p.write_text(s)
PY

chmod +x "$CYBERLAB_HOME/bin/cyberlab"

if ! grep -q 'CyberLab/core/bootstrap.sh' "$HOME/.zshrc" 2>/dev/null; then
  echo 'source ~/CyberLab/core/bootstrap.sh' >> "$HOME/.zshrc"
fi

echo
echo "[OK] Bloco 16 Sync Core instalado"
echo
echo "Agora rode:"
echo "source ~/CyberLab/core/bootstrap.sh"
echo "cyberlab sync-all"
echo "cyberlab validate-all"
echo
