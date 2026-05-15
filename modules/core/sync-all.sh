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

  "$CYBERLAB_MODULES/intelligence/intelligence.sh"
  "$CYBERLAB_MODULES/findings/findings-engine.py"
  "$CYBERLAB_MODULES/risk/risk-engine.py"
  "$CYBERLAB_MODULES/remediation/remediation-engine.py"
  "$CYBERLAB_MODULES/assets/asset-engine.py"
  "$CYBERLAB_MODULES/timeline/timeline-engine.py"
  "$CYBERLAB_MODULES/analytics/analytics-engine.py"

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

[ -f "$CYBERLAB_MODULES/intelligence/intelligence-pipeline.sh" ] && chmod +x "$CYBERLAB_MODULES/intelligence/intelligence-pipeline.sh"

[ -f "$CYBERLAB_MODULES/intelligence/json-recovery.sh" ] && chmod +x "$CYBERLAB_MODULES/intelligence/json-recovery.sh"

[ -f "$CYBERLAB_MODULES/intelligence/dedupe-engine.sh" ] && chmod +x "$CYBERLAB_MODULES/intelligence/dedupe-engine.sh"

[ -f "$CYBERLAB_MODULES/intelligence/confidence-engine.sh" ] && chmod +x "$CYBERLAB_MODULES/intelligence/confidence-engine.sh"

[ -f "$CYBERLAB_MODULES/intelligence/context-engine.sh" ] && chmod +x "$CYBERLAB_MODULES/intelligence/context-engine.sh"

[ -f "$CYBERLAB_MODULES/intelligence/severity-engine.sh" ] && chmod +x "$CYBERLAB_MODULES/intelligence/severity-engine.sh"

[ -f "$CYBERLAB_MODULES/intelligence/risk-engine.sh" ] && chmod +x "$CYBERLAB_MODULES/intelligence/risk-engine.sh"
