#!/bin/bash

set -u

source "$HOME/CyberLab/core/bootstrap.sh"

echo
echo "========================================"
echo " CYBERLAB SYNC ENGINE"
echo "========================================"
echo

sync_latest() {
  name="$1"
  base="$CYBERLAB_RESULTS/$name"

  mkdir -p "$base"

  latest="$(find "$base" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | tail -1)"

  if [ -n "$latest" ]; then
    echo "$latest" > "$base/latest.txt"
    echo "[OK] $name latest: $latest"
  else
    echo "[INFO] $name sem resultados"
  fi
}

echo "[1/8] Sincronizando latest.txt"

sync_latest web
sync_latest lan
sync_latest threat
sync_latest detection
sync_latest correlation
sync_latest redteam

echo
echo "[2/8] Corrigindo permissões"

chmod -R 755 "$CYBERLAB_BIN" 2>/dev/null || true
chmod -R 755 "$CYBERLAB_CORE" 2>/dev/null || true
chmod -R 755 "$CYBERLAB_MODULES" 2>/dev/null || true
chmod -R 755 "$CYBERLAB_UI" 2>/dev/null || true
chmod -R 755 "$CYBERLAB_WEB" 2>/dev/null || true

echo "[OK] Permissões corrigidas"

echo
echo "[3/8] Validando arquivos principais"

FILES=(
  "$CYBERLAB_BIN/cyberlab"
  "$CYBERLAB_CORE/bootstrap.sh"
  "$CYBERLAB_WEB/dashboard.py"
  "$CYBERLAB_UI/menu.sh"
  "$CYBERLAB_UI/monitor.sh"
)

for f in "${FILES[@]}"; do
  if [ -f "$f" ]; then
    echo "[OK] $f"
  else
    echo "[MISS] $f"
  fi
done

echo
echo "[4/8] Validando módulos"

MODULE_FILES=(
  "$CYBERLAB_MODULES/web/web-scan.sh"
  "$CYBERLAB_MODULES/lan/lan-scan.sh"
  "$CYBERLAB_MODULES/threat/threat-engine.sh"
  "$CYBERLAB_MODULES/detection/detection-engine.sh"
  "$CYBERLAB_MODULES/correlation/correlation.sh"
  "$CYBERLAB_MODULES/redteam/redteam.sh"
  "$CYBERLAB_MODULES/core/labup.sh"
  "$CYBERLAB_MODULES/core/sync.sh"
)

for f in "${MODULE_FILES[@]}"; do
  if [ -f "$f" ]; then
    echo "[OK] $f"
  else
    echo "[MISS] $f"
  fi
done

echo
echo "[5/8] Limpando temporários"

find "$CYBERLAB_HOME" -name "*.tmp" -delete 2>/dev/null || true
find "$CYBERLAB_HOME" -name "*.cache" -delete 2>/dev/null || true
find "$CYBERLAB_HOME" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

echo "[OK] Limpeza concluída"

echo
echo "[6/8] Validando JSON"

find "$CYBERLAB_RESULTS" "$CYBERLAB_CLIENTS" -name "*.json" 2>/dev/null | while read -r j; do
  if jq empty "$j" >/dev/null 2>&1; then
    echo "[OK] $j"
  else
    echo "[BROKEN] $j"
  fi
done

echo
echo "[7/8] Verificando dashboard"

if pgrep -f "$CYBERLAB_WEB/dashboard.py" >/dev/null 2>&1; then
  echo "[OK] Dashboard ativo"
else
  echo "[INFO] Dashboard parado"
fi

echo
echo "[8/8] Finalizado"

echo
echo "SYNC FINALIZADO"
echo
