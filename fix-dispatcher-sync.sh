#!/bin/bash

set -u

CYBER="$CYBERLAB_HOME/bin/cyberlab"

if [ ! -f "$CYBER" ]; then
  echo "[ERRO] bin/cyberlab não encontrado"
  exit 1
fi

cp "$CYBER" "$CYBER.bak.$(date +%s)"

cat > "$CYBER" <<'EOS'
#!/bin/bash

source "${CYBERLAB_HOME:-$HOME/CyberLab}/core/bootstrap.sh"

CMD="$1"
shift || true

case "$CMD" in

  help|"")
    echo
    echo "========================================"
    echo " CYBERLAB UNIFIED"
    echo "========================================"
    echo
    echo "Core:"
    echo "  cyberlab status"
    echo "  cyberlab sync-all"
    echo "  cyberlab validate-all"
    echo "  cyberlab health"
    echo
    echo "Clientes:"
    echo "  cyberlab client add"
    echo "  cyberlab client scan"
    echo
    echo "Scans:"
    echo "  cyberlab web"
    echo "  cyberlab lan"
    echo "  cyberlab threat"
    echo "  cyberlab detect"
    echo "  cyberlab correlate"
    echo "  cyberlab redteam"
    echo
    echo "Interface:"
    echo "  cyberlab dashboard"
    echo "  cyberlab monitor"
    echo "  cyberlab menu"
    echo
    exit 0
    ;;

  status)
    echo
    echo "==== CYBERLAB STATUS ===="
    echo "Home:   $CYBERLAB_HOME"
    echo "User:   $USER"
    echo "Host:   $(hostname)"
    echo "Kernel: $(uname -r)"
    echo
    ;;

  sync-all)
    bash "$CYBERLAB_MODULES/core/sync-all.sh"
    ;;

  validate-all)
    bash "$CYBERLAB_MODULES/core/validate-all.sh"
    ;;

  health)
    bash "$CYBERLAB_MODULES/health/health.sh" "$@"
    ;;

  web)
    bash "$CYBERLAB_MODULES/web/web-scan.sh" "$@"
    ;;

  lan)
    bash "$CYBERLAB_MODULES/lan/lan-scan.sh" "$@"
    ;;

  threat)
    bash "$CYBERLAB_MODULES/threat/threat-engine.sh" "$@"
    ;;

  detect)
    bash "$CYBERLAB_MODULES/detection/detection-engine.sh" "$@"
    ;;

  correlate)
    bash "$CYBERLAB_MODULES/correlation/correlation.sh" "$@"
    ;;

  redteam)
    bash "$CYBERLAB_MODULES/redteam/redteam.sh" "$@"
    ;;

  report)
    bash "$CYBERLAB_CORE/report.sh" "$@"
    ;;

  delivery)
    bash "$CYBERLAB_CORE/delivery.sh" "$@"
    ;;

  client)
    bash "$CYBERLAB_CORE/client.sh" "$@"
    ;;

  dashboard)
    python3 "$CYBERLAB_WEB/dashboard.py"
    ;;

  dashboard-start)
    nohup python3 "$CYBERLAB_WEB/dashboard.py" \
      > "$CYBERLAB_LOGS/dashboard.log" 2>&1 &
    echo "[OK] Dashboard iniciado"
    ;;

  menu)
    bash "$CYBERLAB_UI/menu.sh"
    ;;

  monitor)
    bash "$CYBERLAB_UI/monitor.sh"
    ;;

  labup)
    bash "$CYBERLAB_MODULES/core/labup.sh"
    ;;

  *)
    echo "[ERRO] comando desconhecido: $CMD"
    echo "Use: cyberlab help"
    exit 1
    ;;

esac
EOS

chmod +x "$CYBER"

echo
echo "[OK] Dispatcher central reconstruído"
echo
echo "Teste agora:"
echo
echo "source "${CYBERLAB_HOME:-$HOME/CyberLab}/core/bootstrap.sh""
echo "hash -r"
echo "cyberlab help"
echo "cyberlab sync-all"
echo "cyberlab validate-all"
echo
