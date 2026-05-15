#!/bin/bash

set -u

source "$HOME/CyberLab/core/bootstrap.sh"

LOG="$HOME/CyberLab/logs/labup.log"
STATE="$HOME/CyberLab/state/lab.state"

mkdir -p "$HOME/CyberLab/logs" "$HOME/CyberLab/state"

exec > >(tee -a "$LOG") 2>&1

echo
echo "========================================"
echo " CYBERLAB LABUP ENGINE"
echo "========================================"
echo "Data:   $(date)"
echo "User:   $USER"
echo "Host:   $(hostname)"
echo "Kernel: $(uname -r)"
echo

echo "[1/10] Validando estrutura"

mkdir -p \
  "$CYBERLAB_HOME" \
  "$CYBERLAB_BIN" \
  "$CYBERLAB_CORE" \
  "$CYBERLAB_MODULES" \
  "$CYBERLAB_RESULTS" \
  "$CYBERLAB_CONFIG" \
  "$CYBERLAB_CLIENTS" \
  "$CYBERLAB_LOGS" \
  "$CYBERLAB_WEB" \
  "$CYBERLAB_UI" \
  "$HOME/CyberLab/results/web" \
  "$HOME/CyberLab/results/lan" \
  "$HOME/CyberLab/results/threat" \
  "$HOME/CyberLab/results/detection" \
  "$HOME/CyberLab/results/correlation" \
  "$HOME/CyberLab/results/redteam"

touch "$CYBERLAB_CONFIG/scope.txt"
touch "$CYBERLAB_LOGS/cyberlab.log"

echo "[OK] Estrutura"

echo
echo "[2/10] Corrigindo permissões"

chmod -R 755 "$CYBERLAB_BIN" 2>/dev/null || true
chmod -R 755 "$CYBERLAB_CORE" 2>/dev/null || true
chmod -R 755 "$CYBERLAB_MODULES" 2>/dev/null || true
chmod -R 755 "$CYBERLAB_UI" 2>/dev/null || true
chmod -R 755 "$CYBERLAB_WEB" 2>/dev/null || true

echo "[OK] Permissões"

echo
echo "[3/10] Ferramentas principais"

TOOLS=(
  bash
  zsh
  git
  curl
  wget
  jq
  python3
  pip3
  nmap
  whois
  dig
  tmux
  docker
  arp-scan
  gobuster
  whatweb
  nikto
  wafw00f
  nuclei
  subfinder
  httpx
  katana
  naabu
)

MISS=0

for t in "${TOOLS[@]}"; do
  if command -v "$t" >/dev/null 2>&1; then
    echo "[OK] $t"
  else
    echo "[MISS] $t"
    MISS=$((MISS+1))
  fi
done

echo
echo "[4/10] Rede"

ip -brief addr || true
echo
ip route || true

echo
echo "[5/10] DNS"

if dig google.com +short >/dev/null 2>&1; then
  echo "[OK] DNS externo"
else
  echo "[WARN] DNS externo falhou"
fi

echo
echo "[6/10] APT"

if ls /var/lib/apt/lists/lock >/dev/null 2>&1; then
  echo "[INFO] Lock APT existe. Normal se nenhum apt estiver rodando."
fi

if pgrep -fa "apt|dpkg|mint-refresh" >/dev/null 2>&1; then
  echo "[WARN] Processo apt/dpkg/mint-refresh ativo:"
  pgrep -fa "apt|dpkg|mint-refresh" || true
else
  echo "[OK] Nenhum processo apt/dpkg ativo"
fi

echo
echo "[7/10] Dashboard"

if pgrep -f "$CYBERLAB_WEB/dashboard.py" >/dev/null 2>&1; then
  echo "[OK] Dashboard ativo"
else
  echo "[INFO] Dashboard parado"
fi

echo
echo "[8/10] Latest files"

for d in web lan threat detection correlation redteam; do
  mkdir -p "$CYBERLAB_RESULTS/$d"
  if [ -f "$CYBERLAB_RESULTS/$d/latest.txt" ]; then
    echo "[OK] latest $d: $(cat "$CYBERLAB_RESULTS/$d/latest.txt" 2>/dev/null)"
  else
    echo "[INFO] latest $d ainda não existe"
  fi
done

echo
echo "[9/10] Clientes"

if [ -d "$CYBERLAB_CLIENTS" ]; then
  find "$CYBERLAB_CLIENTS" -maxdepth 2 -name client.json -print 2>/dev/null || true
else
  echo "[INFO] Sem clientes ainda"
fi

echo
echo "[10/10] Salvando estado"

cat > "$STATE" <<EOFSTATE
LABUP_DATE="$(date)"
HOSTNAME="$(hostname)"
KERNEL="$(uname -r)"
USER="$USER"
MISSING_TOOLS="$MISS"
CYBERLAB_HOME="$CYBERLAB_HOME"
EOFSTATE

echo "[OK] Estado salvo em: $STATE"
echo
echo "========================================"
echo " CYBERLAB READY"
echo "========================================"
echo "Dashboard: http://127.0.0.1:9088"
echo "Log: $LOG"
echo
