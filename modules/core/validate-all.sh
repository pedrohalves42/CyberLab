#!/bin/bash

source "$HOME/CyberLab/core/bootstrap.sh"

echo "==== CYBERLAB VALIDATE ALL ===="

FAIL=0

check_file() {
  [ -f "$1" ] && echo "[OK] $1" || { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }
}

check_dir() {
  [ -d "$1" ] && echo "[OK] $1" || { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }
}

echo
echo "[Diretórios]"
for d in "$CYBERLAB_HOME" "$CYBERLAB_BIN" "$CYBERLAB_CORE" "$CYBERLAB_MODULES" "$CYBERLAB_RESULTS" "$CYBERLAB_CONFIG" "$CYBERLAB_CLIENTS" "$CYBERLAB_LOGS" "$CYBERLAB_STATE"; do
  check_dir "$d"
done

echo
echo "[Arquivos essenciais]"
check_file "$CYBERLAB_CORE/bootstrap.sh"
check_file "$CYBERLAB_BIN/cyberlab"
check_file "$CYBERLAB_MODULES/core/sync-all.sh"
check_file "$CYBERLAB_MODULES/core/validate-all.sh"

echo
echo "[Comandos mapeados]"
for cmd in status sync sync-all validate-all health tools labup client web lan threat detect correlate redteam dashboard monitor menu intelligence risk findings assets timeline analytics remediation delivery report cleanup-obsolete cleanup-status audit-context context block16 client-audit-final-approved client-final-polish block17-4c1 client-final-delivery block17-final block17 audit recon deliver maintain lab; do
  if grep -Eq "^[[:space:]]*([^#[:space:]]+\|)*${cmd}(\|[^)]*)?\)" "$CYBERLAB_BIN/cyberlab"; then
    echo "[OK/MAP] cyberlab $cmd"
  else
    echo "[WARN] não mapeado: cyberlab $cmd"
  fi
done

echo
echo "[Ferramentas]"
for t in nmap curl jq python3 git dig whois tmux docker nuclei subfinder httpx katana naabu; do
  command -v "$t" >/dev/null 2>&1 && echo "[OK] $t" || echo "[MISS] $t"
done

echo
echo "[JSON]"
find "$CYBERLAB_HOME" \
    \( -path "$CYBERLAB_HOME/quarantine" -o -path "$CYBERLAB_HOME/tools/wordlists" \) -prune -o \
    -name "*.json" -type f -print 2>/dev/null | while read -r j; do
    jq empty "$j" >/dev/null 2>&1 && echo "[OK] $j" || echo "[BROKEN] $j"
done

echo "[Resumo]"
[ "$FAIL" -eq 0 ] && echo "[OK] Estrutura validada" || echo "[WARN] Falhas estruturais: $FAIL"

echo "[OK/MAP] cyberlab intelligence-pipeline"
