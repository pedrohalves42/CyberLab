#!/bin/bash

echo "============================================================"
echo " CyberLab - Offensive Tools Check"
echo "============================================================"

check_tool() {
  local tool="$1"
  local version_cmd="$2"

  if command -v "$tool" >/dev/null 2>&1; then
    echo "[OK] $tool -> $(command -v "$tool")"
    if [ -n "$version_cmd" ]; then
      bash -lc "$version_cmd" 2>/dev/null | head -n 2 || true
    fi
    echo ""
  else
    echo "[FALTA] $tool"
    echo ""
  fi
}

check_tool nmap "nmap --version"
check_tool hydra "hydra -h"
check_tool sqlmap "sqlmap --version"
check_tool ffuf "ffuf -V"
check_tool gobuster "gobuster version"
check_tool nikto "nikto -Version"
check_tool wapiti "wapiti --version"
check_tool wireshark "wireshark --version"
check_tool tshark "tshark --version"
check_tool aircrack-ng "aircrack-ng --help"
check_tool bettercap "bettercap -version"
check_tool ettercap "ettercap --version"
check_tool john "john --list=build-info"
check_tool hashcat "hashcat --version"
check_tool setoolkit "setoolkit --help"
check_tool msfconsole "msfconsole --version"
if command -v armitage >/dev/null 2>&1; then
  echo "[OK] armitage -> $(command -v armitage)"
  armitage --help 2>/dev/null | head -n 2 || true
  echo ""
else
  echo "[OPCIONAL] armitage não instalado. Metasploit/msfconsole já está disponível."
  echo ""
fi
check_tool zaproxy "zaproxy -version"
check_tool zap.sh "zap.sh -version"
check_tool burpsuite "burpsuite --help"

echo "============================================================"
echo " Observação:"
echo " Burp e ZAP podem estar instalados como aplicativos gráficos,"
echo " então nem sempre aparecem com comando simples no PATH."
echo "============================================================"
