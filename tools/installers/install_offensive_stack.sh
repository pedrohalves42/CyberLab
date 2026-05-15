#!/bin/bash
set -u

LOG="$HOME/CyberLab/tools/logs/install_offensive_stack_$(date +%Y%m%d_%H%M%S).log"

mkdir -p "$HOME/CyberLab/tools/logs" "$HOME/CyberLab/tools/bin"

exec > >(tee -a "$LOG") 2>&1

echo "============================================================"
echo " CyberLab - Offensive Tools Installer Controlado"
echo "============================================================"
echo " Log: $LOG"
echo " Modo: instalação de ferramentas para lab autorizado"
echo "============================================================"
echo ""

echo "[1/8] Atualizando sistema..."
sudo apt update

echo ""
echo "[2/8] Instalando dependências base..."
sudo apt install -y \
  curl wget git unzip zip tar ca-certificates gnupg lsb-release \
  software-properties-common apt-transport-https \
  build-essential make gcc g++ pkg-config cmake \
  python3 python3-pip python3-venv python3-dev \
  ruby ruby-dev gem \
  golang-go \
  default-jre default-jdk \
  postgresql postgresql-contrib libpq-dev \
  libxml2-dev libxslt1-dev zlib1g-dev libssl-dev libffi-dev \
  libpcap-dev libusb-1.0-0-dev \
  openjdk-17-jre openjdk-17-jdk \
  snapd flatpak \
  xterm tmux screen jq

echo ""
echo "[3/8] Instalando ferramentas via apt quando disponíveis..."

sudo apt install -y \
  nmap \
  hydra \
  sqlmap \
  ffuf \
  gobuster \
  nikto \
  wapiti \
  wireshark \
  aircrack-ng \
  bettercap \
  ettercap-text-only \
  john \
  hashcat \
  set \
  setoolkit \
  zaproxy \
  burpsuite \
  armitage \
  metasploit-framework || true

echo ""
echo "[4/8] Fallback Go para ffuf/gobuster se necessário..."

export PATH="$PATH:$HOME/go/bin"

if ! command -v ffuf >/dev/null 2>&1; then
  echo "[INFO] Instalando ffuf via Go..."
  go install github.com/ffuf/ffuf/v2@latest || true
fi

if ! command -v gobuster >/dev/null 2>&1; then
  echo "[INFO] Instalando gobuster via Go..."
  go install github.com/OJ/gobuster/v3@latest || true
fi

if ! grep -q 'HOME/go/bin' "$HOME/.zshrc" 2>/dev/null; then
  echo 'export PATH="$PATH:$HOME/go/bin"' >> "$HOME/.zshrc"
fi

if ! grep -q 'HOME/go/bin' "$HOME/.bashrc" 2>/dev/null; then
  echo 'export PATH="$PATH:$HOME/go/bin"' >> "$HOME/.bashrc"
fi

echo ""
echo "[5/8] Fallback Ruby para WPScan se necessário..."

if ! command -v wpscan >/dev/null 2>&1; then
  echo "[INFO] Instalando wpscan via gem..."
  sudo gem install wpscan || true
fi

echo ""
echo "[6/8] Instalando Metasploit via instalador oficial se necessário..."

if ! command -v msfconsole >/dev/null 2>&1; then
  echo "[INFO] Metasploit não encontrado. Instalando via msfinstall..."
  curl https://raw.githubusercontent.com/rapid7/metasploit-framework/master/msfinstall | sudo bash || true
fi

echo ""
echo "[7/8] PostgreSQL para Metasploit..."

sudo systemctl enable postgresql || true
sudo systemctl start postgresql || true

if command -v msfdb >/dev/null 2>&1; then
  msfdb init || true
fi

echo ""
echo "[8/8] Criando verificador de ferramentas..."

cat > "$HOME/CyberLab/tools/offensive_tools_check.sh" << 'SH'
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
check_tool set "set --help"
check_tool msfconsole "msfconsole --version"
check_tool armitage "armitage --help"
check_tool zaproxy "zaproxy -version"
check_tool zap.sh "zap.sh -version"
check_tool burpsuite "burpsuite --help"

echo "============================================================"
echo " Observação:"
echo " Burp e ZAP podem estar instalados como aplicativos gráficos,"
echo " então nem sempre aparecem com comando simples no PATH."
echo "============================================================"
SH

chmod +x "$HOME/CyberLab/tools/offensive_tools_check.sh"

echo ""
echo "============================================================"
echo " Instalação finalizada"
echo "============================================================"
echo " Rode:"
echo "   ~/CyberLab/tools/offensive_tools_check.sh"
echo ""
echo " Log:"
echo "   $LOG"
echo "============================================================"
