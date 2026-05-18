#!/bin/bash

source "${CYBERLAB_HOME:-$HOME/CyberLab}/core/bootstrap.sh"

info "Iniciando instalação base"

echo "==== CYBERLAB INSTALL BASE ===="

sudo apt update

sudo apt install -y \
  bash zsh git curl wget unzip jq \
  python3 python3-pip python3-venv python3-dev \
  build-essential \
  nmap whois dnsutils net-tools iputils-ping \
  tmux dialog \
  docker.io docker-compose-plugin \
  arp-scan \
  gobuster whatweb nikto wafw00f hydra \
  masscan parallel \
  libssl-dev libffi-dev libxml2-dev libxslt1-dev zlib1g-dev

echo
echo "[+] Instalando ferramentas Go, se Go estiver disponível..."

if command -v go >/dev/null 2>&1; then
  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  go install github.com/projectdiscovery/httpx/cmd/httpx@latest
  go install github.com/projectdiscovery/katana/cmd/katana@latest
  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

  if ! grep -q 'go/bin' "$HOME/.zshrc" 2>/dev/null; then
    echo 'export PATH="$PATH:$HOME/go/bin"' >> "$HOME/.zshrc"
  fi

  export PATH="$PATH:$HOME/go/bin"
else
  warn "Go não encontrado. Ferramentas ProjectDiscovery não foram instaladas."
  echo "[WARN] Instale Go depois para subfinder/httpx/katana/nuclei/naabu."
fi

info "Instalação base finalizada"

echo
check_tools
