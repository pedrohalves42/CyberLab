#!/bin/bash

tools_file="$CYBERLAB_CONFIG/tools.list"

check_tool() {
  tool="$1"

  if command -v "$tool" >/dev/null 2>&1; then
    echo "[OK] $tool"
    return 0
  else
    echo "[MISS] $tool"
    return 1
  fi
}

check_tools() {
  echo "==== CYBERLAB TOOLS CHECK ===="

  missing=0

  while read -r tool; do
    [[ -z "$tool" ]] && continue
    [[ "$tool" =~ ^# ]] && continue

    if ! check_tool "$tool"; then
      missing=$((missing+1))
    fi
  done < "$tools_file"

  echo

  if [ "$missing" -eq 0 ]; then
    echo "[✓] Todas as ferramentas principais encontradas."
    return 0
  else
    echo "[!] Faltando $missing ferramenta(s)."
    return 1
  fi
}

tool_path() {
  tool="$1"

  if command -v "$tool" >/dev/null 2>&1; then
    command -v "$tool"
  else
    echo "[MISS] $tool"
    return 1
  fi
}

tools_versions() {
  echo "==== CYBERLAB TOOLS VERSIONS ===="

  echo
  echo "[nmap]"
  nmap --version 2>/dev/null | head -1 || true

  echo
  echo "[gobuster]"
  gobuster version 2>/dev/null || gobuster --version 2>/dev/null || true

  echo
  echo "[nuclei]"
  nuclei -version 2>/dev/null || true

  echo
  echo "[subfinder]"
  subfinder -version 2>/dev/null || true

  echo
  echo "[httpx]"
  httpx -version 2>/dev/null || true

  echo
  echo "[katana]"
  katana -version 2>/dev/null || true

  echo
  echo "[naabu]"
  naabu -version 2>/dev/null || true

  echo
  echo "[python]"
  python3 --version 2>/dev/null || true

  echo
  echo "[docker]"
  docker --version 2>/dev/null || true
}
