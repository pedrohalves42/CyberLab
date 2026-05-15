#!/bin/bash

source "$HOME/CyberLab/core/bootstrap.sh"

while true; do
  clear
  echo "==== CYBERLAB MONITOR ===="
  echo
  echo "Data:   $(date)"
  echo "Host:   $(hostname)"
  echo "Kernel: $(uname -r)"
  echo

  echo "==== Rede ===="
  ip -brief addr
  echo

  echo "==== Último Web Scan ===="
  latest="$(cat "$CYBERLAB_RESULTS/web/latest.txt" 2>/dev/null)"

  if [ -n "$latest" ]; then
    echo "$latest"
    echo

    if [ -f "$latest/10-json/risk-summary.json" ]; then
      cat "$latest/10-json/risk-summary.json"
    else
      echo "Sem risk-summary ainda."
    fi
  else
    echo "Nenhum scan web ainda."
  fi

  echo
  echo "==== Último Detection ===="
  det_latest="$(cat "$CYBERLAB_RESULTS/detection/latest.txt" 2>/dev/null)"
  [ -n "$det_latest" ] && echo "$det_latest" && cat "$det_latest/json/detection-summary.json" 2>/dev/null || echo "Nenhum detection ainda."
  echo

  echo "==== Último Threat Intel ===="
  threat_latest="$(cat "$CYBERLAB_RESULTS/threat/latest.txt" 2>/dev/null)"
  [ -n "$threat_latest" ] && echo "$threat_latest" && cat "$threat_latest/json/threat-summary.json" 2>/dev/null || echo "Nenhum threat ainda."
  echo

  echo "==== Último Correlation ===="
  corr_latest="$(cat "$CYBERLAB_RESULTS/correlation/latest.txt" 2>/dev/null)"
  [ -n "$corr_latest" ] && echo "$corr_latest" && cat "$corr_latest/json/correlation-summary.json" 2>/dev/null || echo "Nenhum correlation ainda."
  echo

  echo "==== Último LAN Scan ===="
  lan_latest="$(cat "$CYBERLAB_RESULTS/lan/latest.txt" 2>/dev/null)"

  if [ -n "$lan_latest" ]; then
    echo "$lan_latest"
  else
    echo "Nenhum scan LAN ainda."
  fi

  sleep 10
done
