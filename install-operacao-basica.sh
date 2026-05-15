#!/bin/bash
set -e

BASE="$HOME/CyberLab"

echo "==== CYBERLAB OPERAÇÃO BÁSICA CLEAN ===="

mkdir -p "$BASE"/{bin,core,clients,config,data,logs,modules,reports,results,state,tmp,ui,web}
mkdir -p "$BASE/state/intelligence"
mkdir -p "$BASE/results/web" "$BASE/results/threat" "$BASE/results/detection" "$BASE/results/correlation" "$BASE/results/redteam"
mkdir -p "$BASE/data/policies"

chmod -R u+rwX "$BASE"

echo "[OK] Estrutura básica validada"
echo "[OK] Sem arquivos versionados legados"
