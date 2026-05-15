#!/bin/bash

source "$HOME/CyberLab/core/bootstrap.sh"

OUT="$CYBERLAB_RESULTS/redteam/redteam-$(timestamp)"
mkdir -p "$OUT"/{mitre,detections,emulation,report,json}

latest_web() {
  cat "$CYBERLAB_RESULTS/web/latest.txt" 2>/dev/null
}

redteam_profile() {
  echo "==== CYBERLAB RED TEAM PROFILE ===="
  echo
  echo "Modo: Emulação segura / Purple Team"
  echo "Permitido:"
  echo "- Recon controlado"
  echo "- Mapeamento MITRE"
  echo "- Checklist de detecção"
  echo "- Simulação local"
  echo "- Relatório defensivo"
  echo
  echo "Bloqueado:"
  echo "- Exploração real"
  echo "- Persistência"
  echo "- Roubo de credenciais"
  echo "- Bypass"
  echo "- Ataque fora de escopo"
}

redteam_lab_check() {
  echo "==== CYBERLAB RED TEAM LAB CHECK ===="
  echo

  cyberlab network status
  echo
  cyberlab tools
  echo
  cyberlab kernel risk

  cat > "$OUT/report/lab-check.md" <<MD
# Red Team Lab Check

Data: $(date)

## Status

Ambiente preparado para emulação controlada.

## Comandos usados

- cyberlab network status
- cyberlab tools
- cyberlab kernel risk
MD

  echo "[✓] Lab check salvo em: $OUT/report/lab-check.md"
}

redteam_mitre() {
  SCAN_DIR="${1:-$(latest_web)}"

  if [ -z "$SCAN_DIR" ] || [ ! -d "$SCAN_DIR" ]; then
    echo "[ERRO] Nenhum scan web encontrado."
    exit 1
  fi

  MATRIX="$SCAN_DIR/09-report/risk-matrix.tsv"
  MITRE="$OUT/mitre/mitre-map.tsv"
  MITRE_MD="$OUT/mitre/mitre-map.md"

  echo -e "RISCO\tCATEGORIA\tITEM\tMITRE_ID\tTÁTICA\tTÉCNICA\tOBJETIVO_DEFENSIVO" > "$MITRE"

  tail -n +2 "$MATRIX" 2>/dev/null | while IFS=$'\t' read -r risk category item evidence impact rec; do
    case "$category" in
      HEADER)
        echo -e "$risk\t$category\t$item\tT1595\tReconnaissance\tActive Scanning\tIdentificar exposição e endurecer cabeçalhos." >> "$MITRE"
        ;;
      PORTA)
        echo -e "$risk\t$category\t$item\tT1133\tInitial Access\tExternal Remote Services\tReduzir serviços expostos e restringir acesso." >> "$MITRE"
        ;;
      ENDPOINT)
        echo -e "$risk\t$category\t$item\tT1190\tInitial Access\tExploit Public-Facing Application\tValidar autenticação e autorização." >> "$MITRE"
        ;;
      JAVASCRIPT)
        echo -e "$risk\t$category\t$item\tT1593\tReconnaissance\tSearch Open Websites/Domains\tRemover segredos e reduzir vazamento de rotas." >> "$MITRE"
        ;;
      NUCLEI)
        echo -e "$risk\t$category\t$item\tT1595\tReconnaissance\tActive Scanning\tValidar achado e criar regra de detecção." >> "$MITRE"
        ;;
      *)
        echo -e "$risk\t$category\t$item\tT1595\tReconnaissance\tActive Scanning\tRevisar manualmente." >> "$MITRE"
        ;;
    esac
  done

  cat > "$MITRE_MD" <<MD
# CyberLab MITRE ATT&CK Mapping

**Data:** $(date)  
**Scan:** $SCAN_DIR  

## Matriz MITRE

\`\`\`
$(cat "$MITRE")
\`\`\`

## Uso defensivo

Este mapeamento ajuda a transformar achados técnicos em objetivos de detecção, hardening e priorização.
MD

  echo "$OUT" > "$CYBERLAB_RESULTS/redteam/latest.txt"
  echo "[✓] MITRE gerado: $MITRE_MD"
}

redteam_detection() {
  SCAN_DIR="${1:-$(latest_web)}"

  if [ -z "$SCAN_DIR" ] || [ ! -d "$SCAN_DIR" ]; then
    echo "[ERRO] Nenhum scan web encontrado."
    exit 1
  fi

  DET="$OUT/detections/detection-checklist.md"

  cat > "$DET" <<MD
# Detection Checklist — Purple Team

**Data:** $(date)  
**Scan:** $SCAN_DIR  

## Web / CDN / WAF

- [ ] Detectar aumento de requisições para endpoints administrativos.
- [ ] Alertar varredura de paths como /admin, /login, /api, /debug.
- [ ] Registrar bloqueios Cloudflare/WAF.
- [ ] Monitorar códigos 403, 404, 429 e 5xx anormais.
- [ ] Criar regra para User-Agent de scanners conhecidos.

## Servidor / Aplicação

- [ ] Logs HTTP centralizados.
- [ ] Rate limit em login/API.
- [ ] Alertas para erro de autenticação repetido.
- [ ] Alertas para acesso a rotas inexistentes em volume.
- [ ] Revisão de headers de segurança.

## Rede

- [ ] Detectar scan de portas interno.
- [ ] Monitorar conexões em portas administrativas.
- [ ] Validar exposição de portas alternativas.
- [ ] Separar rede de laboratório, clientes e operação.

## Resposta

- [ ] Playbook para falso positivo.
- [ ] Playbook para achado alto.
- [ ] Playbook para exposição crítica.
- [ ] Evidências preservadas.
MD

  echo "$OUT" > "$CYBERLAB_RESULTS/redteam/latest.txt"
  echo "[✓] Checklist gerado: $DET"
}

redteam_emulate_lab() {
  TARGET="${1:-localhost}"
  TARGET="$(clean_target "$TARGET")"

  if [[ "$TARGET" != "localhost" && "$TARGET" != "127.0.0.1" && ! "$TARGET" =~ ^192\.168\.1\. ]]; then
    echo "[BLOQUEADO] Emulação ativa somente em localhost ou LAN autorizada."
    exit 1
  fi

  EMU="$OUT/emulation/lab-emulation.md"

  echo "==== RED TEAM LAB EMULATION ===="
  echo "Target: $TARGET"
  echo

  {
    echo "# Red Team Lab Emulation"
    echo
    echo "Data: $(date)"
    echo "Target: $TARGET"
    echo
    echo "## Simulações seguras executadas"
    echo
    echo "### 1. Verificação HTTP leve"
    curl -I --max-time 5 "http://$TARGET" 2>&1 || true
    echo
    echo "### 2. Verificação HTTPS leve"
    curl -k -I --max-time 5 "https://$TARGET" 2>&1 || true
    echo
    echo "### 3. Scan discovery seguro"
    nmap -sn "$TARGET" 2>&1 || true
    echo
    echo "### 4. Teste de logging"
    echo "Evento simulado: acesso a rota administrativa fictícia /admin"
    echo "Evento simulado: acesso a rota API fictícia /api"
    echo
    echo "## Observação"
    echo "Nenhuma exploração foi executada. Apenas emulação defensiva e validação de visibilidade."
  } | tee "$EMU"

  echo "$OUT" > "$CYBERLAB_RESULTS/redteam/latest.txt"
  echo "[✓] Emulação salva: $EMU"
}

redteam_report() {

  # Gera automaticamente artefatos faltantes
  if [ ! -f "$OUT/mitre/mitre-map.md" ]; then
    redteam_mitre latest >/dev/null 2>&1 || true
  fi

  if [ ! -f "$OUT/detections/detection-checklist.md" ]; then
    redteam_detection latest >/dev/null 2>&1 || true
  fi

  LATEST_RT="$(cat "$CYBERLAB_RESULTS/redteam/latest.txt" 2>/dev/null)"

  if [ -z "$LATEST_RT" ] || [ ! -d "$LATEST_RT" ]; then
    echo "[ERRO] Nenhum resultado Red Team."
    exit 1
  fi

  mkdir -p "$LATEST_RT/report"

  REPORT="$LATEST_RT/report/redteam-report.md"

  cat > "$REPORT" <<MD
# CyberLab Red Team / Purple Team Report

**Data:** $(date)  
**Pasta:** $LATEST_RT  

## Objetivo

Executar emulação segura para transformar achados técnicos em melhoria defensiva.

## Artefatos

- MITRE map: \`mitre/mitre-map.md\`
- Detection checklist: \`detections/detection-checklist.md\`
- Lab emulation: \`emulation/lab-emulation.md\`

## Conclusão

A operação está limitada a ambiente próprio/autorizado, sem exploração destrutiva.
O foco é validação de controles, visibilidade, priorização e melhoria contínua.
MD

  echo "[✓] Relatório Red Team: $REPORT"
}

case "$1" in
  profile)
    redteam_profile
    ;;
  lab-check)
    redteam_lab_check
    ;;
  mitre)
    redteam_mitre "$2"
    ;;
  detection)
    redteam_detection "$2"
    ;;
  emulate)
    redteam_emulate_lab "$2"
    ;;
  report)
    redteam_report
    ;;
  latest)
    cat "$CYBERLAB_RESULTS/redteam/latest.txt" 2>/dev/null || echo "Nenhum resultado Red Team."
    ;;
  *)
    echo "Uso:"
    echo "  cyberlab redteam profile"
    echo "  cyberlab redteam lab-check"
    echo "  cyberlab redteam mitre latest"
    echo "  cyberlab redteam detection latest"
    echo "  cyberlab redteam emulate localhost"
    echo "  cyberlab redteam report"
    echo "  cyberlab redteam latest"
    ;;
esac
