#!/bin/bash

source "$HOME/CyberLab/core/bootstrap.sh"

SCAN_DIR="$1"

if [ -z "$SCAN_DIR" ]; then
  echo "Uso: risk-engine.sh /caminho/do/scan"
  exit 1
fi

if [ ! -d "$SCAN_DIR" ]; then
  echo "[ERRO] pasta não encontrada: $SCAN_DIR"
  exit 1
fi

OUT="$SCAN_DIR/09-report"
JSON="$SCAN_DIR/10-json"
mkdir -p "$OUT" "$JSON"

ANALYSIS="$OUT/risk-analysis.md"
MATRIX="$OUT/risk-matrix.tsv"
SUMMARY="$JSON/risk-summary.json"

HEADERS="$SCAN_DIR/06-headers/headers.txt"
PORTS="$SCAN_DIR/03-ports/nmap-fast.txt"
SERVICES="$SCAN_DIR/03-ports/nmap-services.txt"
JUICY="$SCAN_DIR/05-crawl/juicy.txt"
JS_SUSPECT="$SCAN_DIR/08-evidence/js-suspect.txt"
JS_ENDPOINTS="$SCAN_DIR/08-evidence/js-endpoints.txt"
NUCLEI="$SCAN_DIR/07-vulns/nuclei.txt"

score=0
low=0
medium=0
high=0
critical=0

add_finding() {
  risk="$1"
  category="$2"
  item="$3"
  evidence="$4"
  impact="$5"
  recommendation="$6"

  echo -e "$risk\t$category\t$item\t$evidence\t$impact\t$recommendation" >> "$MATRIX"

  case "$risk" in
    LOW)
      low=$((low+1))
      score=$((score+3))
      ;;
    MEDIUM)
      medium=$((medium+1))
      score=$((score+10))
      ;;
    HIGH)
      high=$((high+1))
      score=$((score+25))
      ;;
    CRITICAL)
      critical=$((critical+1))
      score=$((score+60))
      ;;
  esac
}

init_matrix() {
  echo -e "RISCO\tCATEGORIA\tITEM\tEVIDÊNCIA\tIMPACTO\tRECOMENDAÇÃO" > "$MATRIX"
}

analyze_headers() {
  [ ! -f "$HEADERS" ] && return

  grep -qi "Strict-Transport-Security" "$HEADERS" || \
    add_finding "MEDIUM" "HEADER" "HSTS ausente" "Strict-Transport-Security não encontrado" "Pode permitir downgrade/uso inseguro em cenários específicos." "Aplicar HSTS com max-age adequado."

  grep -qi "Content-Security-Policy" "$HEADERS" || \
    add_finding "MEDIUM" "HEADER" "CSP ausente" "Content-Security-Policy não encontrado" "Aumenta impacto de XSS e injeção de conteúdo." "Definir uma Content-Security-Policy compatível com o site."

  grep -qi "X-Frame-Options" "$HEADERS" || \
    add_finding "LOW" "HEADER" "X-Frame-Options ausente" "Header não encontrado" "Pode permitir clickjacking em páginas sensíveis." "Aplicar X-Frame-Options ou frame-ancestors via CSP."

  grep -qi "X-Content-Type-Options" "$HEADERS" || \
    add_finding "LOW" "HEADER" "X-Content-Type-Options ausente" "Header não encontrado" "Pode permitir MIME sniffing." "Aplicar X-Content-Type-Options: nosniff."

  grep -qi "Referrer-Policy" "$HEADERS" || \
    add_finding "LOW" "HEADER" "Referrer-Policy ausente" "Header não encontrado" "Pode expor URLs internas ou parâmetros em referências." "Aplicar Referrer-Policy restritiva."

  grep -qi "Permissions-Policy" "$HEADERS" || \
    add_finding "LOW" "HEADER" "Permissions-Policy ausente" "Header não encontrado" "Navegador pode permitir APIs desnecessárias por padrão." "Definir Permissions-Policy mínima."
}

analyze_ports() {
  [ ! -f "$PORTS" ] && return

  while read -r line; do
    echo "$line" | grep -q " open " || continue

    port="$(echo "$line" | awk '{print $1}')"
    service="$(echo "$line" | awk '{print $3}')"

    case "$port" in
      21/tcp|23/tcp|25/tcp|110/tcp|143/tcp)
        add_finding "HIGH" "PORTA" "$port" "$line" "Serviço legado ou sensível exposto." "Validar necessidade, restringir por firewall/VPN ou remover exposição."
        ;;
      22/tcp|3389/tcp|5900/tcp)
        add_finding "HIGH" "PORTA" "$port" "$line" "Serviço administrativo exposto." "Restringir acesso por VPN/IP permitido, MFA e hardening."
        ;;
      8080/tcp|8000/tcp|8443/tcp|3000/tcp|5000/tcp|9000/tcp)
        add_finding "MEDIUM" "PORTA" "$port" "$line" "Porta alternativa pode indicar painel, proxy ou ambiente não endurecido." "Validar serviço, autenticação e necessidade da exposição."
        ;;
      80/tcp|443/tcp)
        add_finding "LOW" "PORTA" "$port" "$line" "Serviço web público esperado." "Manter monitoramento, headers e WAF configurados."
        ;;
      *)
        add_finding "LOW" "PORTA" "$port" "$line" "Serviço exposto identificado." "Validar necessidade e reduzir superfície."
        ;;
    esac
  done < "$PORTS"
}

analyze_juicy() {
  [ ! -f "$JUICY" ] && return

  while read -r url; do
    [ -z "$url" ] && continue

    if echo "$url" | grep -Eiq 'debug|internal|super-admin|admin|backup|config|\.env|secret'; then
      add_finding "HIGH" "ENDPOINT" "$url" "Endpoint sensível encontrado no crawl" "Pode indicar rota administrativa, debug ou arquivo sensível." "Validar autenticação, autorização e remoção se não for necessário."
    elif echo "$url" | grep -Eiq 'login|auth|token|api|graphql|swagger|openapi'; then
      add_finding "MEDIUM" "ENDPOINT" "$url" "Endpoint relevante encontrado" "Pode ampliar superfície de autenticação/API." "Validar controles de acesso, rate limit e exposição pública."
    else
      add_finding "LOW" "ENDPOINT" "$url" "Endpoint priorizado pelo padrão" "Endpoint pode merecer revisão manual." "Validar necessidade e comportamento."
    fi
  done < "$JUICY"
}

analyze_js() {
  [ -f "$JS_SUSPECT" ] || return

  while read -r js; do
    [ -z "$js" ] && continue
    add_finding "HIGH" "JAVASCRIPT" "$js" "Indicadores sensíveis no JavaScript" "Pode existir exposição de chaves, tokens, URLs internas ou integrações." "Revisar bundle JS e remover segredos do frontend."
  done < "$JS_SUSPECT"

  if [ -f "$JS_ENDPOINTS" ]; then
    count="$(wc -l < "$JS_ENDPOINTS" 2>/dev/null || echo 0)"
    if [ "$count" -gt 20 ]; then
      add_finding "MEDIUM" "JAVASCRIPT" "Muitos endpoints em JS" "$count endpoints extraídos" "A aplicação expõe grande mapa de rotas no frontend." "Classificar endpoints e validar autorização."
    fi
  fi
}

analyze_nuclei() {
  [ ! -f "$NUCLEI" ] && return

  while read -r line; do
    [ -z "$line" ] && continue

    if echo "$line" | grep -Eiq '\[critical\]'; then
      add_finding "CRITICAL" "NUCLEI" "$line" "Achado crítico por template" "Possível vulnerabilidade crítica ou exposição severa." "Validar manualmente com prioridade máxima."
    elif echo "$line" | grep -Eiq '\[high\]'; then
      add_finding "HIGH" "NUCLEI" "$line" "Achado alto por template" "Possível vulnerabilidade de alto impacto." "Validar manualmente e corrigir rapidamente."
    elif echo "$line" | grep -Eiq '\[medium\]'; then
      add_finding "MEDIUM" "NUCLEI" "$line" "Achado médio por template" "Possível configuração fraca ou exposição." "Validar e corrigir conforme impacto."
    elif echo "$line" | grep -Eiq '\[low\]'; then
      add_finding "LOW" "NUCLEI" "$line" "Achado baixo por template" "Sinal informativo ou baixa severidade." "Validar em rotina normal."
    else
      add_finding "LOW" "NUCLEI" "$line" "Achado sem severidade explícita" "Pode ser informativo." "Validar manualmente."
    fi
  done < "$NUCLEI"
}

level_from_score() {
  if [ "$score" -ge 160 ]; then
    echo "CRÍTICO"
  elif [ "$score" -ge 90 ]; then
    echo "ALTO"
  elif [ "$score" -ge 40 ]; then
    echo "MÉDIO"
  else
    echo "BAIXO"
  fi
}

generate_analysis() {
  level="$(level_from_score)"

  cat > "$SUMMARY" <<JSON
{
  "score": $score,
  "level": "$level",
  "findings": {
    "low": $low,
    "medium": $medium,
    "high": $high,
    "critical": $critical
  },
  "scan_dir": "$SCAN_DIR",
  "generated_at": "$(date)"
}
JSON

  cat > "$ANALYSIS" <<MD
# CyberLab Risk Analysis

**Pasta:** $SCAN_DIR  
**Data:** $(date)  

## Risco Geral

- Score: $score
- Nível: $level

## Achados por severidade

- LOW: $low
- MEDIUM: $medium
- HIGH: $high
- CRITICAL: $critical

## Top Prioridades

\`\`\`
$(tail -n +2 "$MATRIX" | grep -E '^CRITICAL|^HIGH|^MEDIUM' | head -20)
\`\`\`

## Plano de Validação Manual

1. Confirmar status HTTP dos endpoints sensíveis.
2. Verificar se `/admin`, `/login`, `/api`, `/debug`, `/internal` exigem autenticação.
3. Revisar portas alternativas e serviços administrativos.
4. Conferir headers de segurança ausentes.
5. Validar achados do Nuclei manualmente, sem exploração agressiva.
6. Corrigir prioridades altas e médias.
7. Reexecutar o CyberLab para comparar score.

## Matriz Técnica

Arquivo gerado:

\`$MATRIX\`
MD

  echo "[✓] Risk analysis: $ANALYSIS"
  echo "[✓] Risk matrix: $MATRIX"
  echo "[✓] Risk summary: $SUMMARY"
}

init_matrix
analyze_headers
analyze_ports
analyze_juicy
analyze_js
analyze_nuclei
generate_analysis
