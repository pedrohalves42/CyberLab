#!/bin/bash

source "$HOME/CyberLab/core/bootstrap.sh"

SCAN_DIR="$1"

if [ "$SCAN_DIR" = "latest" ] || [ -z "$SCAN_DIR" ]; then
  SCAN_DIR="$(cat "$CYBERLAB_RESULTS/web/latest.txt" 2>/dev/null)"
fi

if [ -z "$SCAN_DIR" ] || [ ! -d "$SCAN_DIR" ]; then
  echo "[ERRO] Nenhum scan web encontrado."
  exit 1
fi

OUT="$CYBERLAB_RESULTS/detection/detection-$(timestamp)"
mkdir -p "$OUT"/{events,rules,json,report}

REPORT="$OUT/report/detection-report.md"
JSON="$OUT/json/detection-summary.json"
EVENTS="$OUT/events/events.tsv"

HEADERS="$SCAN_DIR/06-headers/headers.txt"
JUICY="$SCAN_DIR/05-crawl/juicy.txt"
NUCLEI="$SCAN_DIR/07-vulns/nuclei.txt"
PORTS="$SCAN_DIR/03-ports/nmap-fast.txt"
JS_SUSPECT="$SCAN_DIR/08-evidence/js-suspect.txt"

echo -e "SEVERIDADE\tTIPO\tEVIDÊNCIA\tREGRA\tAÇÃO_RECOMENDADA" > "$EVENTS"

add_event() {
  sev="$1"
  type="$2"
  evidence="$3"
  rule="$4"
  action="$5"

  echo -e "$sev\t$type\t$evidence\t$rule\t$action" >> "$EVENTS"
}

echo "==== CYBERLAB DETECTION ENGINE ===="
echo "Scan: $SCAN_DIR"

if [ -f "$HEADERS" ]; then
  grep -iq '^content-security-policy:' "$HEADERS" || \
    add_event "MEDIUM" "HEADER" "CSP ausente" "WEB-HEADER-CSP-MISSING" "Criar alerta para ausência de CSP e aplicar política."

  grep -iq '^strict-transport-security:' "$HEADERS" || \
    add_event "MEDIUM" "HEADER" "HSTS ausente" "WEB-HEADER-HSTS-MISSING" "Aplicar HSTS e monitorar downgrade."

  grep -iq '^server:' "$HEADERS" && \
    add_event "LOW" "HEADER" "$(grep -i '^server:' "$HEADERS" | head -1)" "WEB-HEADER-SERVER-EXPOSED" "Reduzir exposição de tecnologia."
fi

if [ -f "$JUICY" ]; then
  while read -r url; do
    [ -z "$url" ] && continue

    if echo "$url" | grep -Eiq 'admin|debug|internal|config|backup|swagger|graphql'; then
      add_event "HIGH" "ENDPOINT" "$url" "WEB-SENSITIVE-ENDPOINT" "Alertar acesso e validar autenticação."
    elif echo "$url" | grep -Eiq 'login|api|auth|token'; then
      add_event "MEDIUM" "ENDPOINT" "$url" "WEB-AUTH-API-ENDPOINT" "Monitorar tentativas e aplicar rate limit."
    fi
  done < "$JUICY"
fi

if [ -f "$PORTS" ]; then
  grep ' open ' "$PORTS" | while read -r line; do
    port="$(echo "$line" | awk '{print $1}' | cut -d/ -f1)"

    case "$port" in
      22|3389|5900)
        add_event "HIGH" "PORT" "$line" "NET-ADMIN-PORT-EXPOSED" "Restringir por VPN/IP permitido."
        ;;
      8080|8443|9000|3000|5000)
        add_event "MEDIUM" "PORT" "$line" "NET-ALT-WEB-PORT" "Validar serviço e autenticação."
        ;;
    esac
  done
fi

if [ -f "$JS_SUSPECT" ]; then
  while read -r js; do
    [ -z "$js" ] && continue
    add_event "HIGH" "JAVASCRIPT" "$js" "WEB-JS-SENSITIVE-INDICATOR" "Revisar bundle e remover segredos."
  done < "$JS_SUSPECT"
fi

if [ -f "$NUCLEI" ]; then
  while read -r n; do
    [ -z "$n" ] && continue

    if echo "$n" | grep -iq '\[critical\]'; then
      add_event "CRITICAL" "NUCLEI" "$n" "VULN-CRITICAL-FINDING" "Validar imediatamente."
    elif echo "$n" | grep -iq '\[high\]'; then
      add_event "HIGH" "NUCLEI" "$n" "VULN-HIGH-FINDING" "Validar e corrigir com prioridade."
    fi
  done < "$NUCLEI"
fi

LOW="$(tail -n +2 "$EVENTS" | grep -c '^LOW' || true)"
MEDIUM="$(tail -n +2 "$EVENTS" | grep -c '^MEDIUM' || true)"
HIGH="$(tail -n +2 "$EVENTS" | grep -c '^HIGH' || true)"
CRITICAL="$(tail -n +2 "$EVENTS" | grep -c '^CRITICAL' || true)"

SCORE=$((LOW*2 + MEDIUM*8 + HIGH*20 + CRITICAL*60))
LEVEL="BAIXO"
[ "$SCORE" -ge 40 ] && LEVEL="MÉDIO"
[ "$SCORE" -ge 90 ] && LEVEL="ALTO"
[ "$SCORE" -ge 160 ] && LEVEL="CRÍTICO"

cat > "$JSON" <<JSON
{
  "scan_dir": "$SCAN_DIR",
  "score": $SCORE,
  "level": "$LEVEL",
  "events": {
    "low": $LOW,
    "medium": $MEDIUM,
    "high": $HIGH,
    "critical": $CRITICAL
  },
  "events_file": "$EVENTS",
  "generated_at": "$(date)"
}
JSON

cat > "$REPORT" <<MD
# CyberLab Detection Report

**Scan:** $SCAN_DIR  
**Data:** $(date)  

## Resumo

- Score: $SCORE
- Nível: $LEVEL
- LOW: $LOW
- MEDIUM: $MEDIUM
- HIGH: $HIGH
- CRITICAL: $CRITICAL

## Eventos

\`\`\`
$(cat "$EVENTS")
\`\`\`

## Recomendações

1. Criar alertas para endpoints sensíveis.
2. Monitorar acessos a rotas administrativas.
3. Criar regras para exposição de portas administrativas.
4. Alertar ausência de headers essenciais.
5. Correlacionar achados com logs do WAF/CDN.
6. Validar achados HIGH/CRITICAL manualmente.
MD

echo "$OUT" > "$CYBERLAB_RESULTS/detection/latest.txt"

echo "[✓] Detection report: $REPORT"
echo "[✓] Events: $EVENTS"
echo "[✓] JSON: $JSON"
