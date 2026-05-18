#!/bin/bash

source "${CYBERLAB_HOME:-$HOME/CyberLab}/core/bootstrap.sh"

# === CYBERLAB_VALIDATE_MODE_FALLBACK ===
# Fallback seguro para ambientes onde validate_mode não foi carregado pelo bootstrap.
# Mantém o modo controlado e não aumenta ofensividade.
if ! command -v validate_mode >/dev/null 2>&1; then
  validate_mode() {
    local mode="${1:-safe}"

    case "$mode" in
      safe|standard|passive|authorized|max)
        return 0
        ;;
      *)
        echo "[ERRO] Modo inválido: $mode"
        echo "Modos aceitos: safe, standard, passive, authorized, max"
        return 1
        ;;
    esac
  }
fi
# === END_CYBERLAB_VALIDATE_MODE_FALLBACK ===



TARGET_RAW="$1"
MODE="${2:-safe}"
CLIENT="${3:-LabInterno}"

TARGET="$(clean_target "$TARGET_RAW")"

if ! validate_target "$TARGET"; then
  exit 1
fi

if ! validate_mode "$MODE"; then
  exit 1
fi

check_scope "$TARGET" || exit 1

STAMP="$(timestamp)"
OUT="$CYBERLAB_RESULTS/web/$TARGET/$STAMP"
mkdir -p "$OUT"/{01-dns,02-alive,03-ports,04-web,05-crawl,06-headers,07-vulns,08-evidence,09-report,10-json}

status_file="$OUT/status.txt"

set_mode() {
  THREADS=5
  RATE=10
  DEPTH=2
  NUCLEI_RATE=3

  if [ "$MODE" = "max" ]; then
    THREADS=15
    RATE=30
    DEPTH=3
    NUCLEI_RATE=8
  fi

  if [ "$MODE" = "lab" ]; then
    THREADS=25
    RATE=60
    DEPTH=4
    NUCLEI_RATE=15
  fi
}

status() {
  echo "$1" | tee -a "$status_file"

  if command -v log_info >/dev/null 2>&1; then
    log_info "$1"
  elif declare -F info >/dev/null 2>&1; then
    info "$1"
  else
    echo "[INFO] $1"
  fi
}

target_url() {
  if curl -k -s -I --max-time 6 "https://$TARGET" >/dev/null 2>&1; then
    echo "https://$TARGET"
  else
    echo "http://$TARGET"
  fi
}

run_dns() {
  status "01/08 DNS"

  dig "$TARGET" A +short | tee "$OUT/01-dns/a.txt"
  dig "$TARGET" NS +short | tee "$OUT/01-dns/ns.txt"
  dig "$TARGET" MX +short | tee "$OUT/01-dns/mx.txt"
  whois "$TARGET" 2>/dev/null | tee "$OUT/01-dns/whois.txt" || true
}

run_alive() {
  status "02/08 ALIVE"

  BASE_URL="$(target_url)"
  echo "$BASE_URL" | tee "$OUT/02-alive/alive.txt"

  if command -v httpx >/dev/null 2>&1; then
    echo "$TARGET" | httpx -silent -status-code -title -tech-detect -follow-redirects \
      | tee "$OUT/02-alive/httpx.txt" || true
  fi
}

run_ports() {
  status "03/08 PORTS"

  nmap -T4 -F "$TARGET" -oN "$OUT/03-ports/nmap-fast.txt" || true

  if [ "$MODE" = "max" ] || [ "$MODE" = "lab" ]; then
    nmap -sV -T3 --version-light "$TARGET" -oN "$OUT/03-ports/nmap-services.txt" || true
  fi
}

run_web_fingerprint() {
  status "04/08 WEB FINGERPRINT"

  BASE_URL="$(cat "$OUT/02-alive/alive.txt" | head -1)"

  curl -k -I -L --max-time 10 "$BASE_URL" | tee "$OUT/06-headers/headers.txt" || true

  if command -v whatweb >/dev/null 2>&1; then
    whatweb "$BASE_URL" | tee "$OUT/04-web/whatweb.txt" || true
  fi

  if command -v wafw00f >/dev/null 2>&1; then
    wafw00f "$BASE_URL" | tee "$OUT/04-web/wafw00f.txt" || true
  fi

  if command -v nikto >/dev/null 2>&1; then
    if [ "$MODE" = "lab" ]; then
      nikto -h "$BASE_URL" -Tuning x -nointeractive | tee "$OUT/04-web/nikto.txt" || true
    else
      timeout 120 nikto -h "$BASE_URL" -nointeractive | tee "$OUT/04-web/nikto.txt" || true
    fi
  fi
}

run_crawl() {
  status "05/08 CRAWL"

  BASE_URL="$(cat "$OUT/02-alive/alive.txt" | head -1)"

  echo "$BASE_URL" > "$OUT/05-crawl/seeds.txt"

  if command -v katana >/dev/null 2>&1; then
    katana -u "$BASE_URL" -silent -d "$DEPTH" -rate-limit "$RATE" \
      | tee "$OUT/05-crawl/urls.txt" || true
  else
    echo "$BASE_URL" > "$OUT/05-crawl/urls.txt"
  fi

  sort -u "$OUT/05-crawl/urls.txt" -o "$OUT/05-crawl/urls.txt"

  grep -Ei '\.js($|\?)' "$OUT/05-crawl/urls.txt" | sort -u > "$OUT/05-crawl/js.txt" || true

  grep -Ei 'admin|login|api|debug|internal|dashboard|panel|client|auth|token|upload|download|backup|config|swagger|graphql' \
    "$OUT/05-crawl/urls.txt" | sort -u > "$OUT/05-crawl/juicy.txt" || true
}

run_js_analysis() {
  status "06/08 JS ANALYSIS"

  > "$OUT/08-evidence/js-endpoints.txt"
  > "$OUT/08-evidence/js-suspect.txt"

  count=0

  while read -r jsurl; do
    [ -z "$jsurl" ] && continue
    count=$((count+1))

    file="$OUT/08-evidence/js-$count.txt"
    curl -k -s --max-time 12 "$jsurl" > "$file" || true

    grep -Eo 'https?://[^"'\'' )]+' "$file" >> "$OUT/08-evidence/js-endpoints.txt" || true
    grep -Eo '["'\''](/[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]{2,})["'\'']' "$file" \
      | tr -d '"' | tr -d "'" >> "$OUT/08-evidence/js-endpoints.txt" || true

    if grep -Eiq 'api[_-]?key|access[_-]?token|secret|bearer|jwt|client[_-]?secret|firebase|supabase|sentry|graphql' "$file"; then
      echo "$jsurl" >> "$OUT/08-evidence/js-suspect.txt"
    fi

  done < "$OUT/05-crawl/js.txt"

  sort -u "$OUT/08-evidence/js-endpoints.txt" -o "$OUT/08-evidence/js-endpoints.txt" || true
  sort -u "$OUT/08-evidence/js-suspect.txt" -o "$OUT/08-evidence/js-suspect.txt" || true
}

run_nuclei_safe() {
  status "07/08 NUCLEI SAFE"

  BASE_URL="$(cat "$OUT/02-alive/alive.txt" | head -1)"

  if command -v nuclei >/dev/null 2>&1; then
    timeout 360 nuclei -u "$BASE_URL" \
      -severity low,medium,high,critical \
      -silent \
      -rate-limit "$NUCLEI_RATE" \
      -c "$THREADS" \
      -retries 0 \
      -o "$OUT/07-vulns/nuclei.txt" || true
  else
    echo "[MISS] nuclei" > "$OUT/07-vulns/nuclei.txt"
  fi
}

run_report() {
  status "08/08 REPORT"

  BASE_URL="$(cat "$OUT/02-alive/alive.txt" | head -1)"

  PORTS="$(grep -c ' open ' "$OUT/03-ports/nmap-fast.txt" 2>/dev/null || echo 0)"
  URLS="$(wc -l < "$OUT/05-crawl/urls.txt" 2>/dev/null || echo 0)"
  JS="$(wc -l < "$OUT/05-crawl/js.txt" 2>/dev/null || echo 0)"
  JUICY="$(wc -l < "$OUT/05-crawl/juicy.txt" 2>/dev/null || echo 0)"
  NUCLEI="$(wc -l < "$OUT/07-vulns/nuclei.txt" 2>/dev/null || echo 0)"

  SCORE=0

  [ "$PORTS" -gt 3 ] && SCORE=$((SCORE+10))
  [ "$JUICY" -gt 0 ] && SCORE=$((SCORE+20))
  [ "$NUCLEI" -gt 0 ] && SCORE=$((SCORE+30))

  grep -qi "Content-Security-Policy" "$OUT/06-headers/headers.txt" || SCORE=$((SCORE+15))
  grep -qi "Strict-Transport-Security" "$OUT/06-headers/headers.txt" || SCORE=$((SCORE+10))
  grep -qi "X-Frame-Options" "$OUT/06-headers/headers.txt" || SCORE=$((SCORE+5))

  LEVEL="BAIXO"
  [ "$SCORE" -ge 40 ] && LEVEL="MÉDIO"
  [ "$SCORE" -ge 70 ] && LEVEL="ALTO"
  [ "$SCORE" -ge 100 ] && LEVEL="CRÍTICO"

  cat > "$OUT/10-json/summary.json" <<JSON
{
  "client": "$CLIENT",
  "target": "$TARGET",
  "url": "$BASE_URL",
  "mode": "$MODE",
  "date": "$(date)",
  "score": "$SCORE",
  "level": "$LEVEL",
  "ports": "$PORTS",
  "urls": "$URLS",
  "javascript_files": "$JS",
  "juicy_endpoints": "$JUICY",
  "nuclei_findings": "$NUCLEI",
  "output": "$OUT"
}
JSON

  REPORT="$OUT/09-report/web-report.md"

  cat > "$REPORT" <<MD
# CyberLab Web Report

**Cliente:** $CLIENT  
**Alvo:** $TARGET  
**URL base:** $BASE_URL  
**Modo:** $MODE  
**Data:** $(date)  
**Pasta:** $OUT  

## Score

- Score: $SCORE
- Nível: $LEVEL

## Superfície

- Portas abertas: $PORTS
- URLs coletadas: $URLS
- Arquivos JavaScript: $JS
- Endpoints sensíveis: $JUICY
- Achados Nuclei: $NUCLEI

## DNS

\`\`\`
$(cat "$OUT/01-dns/a.txt" 2>/dev/null)
\`\`\`

## Portas

\`\`\`
$(cat "$OUT/03-ports/nmap-fast.txt" 2>/dev/null)
\`\`\`

## Headers

\`\`\`
$(cat "$OUT/06-headers/headers.txt" 2>/dev/null)
\`\`\`

## Juicy Endpoints

\`\`\`
$(cat "$OUT/05-crawl/juicy.txt" 2>/dev/null)
\`\`\`

## JS Suspeitos

\`\`\`
$(cat "$OUT/08-evidence/js-suspect.txt" 2>/dev/null)
\`\`\`

## Nuclei

\`\`\`
$(cat "$OUT/07-vulns/nuclei.txt" 2>/dev/null)
\`\`\`

## Recomendações

1. Validar manualmente endpoints sensíveis.
2. Corrigir headers de segurança ausentes.
3. Revisar arquivos JavaScript públicos.
4. Conferir portas alternativas expostas.
5. Validar achados do Nuclei sem exploração agressiva.
6. Reexecutar o scan após correções.
MD

  echo "$OUT" > "$CYBERLAB_RESULTS/web/latest.txt"
  echo "[✓] Relatório: $REPORT"
}

set_mode

echo "==== CYBERLAB WEB SCAN ===="
echo "Target: $TARGET"
echo "Mode:   $MODE"
echo "Client: $CLIENT"
echo "Out:    $OUT"

run_dns
run_alive
run_ports
run_web_fingerprint
run_crawl
run_js_analysis
run_nuclei_safe
run_report

echo
echo "==== RISK ENGINE ===="
bash "$CYBERLAB_CORE/risk/risk-engine.sh" "$OUT" || true

echo
echo "==== REPORT ENGINE ===="
bash "$CYBERLAB_REPORTS/report-engine.sh" "$OUT" || true

echo
echo "==== DETECTION ENGINE ===="
bash "$CYBERLAB_MODULES/detection/detection-engine.sh" "$OUT" || true

echo
echo "==== THREAT INTEL ===="
bash "$CYBERLAB_MODULES/threat/threat-engine.sh" "$TARGET" || true

echo
echo "==== CORRELATION ENGINE ===="
bash "$CYBERLAB_MODULES/correlation/correlation.sh" "$OUT" || true

echo "[✓] Finalizado: $OUT"
