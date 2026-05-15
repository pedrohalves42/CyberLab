#!/bin/bash

source "$HOME/CyberLab/core/bootstrap.sh"

TARGET_RAW="$1"
TARGET="$(clean_target "$TARGET_RAW")"

if [ -z "$TARGET" ]; then
  echo "Uso: cyberlab threat alvo.com"
  exit 1
fi

validate_target "$TARGET" || exit 1
check_scope "$TARGET" || exit 1

OUT="$CYBERLAB_RESULTS/threat/threat-$(timestamp)-$TARGET"
mkdir -p "$OUT"/{dns,whois,http,json,report}

REPORT="$OUT/report/threat-report.md"
JSON="$OUT/json/threat-summary.json"

echo "==== CYBERLAB THREAT INTEL ===="
echo "Target: $TARGET"
echo "Out:    $OUT"

echo "[1/5] DNS"
dig "$TARGET" A +short | tee "$OUT/dns/a.txt"
dig "$TARGET" AAAA +short | tee "$OUT/dns/aaaa.txt"
dig "$TARGET" NS +short | tee "$OUT/dns/ns.txt"
dig "$TARGET" MX +short | tee "$OUT/dns/mx.txt"
dig "$TARGET" TXT +short | tee "$OUT/dns/txt.txt"

IP="$(cat "$OUT/dns/a.txt" | head -1)"

echo "[2/5] WHOIS"
if [ -n "$IP" ]; then
  whois "$IP" 2>/dev/null | tee "$OUT/whois/ip-whois.txt" || true
fi

whois "$TARGET" 2>/dev/null | tee "$OUT/whois/domain-whois.txt" || true

echo "[3/5] HTTP HEADERS"
BASE_URL="https://$TARGET"
curl -k -I -L --max-time 10 "$BASE_URL" 2>/dev/null | tee "$OUT/http/headers.txt" || true

if [ ! -s "$OUT/http/headers.txt" ]; then
  BASE_URL="http://$TARGET"
  curl -I -L --max-time 10 "$BASE_URL" 2>/dev/null | tee "$OUT/http/headers.txt" || true
fi

echo "[4/5] INTEL EXTRACTION"

ASN="$(grep -Ei 'origin|originas|aut-num' "$OUT/whois/ip-whois.txt" 2>/dev/null | head -1 | sed 's/"/'\''/g')"
ORG="$(grep -Ei 'orgname|owner|descr|netname' "$OUT/whois/ip-whois.txt" 2>/dev/null | head -1 | sed 's/"/'\''/g')"
SERVER="$(grep -i '^server:' "$OUT/http/headers.txt" 2>/dev/null | head -1 | cut -d: -f2- | xargs)"
WAF="NÃO"

if grep -Eiq 'cloudflare|cf-ray|akamai|sucuri|incapsula|imperva|fastly|cloudfront' "$OUT/http/headers.txt"; then
  WAF="SIM"
fi

SEC_HEADERS_PRESENT=0
SEC_HEADERS_MISSING=0

for h in strict-transport-security content-security-policy x-frame-options x-content-type-options referrer-policy permissions-policy; do
  if grep -iq "^$h:" "$OUT/http/headers.txt"; then
    SEC_HEADERS_PRESENT=$((SEC_HEADERS_PRESENT+1))
  else
    SEC_HEADERS_MISSING=$((SEC_HEADERS_MISSING+1))
  fi
done

SCORE=0
[ "$WAF" = "NÃO" ] && SCORE=$((SCORE+20))
[ "$SEC_HEADERS_MISSING" -ge 3 ] && SCORE=$((SCORE+25))
[ -n "$SERVER" ] && SCORE=$((SCORE+5))

LEVEL="BAIXO"
[ "$SCORE" -ge 30 ] && LEVEL="MÉDIO"
[ "$SCORE" -ge 60 ] && LEVEL="ALTO"

cat > "$JSON" <<JSON
{
  "target": "$TARGET",
  "url": "$BASE_URL",
  "ip": "$IP",
  "asn": "$ASN",
  "organization": "$ORG",
  "server": "$SERVER",
  "waf_detected": "$WAF",
  "security_headers_present": $SEC_HEADERS_PRESENT,
  "security_headers_missing": $SEC_HEADERS_MISSING,
  "score": $SCORE,
  "level": "$LEVEL",
  "output": "$OUT",
  "generated_at": "$(date)"
}
JSON

echo "[5/5] REPORT"

cat > "$REPORT" <<MD
# CyberLab Threat Intelligence Report

**Alvo:** $TARGET  
**URL:** $BASE_URL  
**IP:** $IP  
**Data:** $(date)  

## Resumo

- Score: $SCORE
- Nível: $LEVEL
- WAF/CDN detectado: $WAF
- Headers de segurança presentes: $SEC_HEADERS_PRESENT
- Headers de segurança ausentes: $SEC_HEADERS_MISSING
- Server header: $SERVER

## ASN / Organização

\`\`\`
$ASN
$ORG
\`\`\`

## DNS

### A

\`\`\`
$(cat "$OUT/dns/a.txt" 2>/dev/null)
\`\`\`

### NS

\`\`\`
$(cat "$OUT/dns/ns.txt" 2>/dev/null)
\`\`\`

### MX

\`\`\`
$(cat "$OUT/dns/mx.txt" 2>/dev/null)
\`\`\`

### TXT

\`\`\`
$(cat "$OUT/dns/txt.txt" 2>/dev/null)
\`\`\`

## Headers HTTP

\`\`\`
$(cat "$OUT/http/headers.txt" 2>/dev/null)
\`\`\`

## Recomendações

1. Validar se o WAF/CDN está corretamente ativo.
2. Remover ou reduzir headers que exponham tecnologia.
3. Aplicar headers de segurança ausentes.
4. Monitorar ASN/IP exposto e mudanças de DNS.
5. Correlacionar com resultados do scan web.
MD

echo "$OUT" > "$CYBERLAB_RESULTS/threat/latest.txt"

echo "[✓] Threat report: $REPORT"
echo "[✓] JSON: $JSON"
