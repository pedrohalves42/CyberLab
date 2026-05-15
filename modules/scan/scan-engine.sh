#!/usr/bin/env bash
set -euo pipefail

BASE="$HOME/CyberLab"
TARGET="${1:-}"
MODE="${2:-safe}"

[ -z "$TARGET" ] && {
  echo "[ERRO] Uso: cyberlab scan dominio.com safe"
  exit 1
}

DATE_ID="$(date +%Y-%m-%d_%H-%M-%S)"
OUT="$BASE/results/web/$TARGET/$DATE_ID"

mkdir -p "$OUT"/{01-dns,02-alive,03-ports,04-web,05-crawl,06-headers,07-evidence,09-report,10-json}

echo "==== CYBERLAB SCAN ENGINE ===="
echo "Target: $TARGET"
echo "Mode: $MODE"
echo "Out: $OUT"

echo "[1/8] DNS"
dig "$TARGET" > "$OUT/01-dns/dig.txt" 2>/dev/null || true
whois "$TARGET" > "$OUT/01-dns/whois.txt" 2>/dev/null || true
dig +short "$TARGET" > "$OUT/01-dns/ips.txt" 2>/dev/null || true

echo "[2/8] HTTP Alive"
if command -v httpx >/dev/null 2>&1; then
  echo "$TARGET" | httpx -silent -title -tech-detect -status-code -follow-redirects > "$OUT/02-alive/httpx.txt" 2>/dev/null || true
else
  curl -I -L --max-time 15 "https://$TARGET" > "$OUT/02-alive/curl-https.txt" 2>/dev/null || true
  curl -I -L --max-time 15 "http://$TARGET" > "$OUT/02-alive/curl-http.txt" 2>/dev/null || true
fi

echo "[3/8] Portas seguras"
if command -v naabu >/dev/null 2>&1; then
  naabu -host "$TARGET" -top-ports 100 -silent > "$OUT/03-ports/naabu.txt" 2>/dev/null || true
else
  nmap -Pn -T2 --top-ports 100 "$TARGET" -oN "$OUT/03-ports/nmap-top100.txt" >/dev/null 2>&1 || true
fi

echo "[4/8] Web fingerprint"
if command -v whatweb >/dev/null 2>&1; then
  whatweb "https://$TARGET" > "$OUT/04-web/whatweb.txt" 2>/dev/null || true
fi

if command -v wafw00f >/dev/null 2>&1; then
  wafw00f "https://$TARGET" > "$OUT/04-web/wafw00f.txt" 2>/dev/null || true
fi

echo "[5/8] Crawl controlado"
if command -v katana >/dev/null 2>&1; then
  echo "https://$TARGET" | katana -silent -d 1 -jc -kf all > "$OUT/05-crawl/urls.txt" 2>/dev/null || true
else
  echo "https://$TARGET" > "$OUT/05-crawl/urls.txt"
fi

echo "[6/8] Headers"
curl -I -L --max-time 20 "https://$TARGET" > "$OUT/06-headers/headers.txt" 2>/dev/null || true

echo "[7/8] Findings básicos"
python3 <<PY
import json, pathlib, re, time

out = pathlib.Path("$OUT")
target = "$TARGET"

headers = ""
hp = out / "06-headers/headers.txt"
if hp.exists():
    headers = hp.read_text(errors="ignore").lower()

findings = []

def add(sev, typ, title, desc, rec):
    findings.append({
        "severity": sev,
        "type": typ,
        "title": title,
        "description": desc,
        "asset": target,
        "recommendation": rec
    })

if "strict-transport-security" not in headers:
    add("MEDIUM", "HEADER", "HSTS ausente", "O header Strict-Transport-Security não foi identificado.", "Configurar HSTS com max-age adequado.")

if "content-security-policy" not in headers:
    add("MEDIUM", "HEADER", "CSP ausente", "O header Content-Security-Policy não foi identificado.", "Implementar CSP compatível com o site.")

if "x-frame-options" not in headers:
    add("LOW", "HEADER", "X-Frame-Options ausente", "Proteção contra clickjacking não identificada.", "Adicionar X-Frame-Options ou frame-ancestors na CSP.")

if "x-content-type-options" not in headers:
    add("LOW", "HEADER", "X-Content-Type-Options ausente", "Proteção contra MIME sniffing não identificada.", "Adicionar X-Content-Type-Options: nosniff.")

if "server:" in headers:
    add("INFO", "FINGERPRINT", "Servidor expõe banner", "O servidor retorna informações no header Server.", "Reduzir exposição de banners quando possível.")

summary = {
    "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    "target": target,
    "mode": "$MODE",
    "findings": findings
}

(out / "10-json/summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2))
(out / "10-json/risk-summary.json").write_text(json.dumps({
    "target": target,
    "findings_count": len(findings)
}, ensure_ascii=False, indent=2))
PY

echo "[8/8] Report técnico base"
cat > "$OUT/09-report/technical-report.md" <<REPORT
# CyberLab Web Scan

**Target:** $TARGET  
**Modo:** $MODE  
**Data:** $(date -Iseconds)

## Artefatos

- DNS: \`01-dns/\`
- Alive: \`02-alive/\`
- Ports: \`03-ports/\`
- Web: \`04-web/\`
- Crawl: \`05-crawl/\`
- Headers: \`06-headers/\`
- JSON: \`10-json/\`

## Observação

Scan controlado e não destrutivo para ambiente autorizado.
REPORT

echo "$OUT" > "$BASE/results/web/latest.txt"

echo "[OK] Scan finalizado:"
echo "$OUT"
