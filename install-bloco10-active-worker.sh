#!/usr/bin/env bash
set -euo pipefail

BASE="$HOME/CyberLab"

echo "==== CYBERLAB BLOCO 10 — ACTIVE MODE ENGINE + QUEUE WORKER ===="

mkdir -p \
  "$BASE/modules/active" \
  "$BASE/modules/worker" \
  "$BASE/data/wordlists" \
  "$BASE/results/active" \
  "$BASE/logs/active"

cat > "$BASE/data/wordlists/active-small.txt" <<'WL'
admin
login
api
app
dashboard
painel
cliente
clientes
user
users
account
accounts
auth
oauth
sso
wp-admin
wordpress
assets
static
uploads
files
backup
backups
config
server-status
status
health
debug
dev
test
staging
homolog
WL

cat > "$BASE/modules/active/active.sh" <<'ACTIVE'
#!/usr/bin/env bash
set -euo pipefail

BASE="$HOME/CyberLab"
OUTBASE="$BASE/results/active"
WORDLIST="$BASE/data/wordlists/active-small.txt"

slug(){
  echo "$1" | tr '[:upper:]' '[:lower:]' | sed 's#https\?://##' | sed 's/[^a-z0-9]/-/g' | sed 's/-\+/-/g' | sed 's/^-//;s/-$//'
}

has(){
  command -v "$1" >/dev/null 2>&1
}

log(){
  echo "[$(date -Iseconds)] $*"
}

safe_url(){
  TARGET="$1"
  if echo "$TARGET" | grep -qE '^https?://'; then
    echo "$TARGET"
  else
    echo "https://$TARGET"
  fi
}

active_run(){
  CLIENT="${1:-}"
  TARGET="${2:-}"
  MODE="${3:-active}"

  if [ -z "$CLIENT" ] || [ -z "$TARGET" ]; then
    echo "[ERRO] Uso: cyberlab active run \"Cliente\" dominio.com active"
    exit 1
  fi

  ID="$(slug "$TARGET")-$(date +%Y%m%d-%H%M%S)"
  OUT="$OUTBASE/$ID"
  URL="$(safe_url "$TARGET")"

  mkdir -p "$OUT"/{crawl,headers,fuzz,nuclei,js,params,logs}

  echo "==== CYBERLAB ACTIVE MODE ENGINE ===="
  echo "Cliente: $CLIENT"
  echo "Target:  $TARGET"
  echo "Mode:    $MODE"
  echo "Out:     $OUT"
  echo

  echo "[1/8] Control Gate"
  cyberlab control active-gate active_mode

  echo "[2/8] Scope"
  cyberlab scope check "$TARGET"

  echo "[3/8] Runtime"
  cyberlab runtime validate 5 5
  cyberlab runtime lock "active-$ID"

  trap 'cyberlab runtime unlock "active-'"$ID"'" >/dev/null 2>&1 || true' EXIT

  echo "[4/8] Evidence"
  cyberlab evidence timeline "active_mode_start target=$TARGET out=$OUT" || true

  echo "[5/8] Headers"
  if has curl; then
    timeout 20 curl -k -I -L "$URL" > "$OUT/headers/headers.txt" 2>"$OUT/logs/curl.err" || true
    echo "[OK] headers coletados"
  else
    echo "[SKIP] curl ausente"
  fi

  echo "[6/8] Crawl controlado"
  if has katana; then
    timeout 180 katana \
      -u "$URL" \
      -silent \
      -d 2 \
      -jc \
      -kf all \
      -rl 3 \
      -c 2 \
      -o "$OUT/crawl/urls.txt" \
      2>"$OUT/logs/katana.err" || true
  elif has gau; then
    timeout 120 gau "$TARGET" > "$OUT/crawl/urls.txt" 2>"$OUT/logs/gau.err" || true
  else
    echo "$URL" > "$OUT/crawl/urls.txt"
  fi

  sort -u "$OUT/crawl/urls.txt" -o "$OUT/crawl/urls.txt" 2>/dev/null || true
  echo "[OK] crawl salvo"

  echo "[7/8] JS e parâmetros"
  grep -Ei '\.js($|\?)' "$OUT/crawl/urls.txt" | sort -u > "$OUT/js/js-files.txt" || true
  grep -E '\?.+=' "$OUT/crawl/urls.txt" | sort -u > "$OUT/params/urls-with-params.txt" || true

  if has python3; then
    python3 - "$OUT/crawl/urls.txt" "$OUT/params/params.txt" <<'PY'
import sys, urllib.parse
inp, out = sys.argv[1], sys.argv[2]
params = set()
try:
    for line in open(inp, errors="ignore"):
        u = line.strip()
        q = urllib.parse.urlparse(u).query
        for k in urllib.parse.parse_qs(q).keys():
            if k:
                params.add(k)
except FileNotFoundError:
    pass
open(out, "w").write("\n".join(sorted(params)) + ("\n" if params else ""))
PY
  fi

  echo "[OK] JS/params extraídos"

  echo "[8/8] Active checks não destrutivos"

  if has httpx; then
    cat "$OUT/crawl/urls.txt" | timeout 180 httpx \
      -silent \
      -status-code \
      -title \
      -tech-detect \
      -follow-redirects \
      -rate-limit 5 \
      -threads 5 \
      -o "$OUT/crawl/httpx.txt" \
      2>"$OUT/logs/httpx.err" || true
    echo "[OK] httpx finalizado"
  else
    echo "[SKIP] httpx ausente"
  fi

  if has ffuf; then
    timeout 180 ffuf \
      -w "$WORDLIST" \
      -u "$URL/FUZZ" \
      -rate 5 \
      -t 5 \
      -timeout 5 \
      -mc 200,204,301,302,307,401,403 \
      -of json \
      -o "$OUT/fuzz/ffuf.json" \
      2>"$OUT/logs/ffuf.err" || true
    echo "[OK] ffuf controlado finalizado"
  else
    echo "[SKIP] ffuf ausente"
  fi

  if has nuclei; then
    timeout 240 nuclei \
      -u "$URL" \
      -severity info,low,medium \
      -exclude-tags intrusive,dos,fuzz,rce,sqli,ssrf,lfi,file-upload,bruteforce \
      -rate-limit 5 \
      -c 5 \
      -silent \
      -jsonl \
      -o "$OUT/nuclei/nuclei.jsonl" \
      2>"$OUT/logs/nuclei.err" || true
    echo "[OK] nuclei não destrutivo finalizado"
  else
    echo "[SKIP] nuclei ausente"
  fi

  cat > "$OUT/active-summary.json" <<JSON
{
  "client": "$CLIENT",
  "target": "$TARGET",
  "mode": "$MODE",
  "out": "$OUT",
  "crawl_urls": $(wc -l < "$OUT/crawl/urls.txt" 2>/dev/null || echo 0),
  "js_files": $(wc -l < "$OUT/js/js-files.txt" 2>/dev/null || echo 0),
  "param_urls": $(wc -l < "$OUT/params/urls-with-params.txt" 2>/dev/null || echo 0),
  "generated_at": "$(date -Iseconds)"
}
JSON

  jq empty "$OUT/active-summary.json" >/dev/null

  cyberlab evidence timeline "active_mode_end target=$TARGET out=$OUT" || true

  echo
  echo "[OK] Active Mode finalizado:"
  echo "$OUT"
}

case "${1:-help}" in
  run)
    shift
    active_run "$@"
    ;;
  *)
    echo "Uso:"
    echo "cyberlab active run \"Cliente\" dominio.com active"
    ;;
esac
ACTIVE

chmod +x "$BASE/modules/active/active.sh"

cat > "$BASE/modules/worker/worker.sh" <<'WORKER'
#!/usr/bin/env bash
set -euo pipefail

BASE="$HOME/CyberLab"
QUEUE="$BASE/queue"

mkdir -p "$QUEUE/pending" "$QUEUE/running" "$QUEUE/finished" "$QUEUE/failed"

run_one(){
  JOB="$(find "$QUEUE/pending" -type f -name "*.json" 2>/dev/null | sort | head -n 1 || true)"

  if [ -z "$JOB" ]; then
    echo "[OK] fila vazia"
    exit 0
  fi

  ID="$(jq -r '.job_id' "$JOB")"
  CLIENT="$(jq -r '.client' "$JOB")"
  TARGET="$(jq -r '.target' "$JOB")"
  MODE="$(jq -r '.mode' "$JOB")"

  RUN="$QUEUE/running/$ID.json"
  FIN="$QUEUE/finished/$ID.json"
  FAIL="$QUEUE/failed/$ID.json"

  mv "$JOB" "$RUN"

  echo "==== CYBERLAB QUEUE WORKER ===="
  echo "Job:    $ID"
  echo "Client: $CLIENT"
  echo "Target: $TARGET"
  echo "Mode:   $MODE"
  echo

  if [ "$MODE" = "active" ]; then
    CMD=(cyberlab active run "$CLIENT" "$TARGET" active)
  else
    CMD=(cyberlab op run "$CLIENT" "$TARGET" safe)
  fi

  if "${CMD[@]}"; then
    jq '.status="finished" | .finished_at=now|todate' "$RUN" > "$FIN"
    rm -f "$RUN"
    echo "[OK] job finalizado: $ID"
  else
    jq '.status="failed" | .failed_at=now|todate' "$RUN" > "$FAIL"
    rm -f "$RUN"
    echo "[FAIL] job falhou: $ID"
    exit 1
  fi
}

loop(){
  INTERVAL="${1:-10}"

  echo "==== CYBERLAB WORKER LOOP ===="
  echo "Intervalo: $INTERVAL segundos"
  echo

  while true; do
    if find "$QUEUE/pending" -type f -name "*.json" 2>/dev/null | grep -q .; then
      bash "$BASE/modules/worker/worker.sh" run-one || true
    else
      echo "[$(date -Iseconds)] fila vazia"
    fi

    sleep "$INTERVAL"
  done
}

case "${1:-help}" in
  run-one)
    run_one
    ;;
  loop)
    shift
    loop "${1:-10}"
    ;;
  *)
    echo "Uso:"
    echo "cyberlab worker run-one"
    echo "cyberlab worker loop 10"
    ;;
esac
WORKER

chmod +x "$BASE/modules/worker/worker.sh"

python3 <<'PY'
from pathlib import Path
import re

p = Path.home() / "CyberLab/bin/cyberlab"
s = p.read_text()

for cmd in ["active", "worker"]:
    s = re.sub(rf'\n?{cmd}\)\n.*?\n\s*;;\n', "\n", s, flags=re.S)

blocks = '''
active)
    bash "$HOME/CyberLab/modules/active/active.sh" "$@"
    ;;

worker)
    bash "$HOME/CyberLab/modules/worker/worker.sh" "$@"
    ;;
'''

idx = s.rfind("*)")
if idx == -1:
    raise SystemExit("[ERRO] não achei bloco *) no dispatcher")

s = s[:idx] + blocks + "\n" + s[idx:]
p.write_text(s)
print("[OK] dispatcher atualizado")
PY

chmod +x "$BASE/bin/cyberlab"

echo
echo "[OK] Bloco 10 Active Mode + Worker instalado"
echo
echo "Validação:"
echo "source ~/CyberLab/core/bootstrap.sh"
echo "hash -r"
echo "cyberlab active run \"CyberShield\" cybshield.com.br active"
echo "cyberlab queue add \"CyberShield\" cybshield.com.br active"
echo "cyberlab worker run-one"
