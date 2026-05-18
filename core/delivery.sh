#!/bin/bash
set -u

source "${CYBERLAB_HOME:-$HOME/CyberLab}/core/bootstrap.sh"

CMD="${1:-generate}"
CLIENT="${2:-}"

slugify() {
  echo "$1" | tr '[:upper:]' '[:lower:]' \
  | sed 's/[^a-z0-9]/-/g' \
  | sed 's/-\+/-/g' \
  | sed 's/^-//;s/-$//'
}

latest_delivery() {
  CLIENT="$1"
  SLUG="$(slugify "$CLIENT")"
  DIR="$CYBERLAB_HOME/clients/$SLUG/reports/delivery"
  find "$DIR" -maxdepth 1 -type d 2>/dev/null | sort | tail -n 1
}

generate_delivery() {
  if [ -z "$CLIENT" ]; then
    echo "[ERRO] Informe o cliente"
    echo "Uso: cyberlab delivery generate \"Cliente\""
    exit 1
  fi

  CLIENT_SLUG="$(slugify "$CLIENT")"
  DATE_ID="$(date +%Y-%m-%d_%H-%M-%S)"
  CLIENT_DIR="$CYBERLAB_HOME/clients/$CLIENT_SLUG"
  OUT="$CLIENT_DIR/reports/delivery/$DATE_ID"
  ZIP="$CLIENT_DIR/reports/cyberlab_${CLIENT_SLUG}_${DATE_ID}.zip"
  VALIDATION="$OUT/validation.txt"

  mkdir -p "$OUT/json" "$OUT/reports" "$OUT/evidence" "$CLIENT_DIR/reports"

  echo "[+] Montando pacote de entrega"
  echo "[+] Cliente: $CLIENT"
  echo "[+] Saída: $OUT"

  cyberlab intelligence >/dev/null 2>&1 || true

  # JSON oficiais únicos
  for f in findings-scored risk-summary analytics remediation-plan timeline assets; do
    SRC="$CYBERLAB_HOME/state/intelligence/$f.json"
    [ -f "$SRC" ] && cp "$SRC" "$OUT/json/$f.json"
  done

  # Evidências do último web scan
  LATEST_WEB="$(cat "$CYBERLAB_HOME/results/web/latest.txt" 2>/dev/null || true)"
  if [ -n "$LATEST_WEB" ] && [ -d "$LATEST_WEB" ]; then
    cp -r "$LATEST_WEB" "$OUT/evidence/web" 2>/dev/null || true
    cp "$LATEST_WEB/report/report.pdf" "$OUT/reports/report.pdf" 2>/dev/null || true
    cp "$LATEST_WEB/report/report.html" "$OUT/reports/report.html" 2>/dev/null || true
    cp "$LATEST_WEB/report/report.md" "$OUT/reports/technical-report.md" 2>/dev/null || true
  fi

  cat > "$OUT/manifest.json" <<JSON
{
  "client": "$CLIENT",
  "client_slug": "$CLIENT_SLUG",
  "generated_at": "$(date -Iseconds)",
  "package": "$ZIP",
  "engine": "CyberLab Unified Clean"
}
JSON

  {
    echo "==== CYBERLAB DELIVERY VALIDATION ===="
    echo "Cliente: $CLIENT"
    echo "Saída: $OUT"
    echo
    echo "[JSON]"
    find "$OUT/json" -name "*.json" | while read f; do
      jq empty "$f" >/dev/null 2>&1 && echo "[OK] $f" || echo "[BROKEN] $f"
    done
    echo
    echo "[FILES]"
    find "$OUT" -type f | sort
  } > "$VALIDATION"

  (
    cd "$OUT/.." || exit 1
    zip -r "$ZIP" "$DATE_ID" >/dev/null
  )

  echo "$OUT" > "$CLIENT_DIR/reports/latest-delivery.txt"

  echo
  echo "[OK] Delivery gerado:"
  echo "$OUT"
  echo
  echo "[OK] ZIP:"
  echo "$ZIP"
  echo
  echo "[OK] Validação:"
  echo "$VALIDATION"
}

case "$CMD" in
  generate)
    generate_delivery
    ;;
  latest)
    latest_delivery "$CLIENT"
    ;;
  *)
    echo "Uso:"
    echo "cyberlab delivery generate \"Cliente\""
    echo "cyberlab delivery latest \"Cliente\""
    ;;
esac
