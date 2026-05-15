#!/bin/bash

source "$HOME/CyberLab/core/bootstrap.sh"

SCAN_DIR="$1"

if [ -z "$SCAN_DIR" ]; then
  latest="$(cat "$CYBERLAB_RESULTS/web/latest.txt" 2>/dev/null)"
  SCAN_DIR="$latest"
fi

if [ -z "$SCAN_DIR" ] || [ ! -d "$SCAN_DIR" ]; then
  echo "[ERRO] Scan não encontrado."
  echo "Uso: cyberlab report latest"
  echo "Ou:  cyberlab report /caminho/do/scan"
  exit 1
fi

REPORT_DIR="$SCAN_DIR/09-report"
JSON_DIR="$SCAN_DIR/10-json"

mkdir -p "$REPORT_DIR" "$JSON_DIR"

SUMMARY_JSON="$JSON_DIR/summary.json"
RISK_JSON="$JSON_DIR/risk-summary.json"
RISK_MATRIX="$REPORT_DIR/risk-matrix.tsv"
RISK_ANALYSIS="$REPORT_DIR/risk-analysis.md"

EXEC_MD="$REPORT_DIR/executive-report.md"
TECH_MD="$REPORT_DIR/technical-report.md"
HTML="$REPORT_DIR/report.html"
PDF="$REPORT_DIR/report.pdf"

get_json_value() {
  key="$1"
  file="$2"

  if command -v jq >/dev/null 2>&1 && [ -f "$file" ]; then
    jq -r "$key // empty" "$file" 2>/dev/null
  fi
}

CLIENT="$(get_json_value '.client' "$SUMMARY_JSON")"
TARGET="$(get_json_value '.target' "$SUMMARY_JSON")"
URL="$(get_json_value '.url' "$SUMMARY_JSON")"
MODE="$(get_json_value '.mode' "$SUMMARY_JSON")"

SCORE="$(get_json_value '.score' "$RISK_JSON")"
LEVEL="$(get_json_value '.level' "$RISK_JSON")"

[ -z "$CLIENT" ] && CLIENT="Cliente"
[ -z "$TARGET" ] && TARGET="$(basename "$(dirname "$SCAN_DIR")")"
[ -z "$URL" ] && URL="$TARGET"
[ -z "$MODE" ] && MODE="safe"
[ -z "$SCORE" ] && SCORE="0"
[ -z "$LEVEL" ] && LEVEL="BAIXO"

LOW="$(get_json_value '.findings.low' "$RISK_JSON")"
MEDIUM="$(get_json_value '.findings.medium' "$RISK_JSON")"
HIGH="$(get_json_value '.findings.high' "$RISK_JSON")"
CRITICAL="$(get_json_value '.findings.critical' "$RISK_JSON")"

[ -z "$LOW" ] && LOW="0"
[ -z "$MEDIUM" ] && MEDIUM="0"
[ -z "$HIGH" ] && HIGH="0"
[ -z "$CRITICAL" ] && CRITICAL="0"

color_level() {
  case "$LEVEL" in
    BAIXO) echo "#2ecc71" ;;
    MÉDIO) echo "#f1c40f" ;;
    ALTO) echo "#e67e22" ;;
    CRÍTICO) echo "#e74c3c" ;;
    *) echo "#3498db" ;;
  esac
}

escape_html() {
  sed \
    -e 's/&/\&amp;/g' \
    -e 's/</\&lt;/g' \
    -e 's/>/\&gt;/g'
}

generate_executive() {
  cat > "$EXEC_MD" <<MD
# Relatório Executivo CyberLab

**Cliente:** $CLIENT  
**Alvo:** $TARGET  
**URL Base:** $URL  
**Modo:** $MODE  
**Data:** $(date)  

---

## 1. Resumo Executivo

Foi executada uma análise automatizada e controlada de segurança no alvo informado.  
O objetivo foi identificar superfície exposta, configurações fracas, endpoints sensíveis e evidências que merecem validação manual.

---

## 2. Resultado Geral

- **Score:** $SCORE
- **Nível de risco:** $LEVEL

### Distribuição de Achados

- Crítico: $CRITICAL
- Alto: $HIGH
- Médio: $MEDIUM
- Baixo: $LOW

---

## 3. Principais Pontos de Atenção

\`\`\`
$(tail -n +2 "$RISK_MATRIX" 2>/dev/null | grep -E '^CRITICAL|^HIGH|^MEDIUM' | head -12)
\`\`\`

---

## 4. Recomendações Prioritárias

1. Corrigir achados críticos e altos primeiro.
2. Validar manualmente endpoints administrativos, login, API, debug e internal.
3. Aplicar headers de segurança ausentes ou fracos.
4. Revisar portas alternativas expostas.
5. Validar resultados de templates automatizados antes de classificar como vulnerabilidade confirmada.
6. Reexecutar o CyberLab após correções para medir evolução do score.

---

## 5. Observação

Este relatório é uma análise defensiva para ambiente próprio ou autorizado.  
Achados automatizados precisam de validação manual antes de comunicação final ao cliente.
MD
}

generate_technical() {
  cat > "$TECH_MD" <<MD
# Relatório Técnico CyberLab

**Cliente:** $CLIENT  
**Alvo:** $TARGET  
**URL Base:** $URL  
**Modo:** $MODE  
**Pasta de evidências:** $SCAN_DIR  
**Data:** $(date)  

---

## 1. Score Técnico

- Score: $SCORE
- Nível: $LEVEL

---

## 2. Matriz de Risco

Arquivo matriz:

\`$RISK_MATRIX\`

\`\`\`
$(cat "$RISK_MATRIX" 2>/dev/null)
\`\`\`

---

## 3. Análise de Risco

\`\`\`
$(cat "$RISK_ANALYSIS" 2>/dev/null)
\`\`\`

---

## 4. DNS

\`\`\`
$(cat "$SCAN_DIR/01-dns/a.txt" 2>/dev/null)
$(cat "$SCAN_DIR/01-dns/ns.txt" 2>/dev/null)
$(cat "$SCAN_DIR/01-dns/mx.txt" 2>/dev/null)
\`\`\`

---

## 5. Portas

\`\`\`
$(cat "$SCAN_DIR/03-ports/nmap-fast.txt" 2>/dev/null)
\`\`\`

---

## 6. Headers

\`\`\`
$(cat "$SCAN_DIR/06-headers/headers.txt" 2>/dev/null)
\`\`\`

---

## 7. Fingerprint Web

### WhatWeb

\`\`\`
$(cat "$SCAN_DIR/04-web/whatweb.txt" 2>/dev/null)
\`\`\`

### WAFW00F

\`\`\`
$(cat "$SCAN_DIR/04-web/wafw00f.txt" 2>/dev/null)
\`\`\`

### Nikto

\`\`\`
$(cat "$SCAN_DIR/04-web/nikto.txt" 2>/dev/null)
\`\`\`

---

## 8. Crawl

### URLs

\`\`\`
$(cat "$SCAN_DIR/05-crawl/urls.txt" 2>/dev/null | head -300)
\`\`\`

### Juicy Endpoints

\`\`\`
$(cat "$SCAN_DIR/05-crawl/juicy.txt" 2>/dev/null)
\`\`\`

---

## 9. JavaScript

### JS Encontrados

\`\`\`
$(cat "$SCAN_DIR/05-crawl/js.txt" 2>/dev/null)
\`\`\`

### JS Suspeitos

\`\`\`
$(cat "$SCAN_DIR/08-evidence/js-suspect.txt" 2>/dev/null)
\`\`\`

### Endpoints extraídos de JS

\`\`\`
$(cat "$SCAN_DIR/08-evidence/js-endpoints.txt" 2>/dev/null | head -300)
\`\`\`

---

## 10. Nuclei

\`\`\`
$(cat "$SCAN_DIR/07-vulns/nuclei.txt" 2>/dev/null)
\`\`\`

---

## 11. Plano Técnico de Correção

1. Corrigir headers ausentes.
2. Validar portas expostas.
3. Classificar endpoints sensíveis.
4. Remover segredos ou indicadores sensíveis do frontend.
5. Configurar WAF/CDN com regras específicas.
6. Aplicar rate limit em autenticação e APIs.
7. Reexecutar o scan e comparar matriz.
MD
}

generate_html() {
  LEVEL_COLOR="$(color_level)"

  MATRIX_HTML="$(tail -n +2 "$RISK_MATRIX" 2>/dev/null | awk -F'\t' '
  {
    risk=$1; cat=$2; item=$3; evidence=$4; impact=$5; rec=$6;
    cls="low";
    if(risk=="MEDIUM") cls="medium";
    if(risk=="HIGH") cls="high";
    if(risk=="CRITICAL") cls="critical";
    printf "<tr class=\"%s\"><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n", cls, risk, cat, item, impact, rec
  }')"

  cat > "$HTML" <<HTML
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<title>CyberLab Report - $TARGET</title>
<style>
body {
  margin: 0;
  font-family: Arial, Helvetica, sans-serif;
  background: #0b1220;
  color: #eaf2ff;
}
header {
  background: linear-gradient(135deg, #102a54, #07111f);
  padding: 32px;
  border-bottom: 2px solid #1d74f5;
}
h1 { margin: 0; font-size: 32px; }
h2 { color: #8cc8ff; border-bottom: 1px solid #284668; padding-bottom: 6px; }
main { padding: 24px; }
.card {
  background: #111c30;
  border: 1px solid #27496d;
  border-radius: 14px;
  padding: 18px;
  margin-bottom: 18px;
  box-shadow: 0 6px 20px rgba(0,0,0,.25);
}
.grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 12px;
}
.metric {
  background: #0d1728;
  border: 1px solid #24496f;
  border-radius: 12px;
  padding: 14px;
}
.metric strong { font-size: 28px; display:block; }
.badge {
  display:inline-block;
  padding: 8px 14px;
  border-radius: 999px;
  background: $LEVEL_COLOR;
  color: #07111f;
  font-weight: bold;
}
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}
th, td {
  padding: 10px;
  border-bottom: 1px solid #263b5a;
  vertical-align: top;
}
th {
  background: #162a47;
  color: #fff;
}
tr.low td:first-child { color: #2ecc71; font-weight:bold; }
tr.medium td:first-child { color: #f1c40f; font-weight:bold; }
tr.high td:first-child { color: #e67e22; font-weight:bold; }
tr.critical td:first-child { color: #e74c3c; font-weight:bold; }
pre {
  background: #050b14;
  padding: 14px;
  border-radius: 10px;
  overflow: auto;
  max-height: 360px;
  border: 1px solid #1d3555;
}
footer {
  padding: 20px;
  text-align: center;
  color: #7e92aa;
}
</style>
</head>
<body>
<header>
  <h1>CyberLab Security Report</h1>
  <p>Cliente: <strong>$CLIENT</strong> | Alvo: <strong>$TARGET</strong></p>
</header>

<main>
  <div class="card">
    <h2>Resumo Executivo</h2>
    <p>Diagnóstico automatizado e controlado para identificar superfície exposta, configurações fracas e pontos que exigem validação manual.</p>
    <p>Nível de risco: <span class="badge">$LEVEL</span></p>
  </div>

  <div class="grid">
    <div class="metric"><strong>$SCORE</strong>Score</div>
    <div class="metric"><strong>$CRITICAL</strong>Crítico</div>
    <div class="metric"><strong>$HIGH</strong>Alto</div>
    <div class="metric"><strong>$MEDIUM</strong>Médio</div>
  </div>

  <div class="card">
    <h2>Matriz de Achados</h2>
    <table>
      <thead>
        <tr>
          <th>Risco</th>
          <th>Categoria</th>
          <th>Item</th>
          <th>Impacto</th>
          <th>Recomendação</th>
        </tr>
      </thead>
      <tbody>
        $MATRIX_HTML
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>Plano de Validação Manual</h2>
    <ol>
      <li>Confirmar status HTTP dos endpoints sensíveis.</li>
      <li>Validar autenticação em rotas administrativas e APIs.</li>
      <li>Revisar portas alternativas expostas.</li>
      <li>Conferir headers de segurança.</li>
      <li>Validar achados automatizados antes de comunicar como vulnerabilidade confirmada.</li>
    </ol>
  </div>

  <div class="card">
    <h2>Resumo Técnico</h2>
    <pre>$(cat "$RISK_ANALYSIS" 2>/dev/null | escape_html)</pre>
  </div>
</main>

<footer>
  CyberLab Unified Clean — Gerado em $(date)
</footer>
</body>
</html>
HTML
}

generate_pdf() {
  if command -v wkhtmltopdf >/dev/null 2>&1; then
    wkhtmltopdf "$HTML" "$PDF" >/dev/null 2>&1 && {
      echo "[✓] PDF gerado: $PDF"
      return 0
    }
  fi

  echo "[WARN] wkhtmltopdf não disponível ou falhou."
  echo "[INFO] HTML gerado em: $HTML"
}

generate_executive
generate_technical
generate_html
generate_pdf

echo "[✓] Executivo: $EXEC_MD"
echo "[✓] Técnico:    $TECH_MD"
echo "[✓] HTML:       $HTML"
echo "[✓] PDF:        $PDF"
