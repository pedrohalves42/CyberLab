#!/usr/bin/env bash
set -euo pipefail

BASE="$CYBERLAB_HOME"
STATE="$BASE/state/intelligence"
REPORTS="$BASE/state/reports"

mkdir -p "$REPORTS"

echo "==== CYBERLAB REPORT ENGINE ENTERPRISE ===="

python3 <<'PY'
import json, pathlib, time, html

base = pathlib.Path.home() / "CyberLab"
state = base / "state/intelligence"
reports = base / "state/reports"
reports.mkdir(parents=True, exist_ok=True)

def load(name, default):
    try:
        return json.loads((state / name).read_text(errors="ignore"))
    except Exception:
        return default

findings_data = load("findings-scored.json", {"findings": []})
risk = load("risk-summary.json", {})
analytics = load("analytics.json", {})
remediation = load("remediation-plan.json", {"items": []})
correlation = load("correlation-summary.json", {"correlations": []})

findings = findings_data.get("findings", [])
if not isinstance(findings, list):
    findings = []

score = risk.get("score", 0)
level = risk.get("level", "BAIXO")
generated_at = time.strftime("%Y-%m-%d %H:%M:%S")

exec_md = f"""# Relatório Executivo CyberLab

**Gerado em:** {generated_at}  
**Score:** {score}  
**Nível:** {level}

## Resumo

Esta análise identifica exposições públicas, configurações ausentes, sinais técnicos e riscos correlacionados em ambiente autorizado.

## Prioridades

1. Corrigir achados críticos e altos.
2. Revisar headers de segurança.
3. Validar exposição de serviços.
4. Aplicar hardening.
5. Reexecutar validação após correções.

## Observação

Diagnóstico controlado e não destrutivo.
"""

tech = ["# Relatório Técnico CyberLab", "", f"Gerado em: {generated_at}", ""]

if findings:
    for i, f in enumerate(findings, 1):
        tech += [
            f"## {i}. {f.get('title','Achado técnico')}",
            "",
            f"- Severidade: {f.get('severity','INFO')}",
            f"- Ativo: {f.get('asset','')}",
            f"- Confiança: {f.get('confidence','')}",
            "",
            "### Descrição",
            str(f.get("description","")),
            "",
            "### Recomendação",
            str(f.get("recommendation","")),
            ""
        ]
else:
    tech.append("Nenhum achado registrado.")

corr = ["# Correlações CyberLab", ""]
for c in correlation.get("correlations", []):
    corr += [
        f"## {c.get('name','Correlação')}",
        "",
        f"- Risco: {c.get('risk','INFO')}",
        f"- Descrição: {c.get('description','')}",
        f"- Recomendação: {c.get('recommendation','')}",
        ""
    ]

summary = {
    "generated_at": generated_at,
    "score": score,
    "level": level,
    "findings_count": len(findings),
    "reports": [
        "executive-report.md",
        "technical-report.md",
        "correlation-report.md",
        "report.html"
    ]
}

(reports / "executive-report.md").write_text(exec_md, encoding="utf-8")
(reports / "technical-report.md").write_text("\n".join(tech), encoding="utf-8")
(reports / "correlation-report.md").write_text("\n".join(corr), encoding="utf-8")
(reports / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

body = html.escape(exec_md + "\n\n" + "\n".join(tech) + "\n\n" + "\n".join(corr)).replace("\n", "<br>")
html_doc = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>CyberLab Report</title>
<style>
body{{font-family:Arial;background:#0f172a;color:#e5e7eb;padding:40px}}
h1,h2,h3{{color:#38bdf8}}
.card{{background:#111827;border:1px solid #334155;border-radius:12px;padding:24px}}
</style>
</head>
<body>
<div class="card">{body}</div>
</body>
</html>
"""
(reports / "report.html").write_text(html_doc, encoding="utf-8")
PY

jq empty "$REPORTS/summary.json" >/dev/null

if command -v wkhtmltopdf >/dev/null 2>&1; then
  wkhtmltopdf "$REPORTS/report.html" "$REPORTS/report.pdf" >/dev/null 2>&1 || true
else
  echo "[WARN] wkhtmltopdf não instalado; PDF não gerado"
fi

echo "[OK] Report Enterprise finalizado"
