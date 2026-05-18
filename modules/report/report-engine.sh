#!/usr/bin/env bash
set -euo pipefail

BASE="$CYBERLAB_HOME"
STATE="$BASE/state/intelligence"
OUT="$BASE/state/reports"

mkdir -p "$OUT"

FINDINGS="$STATE/findings-scored.json"
RISK="$STATE/risk-summary.json"
ANALYTICS="$STATE/analytics.json"
REMEDIATION="$STATE/remediation-plan.json"
CORRELATION="$STATE/correlation-summary.json"

echo "==== CYBERLAB REPORT ENGINE FINAL ===="

for f in "$FINDINGS" "$RISK" "$ANALYTICS" "$REMEDIATION"; do
  jq empty "$f" >/dev/null 2>&1 || {
    echo "[ERRO] JSON inválido ou ausente: $f"
    exit 1
  }
done

python3 <<'PY'
import json, html, time
from pathlib import Path

base = Path.home() / "CyberLab"
state = base / "state/intelligence"
out = base / "state/reports"
out.mkdir(parents=True, exist_ok=True)

def load(name, default):
    p = state / name
    try:
        return json.loads(p.read_text(errors="ignore"))
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
level = risk.get("level", "INDEFINIDO")

totals = analytics.get("totals", {})
critical = totals.get("critical", risk.get("critical", 0))
high = totals.get("high", risk.get("high", 0))
medium = totals.get("medium", risk.get("medium", 0))
low = totals.get("low", risk.get("low", 0))
info = totals.get("info", risk.get("info", 0))

generated_at = time.strftime("%Y-%m-%d %H:%M:%S")

executive = f"""# Relatório Executivo CyberLab

**Gerado em:** {generated_at}

## Resumo Geral

- **Score:** {score}
- **Nível de risco:** {level}
- **Achados críticos:** {critical}
- **Achados altos:** {high}
- **Achados médios:** {medium}
- **Achados baixos:** {low}
- **Informativos:** {info}

## Interpretação para o cliente

Este diagnóstico identifica pontos de exposição pública, configurações fracas, tecnologias detectadas e itens que merecem validação manual.

O objetivo é apoiar a correção preventiva antes que falhas simples sejam exploradas por terceiros.

## Prioridades

1. Corrigir achados críticos e altos.
2. Revisar headers e configurações de segurança.
3. Validar serviços expostos.
4. Aplicar hardening.
5. Reexecutar o diagnóstico após correção.

## Observação

Esta análise é controlada e não invasiva, focada em visibilidade, priorização e melhoria defensiva.
"""

technical_lines = [
    "# Relatório Técnico CyberLab",
    "",
    f"**Gerado em:** {generated_at}",
    "",
    "## Achados",
    ""
]

if findings:
    for i, f in enumerate(findings, 1):
        technical_lines.append(f"### {i}. {f.get('title','Achado técnico')}")
        technical_lines.append("")
        technical_lines.append(f"- **Severidade:** {f.get('severity','INFO')}")
        technical_lines.append(f"- **Score de prioridade:** {f.get('priority_score','')}")
        technical_lines.append(f"- **Confiança:** {f.get('confidence','')}")
        technical_lines.append(f"- **Ativo:** {f.get('asset','')}")
        technical_lines.append("")
        technical_lines.append("**Descrição:**")
        technical_lines.append(str(f.get("description","Sem descrição.")))
        technical_lines.append("")
        technical_lines.append("**Recomendação:**")
        technical_lines.append(str(f.get("recommendation","Validar tecnicamente e aplicar correção proporcional ao risco.")))
        technical_lines.append("")
        technical_lines.append("---")
        technical_lines.append("")
else:
    technical_lines.append("Nenhum achado técnico registrado no JSON principal.")

correlation_lines = [
    "# Correlações CyberLab",
    "",
    f"**Gerado em:** {generated_at}",
    ""
]

correlations = correlation.get("correlations", [])
if correlations:
    for c in correlations:
        correlation_lines.append(f"## {c.get('name','Correlação')}")
        correlation_lines.append("")
        correlation_lines.append(f"- **Risco:** {c.get('risk','INFO')}")
        correlation_lines.append(f"- **Descrição:** {c.get('description','')}")
        correlation_lines.append(f"- **Recomendação:** {c.get('recommendation','')}")
        correlation_lines.append("")
else:
    correlation_lines.append("Nenhuma correlação relevante identificada.")

summary = {
    "generated_at": generated_at,
    "score": score,
    "level": level,
    "totals": {
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "info": info,
        "findings": len(findings)
    },
    "reports": {
        "executive": "executive-report.md",
        "technical": "technical-report.md",
        "correlation": "correlation-report.md",
        "html": "report.html"
    }
}

(out / "executive-report.md").write_text(executive, encoding="utf-8")
(out / "technical-report.md").write_text("\n".join(technical_lines), encoding="utf-8")
(out / "correlation-report.md").write_text("\n".join(correlation_lines), encoding="utf-8")
(out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

def md_to_html(md):
    escaped = html.escape(md)
    escaped = escaped.replace("\n", "<br>\n")
    return escaped

html_doc = f"""<!doctype html>
<html lang="pt-br">
<head>
<meta charset="utf-8">
<title>CyberLab Report</title>
<style>
body {{
  font-family: Arial, sans-serif;
  background: #0f172a;
  color: #e5e7eb;
  margin: 40px;
  line-height: 1.6;
}}
.card {{
  background: #111827;
  border: 1px solid #334155;
  border-radius: 12px;
  padding: 24px;
  margin-bottom: 24px;
}}
h1, h2, h3 {{
  color: #38bdf8;
}}
.badge {{
  display: inline-block;
  padding: 6px 12px;
  border-radius: 999px;
  background: #1e40af;
  color: white;
}}
</style>
</head>
<body>
<div class="card">
<h1>CyberLab Security Report</h1>
<p><strong>Score:</strong> <span class="badge">{score}</span></p>
<p><strong>Nível:</strong> <span class="badge">{html.escape(str(level))}</span></p>
<p><strong>Gerado em:</strong> {html.escape(generated_at)}</p>
</div>

<div class="card">
{md_to_html(executive)}
</div>

<div class="card">
{md_to_html("\\n".join(technical_lines))}
</div>

<div class="card">
{md_to_html("\\n".join(correlation_lines))}
</div>
</body>
</html>
"""

(out / "report.html").write_text(html_doc, encoding="utf-8")

print("[OK] executive-report.md")
print("[OK] technical-report.md")
print("[OK] correlation-report.md")
print("[OK] report.html")
print("[OK] summary.json")
PY

jq empty "$OUT/summary.json" >/dev/null
echo "[OK] Report Engine finalizado"
