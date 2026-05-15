#!/usr/bin/env bash
set -euo pipefail

echo "==== CYBERLAB CORRELATION ENGINE FINAL ===="

python3 <<'PY'
import json, time
from pathlib import Path

state = Path.home() / "CyberLab/state/intelligence"
state.mkdir(parents=True, exist_ok=True)

fpath = state / "findings-scored.json"

try:
    data = json.loads(fpath.read_text(errors="ignore"))
except Exception:
    data = {"findings": []}

findings = data.get("findings", [])
if not isinstance(findings, list):
    findings = []

chains = []

has_high = any(f.get("severity") in ["HIGH", "CRITICAL"] for f in findings)
has_headers = any("header" in str(f.get("title","")).lower() or "header" in str(f.get("type","")).lower() for f in findings)
has_ports = any("porta" in str(f.get("title","")).lower() or "port" in str(f.get("type","")).lower() for f in findings)
has_cookie = any("cookie" in str(f.get("title","")).lower() for f in findings)

if has_high and has_headers:
    chains.append({
        "name": "Exposição web com hardening fraco",
        "risk": "HIGH",
        "description": "Achados de maior severidade combinados com ausência de headers aumentam superfície de ataque.",
        "recommendation": "Priorizar correção dos achados altos e aplicar headers de segurança."
    })

if has_ports and has_headers:
    chains.append({
        "name": "Serviços expostos e aplicação web pública",
        "risk": "MEDIUM",
        "description": "Presença de serviços expostos combinada com aplicação web exige revisão de exposição.",
        "recommendation": "Validar portas necessárias, restringir painel administrativo e revisar WAF/CDN."
    })

if has_cookie:
    chains.append({
        "name": "Sessão/cookies exigem revisão",
        "risk": "MEDIUM",
        "description": "Cookies ou sessão identificados devem ser revisados quanto a Secure, HttpOnly e SameSite.",
        "recommendation": "Aplicar flags seguras em cookies e revisar política de sessão."
    })

out = {
    "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    "engine": "CyberLab Correlation Engine Final",
    "correlations_count": len(chains),
    "correlations": chains
}

(state / "correlation-summary.json").write_text(json.dumps(out, ensure_ascii=False, indent=2))

print("[OK] correlation-summary.json")
PY
