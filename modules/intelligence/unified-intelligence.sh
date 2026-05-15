#!/usr/bin/env bash
set -euo pipefail

echo "==== CYBERLAB UNIFIED INTELLIGENCE FINAL ===="

python3 <<'PY'
import json, time
from pathlib import Path

base = Path.home() / "CyberLab"
state = base / "state/intelligence"
state.mkdir(parents=True, exist_ok=True)

src = state / "findings-scored.json"

def load(path):
    try:
        if path.exists() and path.stat().st_size > 0:
            return json.loads(path.read_text(errors="ignore"))
    except Exception:
        return {"findings": []}
    return {"findings": []}

data = load(src)

if isinstance(data, list):
    raw = data
elif isinstance(data, dict):
    raw = data.get("findings", [])
else:
    raw = []

if not isinstance(raw, list):
    raw = []

severity_map = {
    "CRÍTICO": "CRITICAL",
    "CRITICO": "CRITICAL",
    "ALTO": "HIGH",
    "MÉDIO": "MEDIUM",
    "MEDIO": "MEDIUM",
    "BAIXO": "LOW"
}

score_map = {
    "CRITICAL": 100,
    "HIGH": 80,
    "MEDIUM": 55,
    "LOW": 25,
    "INFO": 5
}

findings = []

for x in raw:
    if not isinstance(x, dict):
        continue

    sev = str(x.get("severity") or x.get("risk") or x.get("level") or "INFO").upper()
    sev = severity_map.get(sev, sev)

    if sev not in score_map:
        sev = "INFO"

    title = str(x.get("title") or x.get("item") or x.get("name") or "Achado técnico")
    desc = str(x.get("description") or x.get("evidence") or "")
    rec = str(x.get("recommendation") or "Validar tecnicamente e aplicar hardening proporcional ao risco.")
    asset = str(x.get("asset") or x.get("host") or x.get("target") or "")

    findings.append({
        "severity": sev,
        "priority_score": score_map[sev],
        "confidence": 85 if sev in ["CRITICAL", "HIGH"] else 65,
        "type": str(x.get("type") or x.get("category") or "generic"),
        "title": title,
        "description": desc,
        "asset": asset,
        "recommendation": rec
    })

seen = set()
dedup = []

for f in findings:
    key = (f["severity"], f["title"], f["asset"])
    if key not in seen:
        seen.add(key)
        dedup.append(f)

findings = sorted(dedup, key=lambda x: x["priority_score"], reverse=True)

critical = sum(1 for x in findings if x["severity"] == "CRITICAL")
high = sum(1 for x in findings if x["severity"] == "HIGH")
medium = sum(1 for x in findings if x["severity"] == "MEDIUM")
low = sum(1 for x in findings if x["severity"] == "LOW")
info = sum(1 for x in findings if x["severity"] == "INFO")

total = len(findings)
score = min(100, critical * 35 + high * 20 + medium * 8 + low * 2)

level = "BAIXO"
if score >= 80:
    level = "CRÍTICO"
elif score >= 60:
    level = "ALTO"
elif score >= 30:
    level = "MÉDIO"

now = time.strftime("%Y-%m-%dT%H:%M:%S%z")

(state / "findings-scored.json").write_text(json.dumps({
    "generated_at": now,
    "engine": "CyberLab Unified Intelligence Final",
    "count": total,
    "findings": findings
}, ensure_ascii=False, indent=2))

(state / "risk-summary.json").write_text(json.dumps({
    "generated_at": now,
    "engine": "CyberLab Unified Intelligence Final",
    "score": score,
    "level": level,
    "findings_count": total,
    "critical": critical,
    "high": high,
    "medium": medium,
    "low": low,
    "info": info
}, ensure_ascii=False, indent=2))

(state / "analytics.json").write_text(json.dumps({
    "generated_at": now,
    "score": score,
    "level": level,
    "totals": {
        "findings": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "info": info
    }
}, ensure_ascii=False, indent=2))

(state / "remediation-plan.json").write_text(json.dumps({
    "generated_at": now,
    "priority_order": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
    "items": [
        {
            "severity": f["severity"],
            "title": f["title"],
            "asset": f["asset"],
            "recommendation": f["recommendation"]
        }
        for f in findings
    ]
}, ensure_ascii=False, indent=2))

print("[OK] findings-scored.json")
print("[OK] risk-summary.json")
print("[OK] analytics.json")
print("[OK] remediation-plan.json")
PY
