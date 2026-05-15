#!/usr/bin/env bash
set -euo pipefail

BASE="$HOME/CyberLab"

echo "==== CYBERLAB FINDING ENGINE ===="

mkdir -p \
  "$BASE/modules/finding" \
  "$BASE/state/intelligence" \
  "$BASE/data/policies"

cat > "$BASE/data/policies/finding-policy.json" <<'JSON'
{
  "severity_score": {
    "CRITICAL": 100,
    "HIGH": 80,
    "MEDIUM": 55,
    "LOW": 25,
    "INFO": 5
  },
  "confidence": {
    "HEADER": 90,
    "PORT": 80,
    "THREAT": 75,
    "FINGERPRINT": 65,
    "GENERIC": 60
  },
  "business_weight": {
    "public_web": 1.2,
    "admin": 1.5,
    "auth": 1.4,
    "payment": 1.7,
    "default": 1.0
  }
}
JSON

cat > "$BASE/modules/finding/finding-engine.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

BASE="$HOME/CyberLab"
STATE="$BASE/state/intelligence"
POLICY="$BASE/data/policies/finding-policy.json"

mkdir -p "$STATE"

echo "==== CYBERLAB FINDING ENGINE ===="

python3 <<'PY'
import json, time, hashlib
from pathlib import Path

base = Path.home() / "CyberLab"
state = base / "state/intelligence"
policy_path = base / "data/policies/finding-policy.json"

policy = json.loads(policy_path.read_text())

severity_score = policy["severity_score"]
confidence_policy = policy["confidence"]
business_weight = policy["business_weight"]

sources = []

# Fontes oficiais já existentes
for path in [
    state / "findings-scored.json",
]:
    if path.exists():
        sources.append(path)

# Último scan web
latest_web_file = base / "results/web/latest.txt"
if latest_web_file.exists():
    latest_web = Path(latest_web_file.read_text().strip())
    if latest_web.exists():
        for p in latest_web.glob("10-json/*.json"):
            sources.append(p)

# Último threat
latest_threat_file = base / "results/threat/latest.txt"
if latest_threat_file.exists():
    latest_threat = Path(latest_threat_file.read_text().strip())
    if latest_threat.exists():
        for p in latest_threat.glob("json/*.json"):
            sources.append(p)

def load_json(path):
    try:
        if path.exists() and path.stat().st_size > 0:
            return json.loads(path.read_text(errors="ignore"))
    except Exception:
        return None
    return None

def normalize_severity(value):
    value = str(value or "INFO").upper().strip()

    mapping = {
        "CRITICO": "CRITICAL",
        "CRÍTICO": "CRITICAL",
        "ALTO": "HIGH",
        "MEDIA": "MEDIUM",
        "MÉDIA": "MEDIUM",
        "MEDIO": "MEDIUM",
        "MÉDIO": "MEDIUM",
        "BAIXO": "LOW",
        "INFORMATIVO": "INFO"
    }

    value = mapping.get(value, value)

    if value not in severity_score:
        return "INFO"

    return value

def normalize_type(value):
    value = str(value or "GENERIC").upper().strip()
    if value not in confidence_policy:
        return "GENERIC"
    return value

def extract_findings(data):
    if data is None:
        return []

    if isinstance(data, list):
        return data

    if not isinstance(data, dict):
        return []

    for key in ["findings", "items", "results", "vulnerabilities"]:
        if isinstance(data.get(key), list):
            return data[key]

    return []

raw_findings = []

for src in sources:
    data = load_json(src)
    for item in extract_findings(data):
        if isinstance(item, dict):
            item["_source_file"] = str(src)
            raw_findings.append(item)

normalized = []

for item in raw_findings:
    severity = normalize_severity(
        item.get("severity") or item.get("risk") or item.get("level")
    )

    ftype = normalize_type(
        item.get("type") or item.get("category")
    )

    title = str(
        item.get("title") or
        item.get("name") or
        item.get("item") or
        "Achado técnico"
    ).strip()

    description = str(
        item.get("description") or
        item.get("evidence") or
        item.get("details") or
        ""
    ).strip()

    recommendation = str(
        item.get("recommendation") or
        item.get("remediation") or
        "Validar tecnicamente e aplicar correção proporcional ao risco."
    ).strip()

    asset = str(
        item.get("asset") or
        item.get("host") or
        item.get("target") or
        item.get("url") or
        ""
    ).strip()

    source_file = item.get("_source_file", "")

    base_score = severity_score.get(severity, 5)
    confidence = int(item.get("confidence") or confidence_policy.get(ftype, 60))

    business_factor = business_weight["default"]

    text = f"{title} {description} {asset}".lower()

    if "admin" in text or "painel" in text:
        business_factor = max(business_factor, business_weight["admin"])

    if "login" in text or "auth" in text or "session" in text or "cookie" in text:
        business_factor = max(business_factor, business_weight["auth"])

    if "payment" in text or "checkout" in text or "pagamento" in text:
        business_factor = max(business_factor, business_weight["payment"])

    if "http" in asset or "." in asset:
        business_factor = max(business_factor, business_weight["public_web"])

    priority_score = min(100, int(base_score * business_factor * (confidence / 100)))

    fingerprint = hashlib.sha256(
        f"{severity}|{ftype}|{title}|{asset}".encode()
    ).hexdigest()[:16]

    normalized.append({
        "id": fingerprint,
        "severity": severity,
        "type": ftype,
        "title": title,
        "description": description,
        "asset": asset,
        "recommendation": recommendation,
        "confidence": confidence,
        "priority_score": priority_score,
        "source_file": source_file
    })

# Deduplicação
dedup = {}
for finding in normalized:
    fid = finding["id"]

    if fid not in dedup:
        dedup[fid] = finding
        continue

    old = dedup[fid]

    if finding["priority_score"] > old["priority_score"]:
        dedup[fid] = finding

findings = list(dedup.values())
findings.sort(key=lambda x: x["priority_score"], reverse=True)

critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
high = sum(1 for f in findings if f["severity"] == "HIGH")
medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
low = sum(1 for f in findings if f["severity"] == "LOW")
info = sum(1 for f in findings if f["severity"] == "INFO")

risk_score = min(
    100,
    critical * 35 +
    high * 20 +
    medium * 8 +
    low * 2 +
    info
)

level = "BAIXO"
if risk_score >= 80:
    level = "CRÍTICO"
elif risk_score >= 60:
    level = "ALTO"
elif risk_score >= 30:
    level = "MÉDIO"

now = time.strftime("%Y-%m-%dT%H:%M:%S%z")

(state / "findings-scored.json").write_text(json.dumps({
    "generated_at": now,
    "engine": "CyberLab Finding Engine",
    "findings_count": len(findings),
    "findings": findings
}, ensure_ascii=False, indent=2))

(state / "risk-summary.json").write_text(json.dumps({
    "generated_at": now,
    "engine": "CyberLab Finding Engine",
    "score": risk_score,
    "level": level,
    "findings_count": len(findings),
    "critical": critical,
    "high": high,
    "medium": medium,
    "low": low,
    "info": info
}, ensure_ascii=False, indent=2))

(state / "analytics.json").write_text(json.dumps({
    "generated_at": now,
    "engine": "CyberLab Finding Engine",
    "score": risk_score,
    "level": level,
    "totals": {
        "findings": len(findings),
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "info": info
    },
    "top_findings": findings[:10]
}, ensure_ascii=False, indent=2))

(state / "remediation-plan.json").write_text(json.dumps({
    "generated_at": now,
    "engine": "CyberLab Finding Engine",
    "items": [
        {
            "severity": f["severity"],
            "priority_score": f["priority_score"],
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
print(f"[OK] Findings normalizados: {len(findings)}")
print(f"[OK] Score: {risk_score} | Nível: {level}")
PY

jq empty "$STATE/findings-scored.json" >/dev/null
jq empty "$STATE/risk-summary.json" >/dev/null
jq empty "$STATE/analytics.json" >/dev/null
jq empty "$STATE/remediation-plan.json" >/dev/null

echo "[OK] Finding Engine finalizado"
SCRIPT

chmod +x "$BASE/modules/finding/finding-engine.sh"

python3 <<'PY'
from pathlib import Path

p = Path.home() / "CyberLab/bin/cyberlab"
s = p.read_text()

block = '''finding)
    bash "$HOME/CyberLab/modules/finding/finding-engine.sh"
    ;;
'''

if "finding)" not in s:
    idx = s.rfind("*)")
    if idx != -1:
        s = s[:idx] + block + "\n" + s[idx:]
    else:
        s += "\n" + block

p.write_text(s)
PY

chmod +x "$BASE/bin/cyberlab"

echo "[OK] Bloco Finding Engine instalado"
echo
echo "Fluxo recomendado:"
echo "cyberlab scan lojamaromba.com safe"
echo "cyberlab threat lojamaromba.com"
echo "cyberlab finding"
echo "cyberlab intelligence"
echo "cyberlab correlate"
echo "cyberlab report"
echo "cyberlab delivery generate \"Loja Maromba\""
