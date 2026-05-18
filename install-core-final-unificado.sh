#!/bin/bash
set -e

BASE="$CYBERLAB_HOME"

echo "==== CYBERLAB CORE FINAL UNIFICADO ===="

mkdir -p \
"$BASE/modules/core" \
"$BASE/modules/correlation" \
"$BASE/modules/ops" \
"$BASE/state/intelligence" \
"$BASE/logs" \
"$BASE/data/schemas"

# Backup seguro
for f in \
"$BASE/bin/cyberlab" \
"$BASE/core/delivery.sh" \
"$BASE/modules/intelligence/unified-intelligence.sh"
do
  [ -f "$f" ] && cp "$f" "$f.bak.final.$(date +%Y%m%d_%H%M%S)"
done

# =====================================================
# 1. SCHEMA OFICIAL
# =====================================================

cat > "$BASE/data/schemas/finding.schema.json" <<'JSON'
{
  "required": ["severity", "title", "description", "recommendation"],
  "severity_allowed": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
}
JSON

# =====================================================
# 2. CONTEXTO CENTRAL
# =====================================================

cat > "$BASE/modules/core/context.sh" <<'SCRIPT'
#!/bin/bash
set -u

export CYBERLAB_BASE="$CYBERLAB_HOME"
export CYBERLAB_STATE="$CYBERLAB_BASE/state"
export CYBERLAB_INTEL="$CYBERLAB_STATE/intelligence"
export CYBERLAB_LOGS="$CYBERLAB_BASE/logs"
export CYBERLAB_CLIENTS="$CYBERLAB_BASE/clients"

slugify() {
  echo "$1" \
  | tr '[:upper:]' '[:lower:]' \
  | sed 's/[^a-z0-9]/-/g' \
  | sed 's/-\+/-/g' \
  | sed 's/^-//;s/-$//'
}

client_dir() {
  local client="$1"
  local slug
  slug="$(slugify "$client")"
  echo "$CYBERLAB_CLIENTS/$slug"
}

latest_delivery() {
  local client="$1"
  local slug
  slug="$(slugify "$client")"
  find "$CYBERLAB_CLIENTS/$slug/reports/delivery" -maxdepth 1 -type d 2>/dev/null | sort | tail -n 1
}
SCRIPT

chmod +x "$BASE/modules/core/context.sh"

# =====================================================
# 3. LOGGER PADRÃO
# =====================================================

cat > "$BASE/modules/core/logger.sh" <<'SCRIPT'
#!/bin/bash
set -u

LOG_DIR="$CYBERLAB_HOME/logs"
mkdir -p "$LOG_DIR"

log_event() {
  local level="$1"
  local module="$2"
  local msg="$3"

  printf '{"ts":"%s","level":"%s","module":"%s","message":"%s"}\n' \
    "$(date -Iseconds)" "$level" "$module" "$msg" \
    >> "$LOG_DIR/cyberlab.jsonl"
}
SCRIPT

chmod +x "$BASE/modules/core/logger.sh"

# =====================================================
# 4. VALIDADOR JSON CENTRAL
# =====================================================

cat > "$BASE/modules/ops/validate-json.sh" <<'SCRIPT'
#!/bin/bash
set -u

TARGET="${1:-$CYBERLAB_HOME/state/intelligence}"

BROKEN=0

find "$TARGET" -name "*.json" | while read -r f; do
  if jq empty "$f" >/dev/null 2>&1; then
    echo "[OK] $f"
  else
    echo "[BROKEN] $f"
    BROKEN=1
  fi
done
SCRIPT

chmod +x "$BASE/modules/ops/validate-json.sh"

# =====================================================
# 5. INTELLIGENCE FINAL SEM JQ FRÁGIL
# =====================================================

cat > "$BASE/modules/intelligence/unified-intelligence.sh" <<'SCRIPT'
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
SCRIPT

chmod +x "$BASE/modules/intelligence/unified-intelligence.sh"

# =====================================================
# 6. CORRELATION ENGINE FINAL
# =====================================================

cat > "$BASE/modules/correlation/correlation.sh" <<'SCRIPT'
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
SCRIPT

chmod +x "$BASE/modules/correlation/correlation.sh"

# =====================================================
# 7. PATCH DISPATCHER
# =====================================================

python3 <<'PY'
from pathlib import Path

p = Path.home() / "CyberLab/bin/cyberlab"
s = p.read_text()

replacements = {
'intelligence)': '''intelligence)
    bash "$CYBERLAB_HOME/modules/intelligence/unified-intelligence.sh"
    ;;''',
'correlate)': '''correlate)
    bash "$CYBERLAB_HOME/modules/correlation/correlation.sh"
    ;;''',
'validate-json)': '''validate-json)
    bash "$CYBERLAB_HOME/modules/ops/validate-json.sh" "$@"
    ;;'''
}

for key, block in replacements.items():
    if key in s and block not in s:
        start = s.find(key)
        end = s.find(';;', start)
        if end != -1:
            end += 2
            s = s[:start] + block + s[end:]
    elif key not in s:
        insert = s.rfind('*)')
        if insert != -1:
            s = s[:insert] + block + "\n" + s[insert:]

p.write_text(s)
PY

chmod +x "$BASE/bin/cyberlab"

# =====================================================
# 8. LIMPEZA LEGADA
# =====================================================

find "$BASE" -name "*-v17.json" -delete
find "$BASE" -name "*-v18.json" -delete
find "$BASE" -name "*-v20.json" -delete

echo "[OK] Core Final Unificado instalado"
