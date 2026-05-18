#!/usr/bin/env bash
set -euo pipefail

BASE="$CYBERLAB_HOME"
TARGET="${1:-}"

[ -z "$TARGET" ] && {
  echo "[ERRO] Uso: cyberlab threat dominio.com"
  exit 1
}

DATE_ID="$(date +%Y-%m-%d_%H-%M-%S)"
OUT="$BASE/results/threat/threat-$DATE_ID-$TARGET"

mkdir -p "$OUT/json" "$OUT/report" "$OUT/evidence"

echo "==== CYBERLAB THREAT ENGINE V2 ===="
echo "Target: $TARGET"

WEB_LATEST="$(cat "$BASE/results/web/latest.txt" 2>/dev/null || true)"

python3 <<PY
import json, pathlib, time, re

base = pathlib.Path.home() / "CyberLab"
out = pathlib.Path("$OUT")
target = "$TARGET"
web_latest = pathlib.Path("$WEB_LATEST") if "$WEB_LATEST" else None

signals = []
findings = []

def add_signal(name, value, source):
    signals.append({"name": name, "value": value, "source": source})

def add_finding(sev, title, desc, rec):
    findings.append({
        "severity": sev,
        "type": "THREAT",
        "title": title,
        "description": desc,
        "asset": target,
        "recommendation": rec
    })

if web_latest and web_latest.exists():
    headers = web_latest / "06-headers/headers.txt"
    if headers.exists():
        h = headers.read_text(errors="ignore").lower()

        if "cloudflare" in h:
            add_signal("cdn_waf", "cloudflare", "headers")

        if "x-powered-by" in h:
            add_signal("technology_leak", "x-powered-by", "headers")
            add_finding(
                "LOW",
                "Exposição de tecnologia via header",
                "Header X-Powered-By identificado.",
                "Remover ou reduzir headers que expõem tecnologia."
            )

        if "php" in h:
            add_signal("backend_hint", "php", "headers")

    ports = web_latest / "03-ports"
    exposed_ports = []
    if ports.exists():
        for f in ports.glob("*.txt"):
            txt = f.read_text(errors="ignore")
            for line in txt.splitlines():
                if re.search(r"\\b(21|22|25|80|443|8080|8443)\\b", line):
                    exposed_ports.append(line.strip())

    if exposed_ports:
        add_signal("exposed_ports", exposed_ports[:20], "ports")
        add_finding(
            "MEDIUM",
            "Serviços públicos detectados",
            "Foram identificados serviços expostos que precisam ser revisados.",
            "Validar se todos os serviços expostos são necessários e protegidos."
        )

exposure_score = 0
for f in findings:
    sev = f["severity"]
    exposure_score += {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10, "LOW": 3, "INFO": 1}.get(sev, 1)

level = "BAIXO"
if exposure_score >= 80:
    level = "CRÍTICO"
elif exposure_score >= 50:
    level = "ALTO"
elif exposure_score >= 20:
    level = "MÉDIO"

summary = {
    "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    "engine": "CyberLab Threat Engine V2",
    "target": target,
    "exposure_score": exposure_score,
    "level": level,
    "signals": signals,
    "findings": findings
}

attack_surface = {
    "target": target,
    "signals_count": len(signals),
    "signals": signals
}

(out / "json/threat-summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2))
(out / "json/attack-surface.json").write_text(json.dumps(attack_surface, ensure_ascii=False, indent=2))
(out / "json/exposure-score.json").write_text(json.dumps({
    "target": target,
    "score": exposure_score,
    "level": level
}, ensure_ascii=False, indent=2))

state = base / "state/intelligence"
state.mkdir(parents=True, exist_ok=True)

main_findings = state / "findings-scored.json"
try:
    existing = json.loads(main_findings.read_text(errors="ignore"))
except Exception:
    existing = {"findings": []}

if not isinstance(existing, dict):
    existing = {"findings": []}

if not isinstance(existing.get("findings"), list):
    existing["findings"] = []

existing["findings"].extend(findings)
main_findings.write_text(json.dumps(existing, ensure_ascii=False, indent=2))

(out / "report/threat-report.md").write_text(f"""# CyberLab Threat Report

**Target:** {target}  
**Score de exposição:** {exposure_score}  
**Nível:** {level}

## Sinais

{json.dumps(signals, ensure_ascii=False, indent=2)}

## Achados

{json.dumps(findings, ensure_ascii=False, indent=2)}
""")
PY

jq empty "$OUT/json/threat-summary.json" >/dev/null
jq empty "$OUT/json/attack-surface.json" >/dev/null
jq empty "$OUT/json/exposure-score.json" >/dev/null

echo "$OUT" > "$BASE/results/threat/latest.txt"

echo "[OK] Threat Engine finalizado:"
echo "$OUT"
