#!/usr/bin/env python3
import json
from pathlib import Path
from datetime import datetime

HOME = Path.home() / "CyberLab"
RISK = HOME / "state/intelligence/risk-summary.json"
ASSETS = HOME / "state/assets/assets.json"
FINDINGS = HOME / "state/intelligence/findings-scored.json"
OUT = HOME / "state/analytics/analytics.json"
OUT.parent.mkdir(parents=True, exist_ok=True)

def load(p):
    try:
        return json.loads(Path(p).read_text(errors="ignore"))
    except Exception:
        return {}

def main():
    risk = load(RISK)
    assets = load(ASSETS)
    findings = load(FINDINGS)

    fs = findings.get("findings", [])
    priorities = {}
    severities = {}

    for f in fs:
        priorities[f.get("priority", "P4")] = priorities.get(f.get("priority", "P4"), 0) + 1
        severities[f.get("severity", "INFO")] = severities.get(f.get("severity", "INFO"), 0) + 1

    out = {
        "generated_at": datetime.now().isoformat(),
        "score": risk.get("score", 0),
        "level": risk.get("level", "BAIXO"),
        "assets_count": assets.get("count", 0),
        "findings_count": len(fs),
        "priorities": priorities,
        "severities": severities,
        "top_assets": risk.get("top_assets", []),
        "categories": risk.get("categories", {})
    }

    OUT.write_text(json.dumps(out, indent=2, ensure_ascii=False))
    print(f"[OK] Analytics: {OUT}")

if __name__ == "__main__":
    main()
