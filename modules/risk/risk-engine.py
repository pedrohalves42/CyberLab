#!/usr/bin/env python3
import json
from pathlib import Path
from datetime import datetime
from collections import Counter, defaultdict

HOME = Path.home() / "CyberLab"
IN = HOME / "state/findings/findings-filtered.json"
if not IN.exists():
    IN = HOME / "state/findings/findings.json"

OUT_DIR = HOME / "state/intelligence"
OUT_DIR.mkdir(parents=True, exist_ok=True)

WEIGHTS = {
    "INFO": 0,
    "LOW": 2,
    "MEDIUM": 7,
    "HIGH": 18,
    "CRITICAL": 45
}

CATEGORY_BOOST = {
    "risk-summary": 0,
    "header": 1,
    "session": 2,
    "fingerprint": 0,
    "waf": 0,
    "scanner": 0,
    "exposure": 5,
    "cve": 20,
    "secret": 35,
    "auth": 18,
    "admin": 12
}

def level(score):
    if score >= 120:
        return "CRÍTICO"
    if score >= 80:
        return "ALTO"
    if score >= 40:
        return "MÉDIO"
    return "BAIXO"

def main():
    data = json.loads(IN.read_text(errors="ignore"))
    findings = data.get("findings", [])

    total = 0
    sev_count = Counter()
    by_asset = defaultdict(int)
    by_category = Counter()

    scored = []

    for f in findings:
        sev = str(f.get("severity", "INFO")).upper()
        cat = str(f.get("category", "general")).lower()
        conf = int(f.get("confidence", 50) or 50)
        fp = bool(f.get("false_positive", False))

        base = WEIGHTS.get(sev, 0)
        boost = CATEGORY_BOOST.get(cat, 0)

        score = int((base + boost) * (conf / 100))

        if fp:
            score = int(score * 0.25)

        f["risk_score"] = score
        f["priority"] = (
            "P1" if score >= 35 else
            "P2" if score >= 18 else
            "P3" if score >= 7 else
            "P4"
        )

        total += score
        sev_count[sev] += 1
        by_asset[f.get("asset", "unknown")] += score
        by_category[cat] += 1
        scored.append(f)

    # limitador para não inflar por duplicidade residual
    final_score = min(total, 200)

    summary = {
        "generated_at": datetime.now().isoformat(),
        "model": "CyberLab Risk Engine v17",
        "score": final_score,
        "level": level(final_score),
        "counts": dict(sev_count),
        "findings_count": len(scored),
        "top_assets": sorted(by_asset.items(), key=lambda x: x[1], reverse=True)[:10],
        "categories": dict(by_category),
        "recommendation": "Priorizar P1/P2, revisar falsos positivos e validar manualmente achados de alto impacto."
    }

    (OUT_DIR / "risk-summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    (OUT_DIR / "findings-scored.json").write_text(json.dumps({
        "generated_at": datetime.now().isoformat(),
        "findings": sorted(scored, key=lambda x: x.get("risk_score", 0), reverse=True)
    }, indent=2, ensure_ascii=False))

    print(f"[OK] Risk summary: {OUT_DIR / 'risk-summary.json'}")
    print(f"[OK] Findings scored: {OUT_DIR / 'findings-scored.json'}")
    print(f"[OK] Score: {final_score} | Level: {level(final_score)}")

if __name__ == "__main__":
    main()
