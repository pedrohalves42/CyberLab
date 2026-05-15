#!/usr/bin/env python3
import json
from pathlib import Path
from datetime import datetime

HOME = Path.home() / "CyberLab"
FINDINGS = HOME / "state/findings/findings.json"
WL = HOME / "data/fp-whitelist.txt"
OUT = HOME / "state/findings/findings-filtered.json"

def load_whitelist():
    if not WL.exists():
        return []
    return [x.strip().lower() for x in WL.read_text(errors="ignore").splitlines() if x.strip() and not x.startswith("#")]

def downgrade(sev):
    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    sev = sev.upper()
    if sev not in order:
        return "INFO"
    i = order.index(sev)
    return order[max(0, i-1)]

def main():
    data = json.loads(FINDINGS.read_text(errors="ignore"))
    whitelist = load_whitelist()
    out = []

    for f in data.get("findings", []):
        hay = " ".join([
            str(f.get("title","")),
            str(f.get("asset","")),
            str(f.get("category","")),
            " ".join(map(str, f.get("evidence", []))),
            " ".join(map(str, f.get("tags", [])))
        ]).lower()

        matched = [w for w in whitelist if w in hay]

        if matched:
            f["fp_context_match"] = matched
            if f["severity"] in ["MEDIUM", "HIGH"]:
                f["severity_original"] = f["severity"]
                f["severity"] = downgrade(f["severity"])
                f["false_positive_note"] = "Rebaixado por contexto conhecido/terceiro/CDN."
            if f["severity"] == "LOW":
                f["confidence"] = max(35, min(f.get("confidence", 50), 60))

        out.append(f)

    OUT.write_text(json.dumps({
        "generated_at": datetime.now().isoformat(),
        "count": len(out),
        "findings": out
    }, indent=2, ensure_ascii=False))

    print(f"[OK] False Positive Engine aplicado: {OUT}")

if __name__ == "__main__":
    main()
