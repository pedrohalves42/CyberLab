#!/usr/bin/env python3
import json, re
from pathlib import Path
from datetime import datetime
from collections import defaultdict

HOME = Path.home() / "CyberLab"
RESULTS = HOME / "results"
OUT = HOME / "state/assets/assets.json"
OUT.parent.mkdir(parents=True, exist_ok=True)

ip_re = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
domain_re = re.compile(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
port_re = re.compile(r'\b(80|443|8080|8443|3000|5000|8000|9000|22|21|25|53|110|143|993|995)\b')

def main():
    assets = defaultdict(lambda: {"ips": set(), "domains": set(), "ports": set(), "sources": set()})

    for p in RESULTS.rglob("*"):
        if not p.is_file():
            continue
        if p.stat().st_size > 3_000_000:
            continue
        try:
            txt = p.read_text(errors="ignore")
        except Exception:
            continue

        ips = set(ip_re.findall(txt))
        domains = set(domain_re.findall(txt))
        ports = set(port_re.findall(txt))

        for d in domains:
            key = d.lower()
            assets[key]["domains"].add(key)
            assets[key]["sources"].add(str(p))
            for ip in ips:
                assets[key]["ips"].add(ip)
            for port in ports:
                assets[key]["ports"].add(port)

        for ip in ips:
            key = ip
            assets[key]["ips"].add(ip)
            assets[key]["sources"].add(str(p))
            for port in ports:
                assets[key]["ports"].add(port)

    normalized = []
    for k, v in assets.items():
        normalized.append({
            "asset": k,
            "ips": sorted(v["ips"]),
            "domains": sorted(v["domains"]),
            "ports": sorted(v["ports"]),
            "sources": sorted(v["sources"])[:20]
        })

    OUT.write_text(json.dumps({
        "generated_at": datetime.now().isoformat(),
        "count": len(normalized),
        "assets": normalized
    }, indent=2, ensure_ascii=False))

    print(f"[OK] Asset inventory: {OUT}")
    print(f"[OK] Assets: {len(normalized)}")

if __name__ == "__main__":
    main()
