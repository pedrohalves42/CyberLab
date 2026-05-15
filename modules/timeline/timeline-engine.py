#!/usr/bin/env python3
import json
from pathlib import Path
from datetime import datetime

HOME = Path.home() / "CyberLab"
RESULTS = HOME / "results"
OUT = HOME / "state/timeline/timeline.json"
OUT.parent.mkdir(parents=True, exist_ok=True)

def main():
    events = []

    for p in RESULTS.rglob("*"):
        if p.is_file():
            try:
                ts = datetime.fromtimestamp(p.stat().st_mtime).isoformat()
                events.append({
                    "time": ts,
                    "type": "file",
                    "path": str(p),
                    "size": p.stat().st_size
                })
            except Exception:
                pass

    events = sorted(events, key=lambda x: x["time"])

    OUT.write_text(json.dumps({
        "generated_at": datetime.now().isoformat(),
        "count": len(events),
        "events": events[-500:]
    }, indent=2, ensure_ascii=False))

    print(f"[OK] Timeline: {OUT}")
    print(f"[OK] Eventos: {len(events)}")

if __name__ == "__main__":
    main()
