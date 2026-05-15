#!/usr/bin/env python3
import csv, json
from pathlib import Path

HOME = Path.home() / "CyberLab"
src = HOME / "state/intelligence/findings-scored.json"
out = HOME / "state/intelligence/findings.csv"

data = json.loads(src.read_text(errors="ignore")) if src.exists() else {"findings":[]}

with out.open("w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["Severidade", "Prioridade", "Título", "Ativo", "Categoria", "Confiança", "Recomendação"])
    for x in data.get("findings", []):
        w.writerow([
            x.get("severity","INFO"),
            x.get("priority","P4"),
            x.get("title",""),
            x.get("asset",""),
            x.get("category",""),
            x.get("confidence",""),
            "Validar tecnicamente e aplicar correção proporcional ao risco."
        ])

print(f"[OK] CSV gerado: {out}")
