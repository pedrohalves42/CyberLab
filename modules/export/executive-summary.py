#!/usr/bin/env python3
import json
from pathlib import Path

HOME = Path.home() / "CyberLab"
risk = HOME / "state/intelligence/risk-summary.json"
out = HOME / "state/intelligence/executive-summary.txt"

data = json.loads(risk.read_text(errors="ignore")) if risk.exists() else {}
score = data.get("score", 0)
level = data.get("level", "BAIXO")
count = data.get("findings_count", 0)

txt = f"""RESUMO EXECUTIVO — CYBERLAB

Nível geral: {level}
Score: {score}
Achados analisados: {count}

Resumo:
Foi realizada uma análise controlada da exposição pública do site. O objetivo foi identificar configurações fracas, tecnologias expostas, riscos básicos e oportunidades de melhoria.

Interpretação:
- BAIXO: poucos pontos de atenção.
- MÉDIO: melhorias recomendadas.
- ALTO: exige priorização técnica.
- CRÍTICO: exige ação imediata e validação manual.

Observação:
Não significa necessariamente que o site foi invadido. O relatório aponta exposição e melhorias preventivas.
"""

out.write_text(txt, encoding="utf-8")
print(f"[OK] Resumo executivo: {out}")
