#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CyberLab - Bloco 12 Intelligence Engine

Camadas:
- 12A Findings Intelligence
- 12B Risk Scoring
- 12C False Positive Review
- 12D Surface Intelligence

Uso por domínio:
python3 modules/block_12_intelligence.py --target lojamaromba.com

Uso por pasta:
python3 modules/block_12_intelligence.py \
  --target-dir results/web/lojamaromba.com/2026-05-09_14-28-12 \
  --target lojamaromba.com
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime

CYBERLAB_ROOT = Path.home() / "CyberLab"
sys.path.insert(0, str(CYBERLAB_ROOT))

from core.block_12_engine import Block12Engine


def find_latest_scan(target: str) -> Path:
    base = CYBERLAB_ROOT / "results" / "web" / target

    if not base.exists():
        raise FileNotFoundError(f"Nenhum resultado encontrado para o alvo: {target}")

    scan_dirs = [p for p in base.iterdir() if p.is_dir()]

    if not scan_dirs:
        raise FileNotFoundError(f"Nenhuma pasta de scan encontrada em: {base}")

    scan_dirs.sort(key=lambda p: p.stat().st_mtime, reverse=True)

    return scan_dirs[0]


def write_client_summary(report: dict, output_path: Path) -> None:
    summary = report.get("summary", {})
    findings = report.get("findings", [])

    total = summary.get("total_findings", 0)
    risk_findings = summary.get("risk_findings", 0)
    surface_findings = summary.get("surface_findings", 0)
    risk_level = summary.get("risk_level", "INFO")
    overall_score = summary.get("overall_score", summary.get("risk_score_total", 0))
    risk_score = summary.get("risk_score_total", 0)
    surface_adjusted = summary.get("surface_adjusted_score", 0)

    lines = []
    lines.append("# Resumo de Segurança - CyberLab")
    lines.append("")
    lines.append(f"**Alvo analisado:** {report.get('target', '-')}")
    lines.append(f"**Nível geral de atenção:** {risk_level}")
    lines.append(f"**Score final calibrado:** {overall_score}")
    lines.append(f"**Score de risco real:** {risk_score}")
    lines.append(f"**Score ajustado de superfície:** {surface_adjusted}")
    lines.append(f"**Total de pontos encontrados:** {total}")
    lines.append(f"**Achados de risco real:** {risk_findings}")
    lines.append(f"**Achados de superfície:** {surface_findings}")
    lines.append("")
    lines.append("## O que isso significa")
    lines.append("")

    if total == 0:
        lines.append(
            "Nenhum ponto relevante foi identificado nesta etapa automatizada."
        )
    elif risk_findings == 0 and surface_findings > 0:
        lines.append(
            "Não foram identificadas evidências automatizadas de exposição crítica nesta etapa. "
            "A análise encontrou superfície pública relevante, como portas, caminhos de autenticação, "
            "CDN/WAF, scripts e headers, que devem ser revisados preventivamente."
        )
    elif risk_level in ["CRITICAL", "HIGH"]:
        lines.append(
            "Foram encontrados pontos que merecem revisão prioritária. "
            "Eles podem aumentar a exposição do ambiente se não forem tratados."
        )
    elif risk_level == "MEDIUM":
        lines.append(
            "Foram encontrados pontos de melhoria importantes, ligados à configuração, "
            "exposição de caminhos, serviços ou boas práticas."
        )
    else:
        lines.append(
            "Foram encontrados pontos preventivos ou de baixa criticidade."
        )

    lines.append("")
    lines.append("## Principais pontos para revisar")
    lines.append("")

    top = findings[:5]

    if not top:
        lines.append("- Nenhum achado prioritário identificado.")
    else:
        for item in top:
            lines.append(
                f"- **{item.get('title')}** "
                f"({item.get('severity')}) — {item.get('impact')}"
            )

    lines.append("")
    lines.append("## Recomendação")
    lines.append("")
    lines.append(
        "Revisar os itens apontados, confirmar se a exposição é esperada, "
        "corrigir configurações necessárias e executar uma nova validação após os ajustes."
    )

    output_path.write_text("\n".join(lines), encoding="utf-8")


def write_false_positive_review(report: dict, output_path: Path) -> None:
    findings = report.get("findings", [])

    review = {
        "block": "12C",
        "module": "False Positive Review",
        "target": report.get("target"),
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "items": [
            {
                "fingerprint": item.get("fingerprint"),
                "title": item.get("title"),
                "category": item.get("category"),
                "severity": item.get("severity"),
                "risk_score": item.get("risk_score"),
                "false_positive_score": item.get("false_positive_score"),
                "review_status": item.get("review_status"),
                "recommended_action": item.get("recommended_action"),
                "source_type": item.get("source_type"),
                "file": item.get("file"),
                "evidence": item.get("evidence")
            }
            for item in findings
        ]
    }

    output_path.write_text(
        json.dumps(review, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )


def write_status(report: dict, output_path: Path) -> None:
    status = {
        "block": "12",
        "module": "CyberLab Intelligence Engine",
        "status": "completed",
        "target": report.get("target"),
        "target_dir": report.get("target_dir"),
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "includes": report.get("includes", []),
        "outputs": {
            "json": "block_12_findings.json",
            "markdown": "block_12_report.md",
            "client_summary": "block_12_client_summary.md",
            "false_positive_review": "block_12_false_positive_review.json",
            "status": "block_12_status.json"
        },
        "summary": report.get("summary", {})
    }

    output_path.write_text(
        json.dumps(status, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )


def main():
    parser = argparse.ArgumentParser(
        description="CyberLab Bloco 12 - Intelligence Engine"
    )

    parser.add_argument(
        "--target",
        required=False,
        help="Domínio autorizado. Ex: lojamaromba.com"
    )

    parser.add_argument(
        "--target-dir",
        required=False,
        help="Pasta específica de resultados do CyberLab"
    )

    parser.add_argument(
        "--rules",
        required=False,
        default=str(CYBERLAB_ROOT / "templates" / "block_12_rules.json"),
        help="Arquivo JSON de regras"
    )

    parser.add_argument(
        "--output-dir",
        required=False,
        default=None,
        help="Diretório de saída opcional"
    )

    args = parser.parse_args()

    if not args.target and not args.target_dir:
        print("[ERRO] Informe --target ou --target-dir")
        print("")
        print("Exemplos:")
        print("  python3 modules/block_12_intelligence.py --target lojamaromba.com")
        print("  python3 modules/block_12_intelligence.py --target-dir results/web/site.com/data --target site.com")
        sys.exit(1)

    try:
        if args.target_dir:
            target_dir = Path(args.target_dir).expanduser().resolve()
            target_name = args.target or target_dir.parent.name
        else:
            target_name = args.target
            target_dir = find_latest_scan(target_name)

        if not target_dir.exists():
            print(f"[ERRO] Diretório não encontrado: {target_dir}")
            sys.exit(1)

        output_dir = (
            Path(args.output_dir).expanduser().resolve()
            if args.output_dir
            else target_dir / "block_12_intelligence"
        )

        output_dir.mkdir(parents=True, exist_ok=True)

        print("")
        print("=== CyberLab - Bloco 12 Intelligence Engine ===")
        print(f"Alvo: {target_name}")
        print(f"Pasta analisada: {target_dir}")
        print(f"Saída: {output_dir}")
        print("")
        print("[12A] Organizando achados...")
        print("[12B] Calculando score de risco...")
        print("[12C] Revisando possíveis falsos positivos...")
        print("[12D] Mapeando superfície exposta...")
        print("")

        engine = Block12Engine(args.rules)

        report = engine.analyze(
            target_dir=str(target_dir),
            target_name=target_name
        )

        json_out = output_dir / "block_12_findings.json"
        md_out = output_dir / "block_12_report.md"
        client_out = output_dir / "block_12_client_summary.md"
        fp_out = output_dir / "block_12_false_positive_review.json"
        status_out = output_dir / "block_12_status.json"

        engine.save_json(report, str(json_out))
        engine.save_markdown(report, str(md_out))
        write_client_summary(report, client_out)
        write_false_positive_review(report, fp_out)
        write_status(report, status_out)

        summary = report.get("summary", {})

        print("[OK] Bloco 12 finalizado")
        print(f"Total de achados: {summary.get('total_findings', 0)}")
        print(f"Achados de risco real: {summary.get('risk_findings', 0)}")
        print(f"Achados de superfície: {summary.get('surface_findings', 0)}")
        print(f"Score risco real: {summary.get('risk_score_total', 0)}")
        print(f"Score superfície bruto: {summary.get('surface_score_total', 0)}")
        print(f"Score superfície ajustado: {summary.get('surface_adjusted_score', 0)}")
        print(f"Score final calibrado: {summary.get('overall_score', 0)}")
        print(f"Nível geral: {summary.get('risk_level', 'INFO')}")
        print("")
        print(f"JSON técnico: {json_out}")
        print(f"Relatório técnico: {md_out}")
        print(f"Resumo cliente: {client_out}")
        print(f"Revisão falso positivo: {fp_out}")
        print(f"Status framework: {status_out}")
        print("")

    except Exception as exc:
        print(f"[ERRO] Falha ao executar Bloco 12: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
