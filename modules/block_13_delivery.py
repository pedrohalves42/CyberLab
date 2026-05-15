#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CyberLab - Bloco 13 Delivery Enterprise

Uso:
python3 modules/block_13_delivery.py --target lojamaromba.com

Este modulo depende do Bloco 12:
results/web/DOMINIO/DATA/block_12_intelligence/block_12_findings.json
"""

import argparse
import json
import sys
from pathlib import Path

CYBERLAB_ROOT = Path.home() / "CyberLab"
sys.path.insert(0, str(CYBERLAB_ROOT))

from core.block_13_report import Block13Report


def find_latest_scan(target: str) -> Path:
    base = CYBERLAB_ROOT / "results" / "web" / target

    if not base.exists():
        raise FileNotFoundError(f"Nenhum resultado encontrado para o alvo: {target}")

    scan_dirs = [
        p for p in base.iterdir()
        if p.is_dir() and not p.name.startswith("block_")
    ]

    if not scan_dirs:
        raise FileNotFoundError(f"Nenhuma pasta de scan encontrada em: {base}")

    scan_dirs.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return scan_dirs[0]


def resolve_block12_input(target_dir: Path, explicit_input: str = None) -> Path:
    if explicit_input:
        path = Path(explicit_input).expanduser().resolve()

        if not path.exists():
            raise FileNotFoundError(f"Arquivo informado nao existe: {path}")

        return path

    candidate = target_dir / "block_12_intelligence" / "block_12_findings.json"

    if not candidate.exists():
        raise FileNotFoundError(
            "Arquivo do Bloco 12 nao encontrado. Rode primeiro:\n"
            "python3 modules/block_12_intelligence.py --target dominio.com\n"
            f"Esperado em: {candidate}"
        )

    return candidate


def main():
    parser = argparse.ArgumentParser(
        description="CyberLab Bloco 13 - Delivery Enterprise"
    )

    parser.add_argument(
        "--target",
        required=False,
        help="Dominio autorizado. Ex: lojamaromba.com"
    )

    parser.add_argument(
        "--target-dir",
        required=False,
        help="Pasta especifica do scan"
    )

    parser.add_argument(
        "--input",
        required=False,
        help="Caminho manual para block_12_findings.json"
    )

    parser.add_argument(
        "--config",
        required=False,
        default=str(CYBERLAB_ROOT / "templates" / "block_13_config.json"),
        help="Arquivo de configuracao"
    )

    parser.add_argument(
        "--output-dir",
        required=False,
        help="Diretorio de saida opcional"
    )

    args = parser.parse_args()

    if not args.target and not args.target_dir and not args.input:
        print("[ERRO] Informe --target, --target-dir ou --input")
        print("")
        print("Exemplos:")
        print("  python3 modules/block_13_delivery.py --target lojamaromba.com")
        print("  python3 modules/block_13_delivery.py --target-dir results/web/site.com/data --target site.com")
        print("  python3 modules/block_13_delivery.py --input /caminho/block_12_findings.json")
        sys.exit(1)

    try:
        if args.target_dir:
            target_dir = Path(args.target_dir).expanduser().resolve()
            target_name = args.target or target_dir.parent.name
        elif args.target:
            target_name = args.target
            target_dir = find_latest_scan(target_name)
        else:
            input_path_tmp = Path(args.input).expanduser().resolve()
            target_dir = input_path_tmp.parents[1]
            target_name = target_dir.parent.name

        if not target_dir.exists():
            raise FileNotFoundError(f"Pasta do scan nao encontrada: {target_dir}")

        block12_input = resolve_block12_input(target_dir, args.input)

    except Exception as exc:
        print(f"[ERRO] {exc}")
        sys.exit(1)

    output_dir = (
        Path(args.output_dir).expanduser().resolve()
        if args.output_dir
        else target_dir / "block_13_delivery"
    )

    output_dir.mkdir(parents=True, exist_ok=True)

    print("")
    print("=== CyberLab - Bloco 13 Delivery Enterprise ===")
    print(f"Alvo: {target_name}")
    print(f"Pasta do scan: {target_dir}")
    print(f"Entrada Bloco 12: {block12_input}")
    print(f"Saida: {output_dir}")
    print("")
    print("[13A] Gerando relatorio executivo...")
    print("[13B] Gerando relatorio tecnico...")
    print("[13C] Gerando plano de remediacao e SLA...")
    print("[13D] Gerando PDFs...")
    print("")

    engine = Block13Report(args.config)
    report = engine.load_block12(str(block12_input))

    executive_md = engine.executive_markdown(report)
    technical_md = engine.technical_markdown(report)
    remediation_md = engine.remediation_markdown(report)
    sla_timeline = engine.build_sla_timeline(report)

    executive_md_path = output_dir / "executive_report.md"
    technical_md_path = output_dir / "technical_report.md"
    remediation_md_path = output_dir / "remediation_plan.md"

    executive_pdf_path = output_dir / "executive_report.pdf"
    technical_pdf_path = output_dir / "technical_report.pdf"
    remediation_pdf_path = output_dir / "remediation_plan.pdf"

    sla_path = output_dir / "sla_timeline.json"

    engine.save_text(executive_md, str(executive_md_path))
    engine.save_text(technical_md, str(technical_md_path))
    engine.save_text(remediation_md, str(remediation_md_path))

    sla_path.write_text(
        json.dumps(sla_timeline, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )

    pdf_status = "not_generated"

    try:
        engine.markdown_to_pdf(
            executive_md,
            str(executive_pdf_path),
            "Relatorio Executivo de Seguranca"
        )

        engine.markdown_to_pdf(
            technical_md,
            str(technical_pdf_path),
            "Relatorio Tecnico de Seguranca"
        )

        engine.markdown_to_pdf(
            remediation_md,
            str(remediation_pdf_path),
            "Plano de Remediacao e SLA"
        )

        pdf_status = "completed"

    except Exception as exc:
        pdf_status = f"pdf_error: {exc}"
        print(f"[AVISO] PDFs nao foram gerados: {exc}")
        print("[AVISO] Markdown e JSON foram gerados normalmente.")

    outputs = {
        "executive_md": str(executive_md_path),
        "technical_md": str(technical_md_path),
        "remediation_md": str(remediation_md_path),
        "executive_pdf": str(executive_pdf_path),
        "technical_pdf": str(technical_pdf_path),
        "remediation_pdf": str(remediation_pdf_path),
        "sla_timeline": str(sla_path),
        "pdf_status": pdf_status
    }

    engine.write_status(report, str(output_dir), outputs)

    summary = report.get("summary", {})

    print("[OK] Bloco 13 finalizado")
    print(f"Nivel geral importado do Bloco 12: {summary.get('risk_level', 'INFO')}")
    print(f"Achados de risco real: {summary.get('risk_findings', 0)}")
    print(f"Achados de superficie: {summary.get('surface_findings', 0)}")
    print(f"Score final calibrado: {summary.get('overall_score', 0)}")
    print("")
    print(f"Executivo MD: {executive_md_path}")
    print(f"Tecnico MD: {technical_md_path}")
    print(f"Remediacao MD: {remediation_md_path}")
    print(f"Executivo PDF: {executive_pdf_path}")
    print(f"Tecnico PDF: {technical_pdf_path}")
    print(f"Remediacao PDF: {remediation_pdf_path}")
    print(f"SLA Timeline: {sla_path}")
    print(f"Status: {output_dir / 'block_13_status.json'}")
    print("")


if __name__ == "__main__":
    main()
