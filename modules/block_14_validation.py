#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
from pathlib import Path

ROOT = Path.home() / "CyberLab"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.block_14_engine import Block14ValidationEngine, find_latest_scan


def main():
    parser = argparse.ArgumentParser(
        description="CyberLab - Bloco 14 Validation Intelligence"
    )

    parser.add_argument(
        "--target",
        required=True,
        help="Domínio autorizado. Ex: muranojoias.com.br",
    )

    parser.add_argument(
        "--scan-dir",
        default=None,
        help="Pasta específica do scan. Se omitido, usa o último scan do alvo.",
    )

    args = parser.parse_args()

    target = args.target.strip().replace("https://", "").replace("http://", "").strip("/")

    if args.scan_dir:
        scan_dir = Path(args.scan_dir).expanduser().resolve()
    else:
        scan_dir = find_latest_scan(target)

    print("")
    print("=== CyberLab - Bloco 14 Validation Intelligence ===")
    print(f"Alvo: {target}")
    print(f"Pasta analisada: {scan_dir}")
    print("Modo: validação local, segura e contextual")
    print("")

    engine = Block14ValidationEngine(scan_dir=scan_dir, target=target)

    print("[14A] Validando tokens, APIs, portas, headers e superfície...")
    print("[14B] Separando risco real, revisão manual e informativos...")
    print("[14C] Consolidando insights úteis...")
    print("[14D] Gerando relatórios...")

    paths = engine.run()

    print("")
    print("[OK] Bloco 14 finalizado")
    print("")
    print(f"Validados JSON: {paths['validated_findings']}")
    print(f"Insights JSON: {paths['insights']}")
    print(f"Relatório técnico: {paths['technical_report']}")
    print(f"Resumo cliente: {paths['client_summary']}")
    print(f"PDF validação: {paths['pdf']}")
    print(f"Status: {paths['status']}")
    print("")


if __name__ == "__main__":
    main()
