#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
from pathlib import Path

ROOT = Path.home() / "CyberLab"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.block_15_engine import Block15ControlledValidationEngine, find_latest_scan


def main():
    parser = argparse.ArgumentParser(
        description="CyberLab - Bloco 15 Controlled Offensive Validation"
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

    parser.add_argument(
        "--mode",
        default="controlled",
        choices=["controlled", "active-plus", "max-controlled"],
        help="Modo de validação controlada.",
    )

    args = parser.parse_args()

    target = args.target.strip().replace("https://", "").replace("http://", "").strip("/")

    if args.scan_dir:
        scan_dir = Path(args.scan_dir).expanduser().resolve()
    else:
        scan_dir = find_latest_scan(target)

    print("")
    print("=== CyberLab - Bloco 15 Controlled Offensive Validation ===")
    print(f"Alvo: {target}")
    print(f"Pasta analisada: {scan_dir}")
    print(f"Modo: {args.mode}")
    print("Controle: sem brute force, sem bypass, sem exploração destrutiva")
    print("")

    engine = Block15ControlledValidationEngine(
        scan_dir=scan_dir,
        target=target,
        mode=args.mode,
    )

    print("[15A] Validando APIs públicas de forma segura...")
    print("[15B] Validando GraphQL com probes benignas...")
    print("[15C] Validando storage/CDN com HEAD controlado...")
    print("[15D] Validando tokens localmente...")
    print("[15E] Validando CORS e headers...")
    print("[15F] Validando superfície de autenticação...")
    print("[15G] Promovendo evidências com impacto real...")
    print("[15H] Gerando relatórios de impacto...")

    paths = engine.run()

    print("")
    print("[OK] Bloco 15 finalizado")
    print("")
    print(f"Validações JSON: {paths['validations']}")
    print(f"Confirmados JSON: {paths['confirmed_findings']}")
    print(f"Relatório impacto: {paths['impact_report']}")
    print(f"Resumo cliente: {paths['client_summary']}")
    print(f"Testes manuais: {paths['manual_tests']}")
    print(f"PDF impacto: {paths['pdf']}")
    print(f"Status: {paths['status']}")
    print("")


if __name__ == "__main__":
    main()
