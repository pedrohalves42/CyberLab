#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path.home() / "CyberLab"
ENGINE = ROOT / "core" / "block_16_unified_orchestrator.py"


def main() -> int:
    if len(sys.argv) < 4:
        print("Uso:")
        print('  modules/block_16_unified_audit.py "Cliente" dominio.com perfil')
        return 1

    client_name = sys.argv[1]
    target = sys.argv[2]
    profile = sys.argv[3]

    if not ENGINE.exists():
        print(f"[ERRO] Motor do Bloco 16 não encontrado: {ENGINE}")
        return 2

    cmd = [
        "python3",
        str(ENGINE),
        client_name,
        target,
        profile,
    ]

    return subprocess.call(cmd, cwd=str(ROOT))


if __name__ == "__main__":
    raise SystemExit(main())
