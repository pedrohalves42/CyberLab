#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, Optional

CYBERLAB_HOME = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CYBERLAB_HOME))

from core.audit_context import (
    add_artifact,
    add_error,
    add_warning,
    finish_context,
    mark_stage,
    normalize_target,
    set_scan_dir,
    start_context,
)

RESULTS_WEB = CYBERLAB_HOME / "results" / "web"


def find_latest_scan(target: str) -> Optional[Path]:
    target = normalize_target(target)
    root = RESULTS_WEB / target
    if not root.exists():
        return None

    dirs = [p for p in root.iterdir() if p.is_dir()]
    if not dirs:
        return None

    return max(dirs, key=lambda p: p.stat().st_mtime)


def safe_json(path: Path) -> Dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def stage_from_logs(scan_dir: Path) -> None:
    block16 = scan_dir / "block_16_unified_audit"

    steps = {
        "validate_all": "02_validate_all",
        "web_scan": "03_web_scan",
        "active_mode": "04_active_mode",
        "tool_orchestrator": "05_tool_orchestrator",
        "final_block12_13": "06_final_block12_13",
        "block14_validation": "07_block14",
        "block15_validation": "08_block15",
        "final_refresh": "09_final_refresh",
    }

    for stage, prefix in steps.items():
        stdout_log = block16 / f"{prefix}_stdout.log"
        stderr_log = block16 / f"{prefix}_stderr.log"

        if not stdout_log.exists() and not stderr_log.exists():
            mark_stage(
                stage,
                "NOT_FOUND",
                "Logs da etapa não localizados.",
                str(stdout_log),
                str(stderr_log),
            )
            continue

        stderr_nonempty = stderr_log.exists() and stderr_log.stat().st_size > 0
        status = "COMPLETED_WITH_WARNINGS" if stderr_nonempty else "OK"
        message = "Etapa executada com stderr registrado." if stderr_nonempty else "Etapa executada."

        mark_stage(
            stage,
            status,
            message,
            str(stdout_log),
            str(stderr_log),
        )


def register_known_artifacts(scan_dir: Path) -> None:
    candidates = {
        "tool_run_summary_json": scan_dir / "11-tool-orchestrator" / "tool_run_summary.json",
        "tool_run_summary_md": scan_dir / "11-tool-orchestrator" / "tool_run_summary.md",

        "block12_status": scan_dir / "block_12_intelligence" / "block_12_status.json",
        "block12_findings": scan_dir / "block_12_intelligence" / "block_12_findings.json",
        "block12_client_summary": scan_dir / "block_12_intelligence" / "block_12_client_summary.md",

        "block13_status": scan_dir / "block_13_delivery" / "block_13_status.json",
        "block13_executive_md": scan_dir / "block_13_delivery" / "executive_report.md",
        "block13_technical_md": scan_dir / "block_13_delivery" / "technical_report.md",
        "block13_remediation_md": scan_dir / "block_13_delivery" / "remediation_plan.md",
        "block13_executive_pdf": scan_dir / "block_13_delivery" / "executive_report.pdf",
        "block13_technical_pdf": scan_dir / "block_13_delivery" / "technical_report.pdf",
        "block13_remediation_pdf": scan_dir / "block_13_delivery" / "remediation_plan.pdf",

        "block14_status": scan_dir / "block_14_validation" / "block_14_status.json",
        "block14_client_summary": scan_dir / "block_14_validation" / "block_14_client_summary.md",
        "block14_validation_pdf": scan_dir / "block_14_validation" / "block_14_validation_report.pdf",

        "block15_status": scan_dir / "block_15_controlled_validation" / "block_15_status.json",
        "block15_client_summary": scan_dir / "block_15_controlled_validation" / "block_15_client_summary.md",
        "block15_impact_pdf": scan_dir / "block_15_controlled_validation" / "block_15_impact_report.pdf",

        "block16_status": scan_dir / "block_16_unified_audit" / "block_16_status.json",
        "block16_manifest": scan_dir / "block_16_unified_audit" / "block_16_manifest.json",
        "block16_execution_log": scan_dir / "block_16_unified_audit" / "block_16_execution_log.md",
        "block16_client_summary": scan_dir / "block_16_unified_audit" / "block_16_client_summary.md",

        "legacy_report_pdf": scan_dir / "09-report" / "report.pdf",
    }

    for name, path in candidates.items():
        if path.exists():
            add_artifact(name, path)


def final_status_from_block16(scan_dir: Path, return_code: int) -> str:
    status_file = scan_dir / "block_16_unified_audit" / "block_16_status.json"
    data = safe_json(status_file)

    explicit = str(data.get("status", "")).strip()
    if explicit:
        return explicit

    if return_code == 0:
        return "COMPLETED"

    return "FAILED_FATAL"


def main() -> int:
    if len(sys.argv) < 3:
        print("[ERRO] Uso:")
        print('  python3 modules/block_16_context_bridge.py "Cliente" dominio.com [perfil]')
        return 1

    client_name = sys.argv[1]
    target = normalize_target(sys.argv[2])
    profile = sys.argv[3] if len(sys.argv) > 3 else "max-controlled"

    print("")
    print("===============================================================")
    print(" CyberLab - Camada 3 Context Bridge")
    print("===============================================================")
    print(f"Cliente: {client_name}")
    print(f"Alvo:    {target}")
    print(f"Perfil:  {profile}")
    print("===============================================================")

    start_context(client_name, target, profile)
    mark_stage("block16_wrapper", "RUNNING", "Camada 3 iniciou a sessão oficial.")

    original = CYBERLAB_HOME / "modules" / "block_16_unified_audit.py"
    if not original.exists():
        add_error(f"Bloco 16 original não encontrado: {original}")
        finish_context("FAILED_FATAL")
        print(f"[ERRO] Arquivo não encontrado: {original}")
        return 1

    cmd = [sys.executable, str(original), client_name, target, profile]
    print(f"[CTX] Executando Bloco 16 original: {' '.join(cmd)}")
    print("")

    proc = subprocess.run(cmd)
    rc = proc.returncode

    scan_dir = find_latest_scan(target)
    if not scan_dir:
        add_error(f"Não foi possível localizar o scan mais recente para {target}.")
        mark_stage("block16_wrapper", "FAILED_FATAL", "Scan oficial não localizado.")
        finish_context("FAILED_FATAL")
        print("[ERRO] Não foi possível localizar a pasta oficial do scan.")
        return rc if rc != 0 else 1

    set_scan_dir(scan_dir)
    stage_from_logs(scan_dir)
    register_known_artifacts(scan_dir)

    if rc != 0:
        add_warning(f"Bloco 16 retornou código {rc}. Contexto finalizado com warning/falha controlada.")

    final_status = final_status_from_block16(scan_dir, rc)
    finish_context(final_status)

    mark_stage(
        "block16_wrapper",
        "OK" if rc == 0 else "COMPLETED_WITH_WARNINGS",
        f"Camada 3 finalizou. Código do processo original: {rc}",
    )

    print("")
    print("===============================================================")
    print(" Camada 3 sincronizada")
    print("===============================================================")
    print(f"[OK] Scan oficial: {scan_dir}")
    print(f"[OK] Contexto: {CYBERLAB_HOME / 'state' / 'audit' / 'current_audit_context.json'}")
    print(f"[OK] Cópia no scan: {scan_dir / 'block_16_unified_audit' / 'audit_context.json'}")
    print(f"[OK] Status final: {final_status}")
    print("")
    print("Consulte:")
    print("  cyberlab audit-context show")
    print("  cyberlab audit-context validate")
    print("===============================================================")

    return rc


if __name__ == "__main__":
    raise SystemExit(main())
