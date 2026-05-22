#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import shutil
from datetime import datetime
from pathlib import Path

# Raiz oficial do CyberLab
CYBERLAB_HOME = Path(__file__).resolve().parents[1]
from typing import Any, Dict, List, Optional


HOME = Path.home()
ROOT = HOME / "CyberLab"
RESULTS_WEB = ROOT / "results" / "web"
CLIENTS_DIR = ROOT / "clients"

BLOCK16_DIRNAME = "block_16_unified_audit"


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def slugify(value: str) -> str:
    value = value.strip().lower()
    out = []
    for ch in value:
        if ch.isalnum():
            out.append(ch)
        elif ch in (" ", "-", "_", "."):
            out.append("-")
    slug = "".join(out)
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip("-")


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def read_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def write_json(path: Path, data: Dict[str, Any]) -> None:
    ensure_dir(path.parent)
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )


def write_text(path: Path, content: str) -> None:
    ensure_dir(path.parent)
    path.write_text(content, encoding="utf-8")


def latest_scan_dir(target: str) -> Optional[Path]:
    base = RESULTS_WEB / target
    if not base.exists():
        return None

    candidates = [p for p in base.iterdir() if p.is_dir()]
    if not candidates:
        return None

    return sorted(candidates, key=lambda p: p.stat().st_mtime, reverse=True)[0]


def cyberlab_cmd(*args: str) -> List[str]:
    return [str(ROOT / "bin" / "cyberlab"), *args]


def run_step(
    step_id: str,
    title: str,
    command: List[str],
    out_dir: Path,
    env_extra: Optional[Dict[str, str]] = None,
    required: bool = True,
    timeout: Optional[int] = None,
) -> Dict[str, Any]:
    ensure_dir(out_dir)

    stdout_file = out_dir / f"{step_id}_stdout.log"
    stderr_file = out_dir / f"{step_id}_stderr.log"

    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)

    started_at = now_iso()

    print("")
    print("=" * 72)
    print(f"[B16] {step_id} — {title}")
    print("=" * 72)
    print("[CMD]", " ".join(shlex.quote(x) for x in command))
    print("")

    try:
        proc = subprocess.run(
            command,
            cwd=str(ROOT),
            env=env,
            text=True,
            capture_output=True,
            timeout=timeout,
        )

        stdout_file.write_text(proc.stdout or "", encoding="utf-8")
        stderr_file.write_text(proc.stderr or "", encoding="utf-8")

        status = "OK" if proc.returncode == 0 else "COMPLETED_WITH_ERRORS"

        print(proc.stdout or "", end="")
        if proc.stderr:
            print(proc.stderr, end="", file=sys.stderr)

        result = {
            "id": step_id,
            "title": title,
            "command": command,
            "started_at": started_at,
            "finished_at": now_iso(),
            "returncode": proc.returncode,
            "status": status,
            "required": required,
            "stdout_log": str(stdout_file),
            "stderr_log": str(stderr_file),
        }

        if required and proc.returncode != 0:
            result["pipeline_blocking_error"] = True

        return result

    except subprocess.TimeoutExpired as exc:
        stdout_file.write_text(exc.stdout or "", encoding="utf-8")
        stderr_file.write_text(exc.stderr or "", encoding="utf-8")

        return {
            "id": step_id,
            "title": title,
            "command": command,
            "started_at": started_at,
            "finished_at": now_iso(),
            "returncode": None,
            "status": "TIMEOUT",
            "required": required,
            "stdout_log": str(stdout_file),
            "stderr_log": str(stderr_file),
            "pipeline_blocking_error": required,
        }

    except Exception as exc:
        stderr_file.write_text(str(exc), encoding="utf-8")
        return {
            "id": step_id,
            "title": title,
            "command": command,
            "started_at": started_at,
            "finished_at": now_iso(),
            "returncode": None,
            "status": "FAILED_TO_RUN",
            "required": required,
            "stdout_log": str(stdout_file),
            "stderr_log": str(stderr_file),
            "error": str(exc),
            "pipeline_blocking_error": required,
        }


def detect_existing_outputs(scan_dir: Path) -> Dict[str, Any]:
    outputs = {
        "block_12": {
            "exists": (scan_dir / "block_12_intelligence").exists(),
            "path": str(scan_dir / "block_12_intelligence"),
        },
        "block_13": {
            "exists": (scan_dir / "block_13_delivery").exists(),
            "path": str(scan_dir / "block_13_delivery"),
        },
        "block_14": {
            "exists": (scan_dir / "block_14_validation").exists(),
            "path": str(scan_dir / "block_14_validation"),
        },
        "block_15": {
            "exists": (scan_dir / "block_15_controlled_validation").exists(),
            "path": str(scan_dir / "block_15_controlled_validation"),
        },
        "layer6_surface_expansion": {
            "exists": (scan_dir / "block_6_surface_expansion").exists(),
            "path": str(scan_dir / "block_6_surface_expansion"),
        },
        "tool_orchestrator": {
            "exists": (scan_dir / "11-tool-orchestrator").exists(),
            "path": str(scan_dir / "11-tool-orchestrator"),
        },
        "report_base": {
            "exists": (scan_dir / "09-report").exists(),
            "path": str(scan_dir / "09-report"),
        },
    }
    return outputs


def find_pdfs(scan_dir: Path) -> List[str]:
    return sorted(str(p) for p in scan_dir.rglob("*.pdf"))


def count_statuses(steps: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for step in steps:
        status = step.get("status", "UNKNOWN")
        counts[status] = counts.get(status, 0) + 1
    return counts


def pipeline_final_status(steps: List[Dict[str, Any]]) -> str:
    blocking = [
        s for s in steps
        if s.get("required") and s.get("pipeline_blocking_error")
    ]
    if blocking:
        return "COMPLETED_WITH_BLOCKING_ERRORS"

    warnings = [
        s for s in steps
        if s.get("status") not in ("OK", "SKIPPED")
    ]
    if warnings:
        return "COMPLETED_WITH_WARNINGS"

    return "OK"


def build_execution_log(
    client_name: str,
    target: str,
    profile: str,
    scan_dir: Path,
    steps: List[Dict[str, Any]],
    outputs: Dict[str, Any],
    pdfs: List[str],
    final_status: str,
) -> str:
    lines = []
    lines.append("# CyberLab — Bloco 16 Unified Audit Execution Log")
    lines.append("")
    lines.append(f"**Cliente:** {client_name}")
    lines.append(f"**Alvo:** {target}")
    lines.append(f"**Perfil:** {profile}")
    lines.append(f"**Pasta oficial do scan:** `{scan_dir}`")
    lines.append(f"**Status final:** **{final_status}**")
    lines.append(f"**Gerado em:** {now_iso()}")
    lines.append("")
    lines.append("## Etapas executadas")
    lines.append("")

    for step in steps:
        lines.append(f"### {step.get('id')} — {step.get('title')}")
        lines.append(f"- Status: **{step.get('status')}**")
        lines.append(f"- Return code: `{step.get('returncode')}`")
        lines.append(f"- Início: `{step.get('started_at')}`")
        lines.append(f"- Fim: `{step.get('finished_at')}`")
        lines.append(f"- STDOUT: `{step.get('stdout_log')}`")
        lines.append(f"- STDERR: `{step.get('stderr_log')}`")
        lines.append("")

    lines.append("## Blocos e saídas detectadas")
    lines.append("")
    for name, info in outputs.items():
        status = "OK" if info.get("exists") else "AUSENTE"
        lines.append(f"- **{name}:** {status} — `{info.get('path')}`")

    lines.append("")
    lines.append("## PDFs localizados na execução")
    lines.append("")
    if pdfs:
        for pdf in pdfs:
            lines.append(f"- `{pdf}`")
    else:
        lines.append("- Nenhum PDF localizado até este ponto.")

    lines.append("")
    return "\n".join(lines)


def build_client_summary(
    client_name: str,
    target: str,
    profile: str,
    scan_dir: Path,
    final_status: str,
    outputs: Dict[str, Any],
    pdfs: List[str],
) -> str:
    lines = []
    lines.append("# CyberLab — Resumo Final da Auditoria Unificada")
    lines.append("")
    lines.append(f"**Cliente:** {client_name}")
    lines.append(f"**Alvo auditado:** {target}")
    lines.append(f"**Perfil aplicado:** {profile}")
    lines.append(f"**Status da orquestração:** **{final_status}**")
    lines.append(f"**Pasta da execução:** `{scan_dir}`")
    lines.append("")
    lines.append("## Camadas executadas")
    lines.append("")
    lines.append("- Reconhecimento web inicial")
    lines.append("- Camada 6A de expansão passiva de superfície")
    lines.append("- Active mode controlado")
    lines.append("- Orquestração de ferramentas auditadas")
    lines.append("- Consolidação de findings")
    lines.append("- Validação contextual")
    lines.append("- Validação de impacto controlado")
    lines.append("- Preparação de entrega final")
    lines.append("")
    lines.append("## Estrutura detectada")
    lines.append("")
    for name, info in outputs.items():
        status = "OK" if info.get("exists") else "PENDENTE"
        lines.append(f"- **{name}:** {status}")

    lines.append("")
    lines.append("## Relatórios e PDFs encontrados")
    lines.append("")
    if pdfs:
        for pdf in pdfs:
            lines.append(f"- `{pdf}`")
    else:
        lines.append("- Ainda não foram localizados PDFs nesta execução.")

    lines.append("")
    lines.append("## Leitura operacional")
    lines.append("")
    lines.append(
        "O Bloco 16 centralizou a execução em uma sessão única de auditoria, "
        "registrando evidências, status de módulos, relatórios produzidos e o "
        "estado final da entrega. Este manifesto passa a ser a referência principal "
        "para o fechamento técnico de cada cliente."
    )
    lines.append("")
    return "\n".join(lines)


def create_client_delivery_index(
    client_name: str,
    target: str,
    scan_dir: Path,
    manifest_path: Path,
    summary_path: Path,
    pdfs: List[str],
) -> Optional[Path]:
    client_slug = slugify(client_name)
    if not client_slug:
        client_slug = slugify(target)

    delivery_dir = CLIENTS_DIR / client_slug / "reports" / "unified-audit" / scan_dir.name
    ensure_dir(delivery_dir)

    index_path = delivery_dir / "delivery_index.md"

    lines = []
    lines.append("# CyberLab — Índice de Entrega Unificada")
    lines.append("")
    lines.append(f"**Cliente:** {client_name}")
    lines.append(f"**Alvo:** {target}")
    lines.append(f"**Scan:** `{scan_dir}`")
    lines.append("")
    lines.append("## Arquivos centrais")
    lines.append("")
    lines.append(f"- Manifesto JSON: `{manifest_path}`")
    lines.append(f"- Resumo final: `{summary_path}`")
    lines.append("")
    lines.append("## PDFs localizados")
    lines.append("")
    if pdfs:
        for pdf in pdfs:
            lines.append(f"- `{pdf}`")
    else:
        lines.append("- Nenhum PDF localizado.")

    write_text(index_path, "\n".join(lines))
    return index_path


def orchestrate(client_name: str, target: str, profile: str) -> int:
    start_time = now_iso()

    print("")
    print("=" * 72)
    print(" CyberLab — BLOCO 16 Unified Client Audit Orchestrator")
    print("=" * 72)
    print(f" Cliente: {client_name}")
    print(f" Alvo:   {target}")
    print(f" Perfil: {profile}")
    print(" Controle: execução sincronizada, escopo, logs e manifesto final")
    print("=" * 72)
    print("")

    # Bootstrap isolado da execução atual.
    # Nunca reutilizar o diretório block_16_unified_audit de scans antigos,
    # pois isso contamina logs, manifestos e status do novo scan.
    temp_base = RESULTS_WEB / target / "_block16_bootstrap"
    ensure_dir(temp_base)

    temp_block16 = temp_base / BLOCK16_DIRNAME
    if temp_block16.exists():
        shutil.rmtree(temp_block16, ignore_errors=True)
    ensure_dir(temp_block16)

    steps: List[Dict[str, Any]] = []

    # 01 — Health
    steps.append(run_step(
        "01_health",
        "Health do framework",
        cyberlab_cmd("health"),
        temp_block16,
        required=False,
        timeout=300,
    ))

    # 02 — Validate all
    steps.append(run_step(
        "02_validate_all",
        "Validação geral do framework",
        cyberlab_cmd("validate-all"),
        temp_block16,
        required=False,
        timeout=600,
    ))

    # 03 — Web Scan cria ou atualiza a sessão-base
    steps.append(run_step(
        "03_web_scan",
        "Reconhecimento web inicial",
        cyberlab_cmd("web", target),
        temp_block16,
        required=True,
        timeout=3600,
    ))

    scan_dir = latest_scan_dir(target)
    if scan_dir is None:
        print("[ERRO] Bloco 16 não conseguiu localizar a pasta oficial do scan após web scan.")
        return 2

    block16_dir = scan_dir / BLOCK16_DIRNAME
    ensure_dir(block16_dir)

    # Migra logs provisórios se a base mudou
    if temp_block16 != block16_dir and temp_block16.exists():
        for item in temp_block16.iterdir():
            dest = block16_dir / item.name
            if not dest.exists():
                try:
                    dest.write_text(item.read_text(encoding="utf-8"), encoding="utf-8")
                except Exception:
                    pass

    env_context = {
        "CYBERLAB_SCAN_DIR": str(scan_dir),
        "CYBERLAB_TARGET": target,
        "CYBERLAB_PROFILE": profile,
        "CYBERLAB_CLIENT_NAME": client_name,
    }

    scan_context = {
        "client_name": client_name,
        "client_slug": slugify(client_name),
        "target": target,
        "profile": profile,
        "scan_dir": str(scan_dir),
        "block16_dir": str(block16_dir),
        "created_at": start_time,
        "locked_at": now_iso(),
        "control_flags": {
            "scope_required": True,
            "approved_profile": profile,
            "execution_mode": "unified_client_audit",
        }
    }

    write_json(block16_dir / "scan_context.json", scan_context)

    print("")
    print("[B16] Sessão oficial travada:")
    print(f"      {scan_dir}")
    print("")

    # 03B — Camada 6A Surface Expansion
    steps.append(run_step(
        "03b_surface_expansion",
        "Camada 6A — expansão passiva de superfície",
        cyberlab_cmd("surface", target, str(scan_dir), profile),
        block16_dir,
        env_extra=env_context,
        required=False,
        timeout=3600,
    ))

    # 04 — Active
    steps.append(run_step(
        "04_active_mode",
        "Modo active controlado",
        cyberlab_cmd("active", "run", client_name, target, "active"),
        block16_dir,
        env_extra=env_context,
        required=False,
        timeout=3600,
    ))

    # 05 — Ferramentas auditadas
    steps.append(run_step(
        "05_tool_orchestrator",
        "Ferramentas auditadas com escopo aprovado",
        cyberlab_cmd("audit-tools-approved", target, profile),
        block16_dir,
        env_extra=env_context,
        required=False,
        timeout=7200,
    ))

    # 05B – Tool Output Intelligence
    steps.append(run_step(
        "05b_tool_output_intelligence",
        "Parser inteligente dos outputs das ferramentas auditadas",
        [
            sys.executable,
            str(CYBERLAB_HOME / "core" / "tool_output_parser.py"),
            "--scan-dir",
            str(scan_dir),
        ],
        block16_dir,
        env_extra=env_context,
        required=False,
        timeout=1200,
    ))

    # 06 — Bloco 12 / final atual
    steps.append(run_step(
        "06_final_block12_13",
        "Pipeline final atual: Bloco 12 + Bloco 13",
        cyberlab_cmd("final", target),
        block16_dir,
        env_extra=env_context,
        required=False,
        timeout=3600,
    ))

    # 07 — Bloco 14
    steps.append(run_step(
        "07_block14",
        "Validation Intelligence",
        cyberlab_cmd("block14", target),
        block16_dir,
        env_extra=env_context,
        required=False,
        timeout=3600,
    ))

    # 08 — Bloco 15
    steps.append(run_step(
        "08_block15",
        "Controlled Offensive Validation",
        cyberlab_cmd("block15", target, "controlled"),
        block16_dir,
        env_extra=env_context,
        required=False,
        timeout=3600,
    ))

    # 09 — Regeração final depois de 14 e 15
    steps.append(run_step(
        "09_final_refresh",
        "Regeração final pós-validações",
        cyberlab_cmd("final", target),
        block16_dir,
        env_extra=env_context,
        required=False,
        timeout=3600,
    ))

    outputs = detect_existing_outputs(scan_dir)
    pdfs = find_pdfs(scan_dir)
    status_counts = count_statuses(steps)
    final_status = pipeline_final_status(steps)

    manifest = {
        "block": "16",
        "name": "Unified Client Audit Orchestrator",
        "client_name": client_name,
        "target": target,
        "profile": profile,
        "scan_dir": str(scan_dir),
        "started_at": start_time,
        "finished_at": now_iso(),
        "final_status": final_status,
        "status_counts": status_counts,
        "steps": steps,
        "outputs": outputs,
        "pdfs": pdfs,
        "scan_context": scan_context,
    }

    status_json = {
        "ok": final_status in ("OK", "COMPLETED_WITH_WARNINGS"),
        "final_status": final_status,
        "client_name": client_name,
        "target": target,
        "profile": profile,
        "scan_dir": str(scan_dir),
        "status_counts": status_counts,
        "generated_at": now_iso(),
    }

    manifest_path = block16_dir / "block_16_manifest.json"
    status_path = block16_dir / "block_16_status.json"
    execution_log_path = block16_dir / "block_16_execution_log.md"
    client_summary_path = block16_dir / "block_16_client_summary.md"

    write_json(manifest_path, manifest)
    write_json(status_path, status_json)

    write_text(
        execution_log_path,
        build_execution_log(
            client_name=client_name,
            target=target,
            profile=profile,
            scan_dir=scan_dir,
            steps=steps,
            outputs=outputs,
            pdfs=pdfs,
            final_status=final_status,
        ),
    )

    write_text(
        client_summary_path,
        build_client_summary(
            client_name=client_name,
            target=target,
            profile=profile,
            scan_dir=scan_dir,
            final_status=final_status,
            outputs=outputs,
            pdfs=pdfs,
        ),
    )

    delivery_index = create_client_delivery_index(
        client_name=client_name,
        target=target,
        scan_dir=scan_dir,
        manifest_path=manifest_path,
        summary_path=client_summary_path,
        pdfs=pdfs,
    )

    print("")
    print("=" * 72)
    print(" BLOCO 16 FINALIZADO")
    print("=" * 72)
    print(f" Status final:      {final_status}")
    print(f" Cliente:           {client_name}")
    print(f" Alvo:              {target}")
    print(f" Pasta do scan:     {scan_dir}")
    print("")
    print(" Arquivos do Bloco 16:")
    print(f" - Contexto:        {block16_dir / 'scan_context.json'}")
    print(f" - Status:          {status_path}")
    print(f" - Manifesto:       {manifest_path}")
    print(f" - Log executivo:   {execution_log_path}")
    print(f" - Resumo cliente:  {client_summary_path}")
    if delivery_index:
        print(f" - Índice entrega:  {delivery_index}")
    print("")
    print(" PDFs detectados:")
    if pdfs:
        for pdf in pdfs:
            print(f" - {pdf}")
    else:
        print(" - Nenhum PDF localizado.")
    print("=" * 72)
    print("")

    return 0


def main() -> int:
    if len(sys.argv) < 4:
        print("Uso:")
        print('  python3 core/block_16_unified_orchestrator.py "Cliente" dominio.com perfil')
        return 1

    client_name = sys.argv[1]
    target = sys.argv[2]
    profile = sys.argv[3]

    return orchestrate(client_name, target, profile)


if __name__ == "__main__":
    raise SystemExit(main())
