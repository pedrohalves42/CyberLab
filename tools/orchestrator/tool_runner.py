#!/usr/bin/env python3
import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List


CYBERLAB_HOME = Path(os.environ.get("CYBERLAB_HOME", str(Path.home() / "CyberLab"))).expanduser()
REGISTRY_PATH = CYBERLAB_HOME / "tools/orchestrator/tool_registry.json"
RESULTS_ROOT = CYBERLAB_HOME / "results/web"
CLIENTS_ROOT = CYBERLAB_HOME / "clients"
AUDIT_ROOT = CYBERLAB_HOME / "state/audit"


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def clean_target(target: str) -> str:
    target = target.strip()
    target = target.replace("https://", "").replace("http://", "")
    target = target.split("/")[0]
    return target.lower()


def load_registry() -> Dict[str, Any]:
    if not REGISTRY_PATH.exists():
        raise SystemExit(f"[ERRO] Registry não encontrado: {REGISTRY_PATH}")
    return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))


def is_in_scope(target: str) -> bool:
    """
    Validação simples e conservadora:
    procura o domínio em arquivos dentro de clients/.
    """
    if not CLIENTS_ROOT.exists():
        return False

    for p in CLIENTS_ROOT.rglob("*"):
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore").lower()
        except Exception:
            continue

        if target in text:
            return True

    return False


def latest_scan_dir(target: str) -> Path:
    base = RESULTS_ROOT / target
    base.mkdir(parents=True, exist_ok=True)

    scans = sorted(
        [p for p in base.iterdir() if p.is_dir()],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    if scans:
        return scans[0]

    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    new_scan = base / stamp
    new_scan.mkdir(parents=True, exist_ok=True)
    return new_scan


def require_binary(binary: str) -> bool:
    return shutil.which(binary) is not None


def render_command(template: str, target: str, out: Path) -> str:
    return template.format(
        target=shlex.quote(target),
        out=shlex.quote(str(out)),
        root=shlex.quote(str(CYBERLAB_HOME)),
    )


def approval_required(tool: Dict[str, Any], mode: str, approve: bool) -> bool:
    if not tool.get("requires_approval"):
        return False

    if approve:
        return False

    return True


def run_tool(
    tool_id: str,
    tool: Dict[str, Any],
    target: str,
    out_dir: Path,
    approve: bool,
) -> Dict[str, Any]:
    binary = tool.get("binary")
    timeout = int(tool.get("timeout", 600))
    command_template = tool.get("command", "")

    result = {
        "tool_id": tool_id,
        "binary": binary,
        "category": tool.get("category"),
        "risk": tool.get("risk"),
        "requires_approval": tool.get("requires_approval", False),
        "started_at": now_iso(),
        "finished_at": None,
        "status": "PENDING",
        "exit_code": None,
        "command": None,
        "stdout_log": None,
        "stderr_log": None,
        "notes": []
    }

    if not require_binary(binary):
        result["status"] = "SKIPPED"
        result["notes"].append(f"Binário não encontrado no PATH: {binary}")
        result["finished_at"] = now_iso()
        return result

    if approval_required(tool, tool.get("risk"), approve):
        result["status"] = "SKIPPED_APPROVAL_REQUIRED"
        result["notes"].append("Ferramenta exige aprovação explícita.")
        result["finished_at"] = now_iso()
        return result

    tool_out = out_dir / tool_id
    tool_out.mkdir(parents=True, exist_ok=True)

    stdout_log = tool_out / "stdout.log"
    stderr_log = tool_out / "stderr.log"

    command = render_command(command_template, target, tool_out)

    result["command"] = command
    result["stdout_log"] = str(stdout_log)
    result["stderr_log"] = str(stderr_log)

    with stdout_log.open("w", encoding="utf-8") as so, stderr_log.open("w", encoding="utf-8") as se:
        so.write(f"# CyberLab tool run\n")
        so.write(f"# tool: {tool_id}\n")
        so.write(f"# target: {target}\n")
        so.write(f"# started_at: {result['started_at']}\n")
        so.write(f"# command: {command}\n\n")
        so.flush()

        try:
            proc = subprocess.run(
                command,
                shell=True,
                stdout=so,
                stderr=se,
                timeout=timeout,
            )
            result["exit_code"] = proc.returncode
            result["status"] = "OK" if proc.returncode == 0 else "COMPLETED_WITH_ERRORS"

            # Normalização do ZAP:
            # o Quick Start pode gerar o HTML corretamente e ainda assim
            # retornar código não-zero quando encerrado por timeout interno.
            if tool_id == "zap_baseline":
                zap_report = tool_out / "zap_baseline.html"
                if zap_report.exists() and zap_report.stat().st_size > 0:
                    if result["status"] != "OK":
                        result["status"] = "OK_REPORT_GENERATED_WITH_TIMEOUT"
                        result["notes"].append(
                            "Relatório HTML do ZAP foi gerado; processo encerrou com código não-zero/timeout."
                        )

            # Normalização semântica de ferramentas cujo exit code
            # pode representar um resultado válido, e não falha operacional.
            if tool_id == "wpscan_passive":
                wpscan_json = tool_out / "wpscan_passive.json"
                if wpscan_json.exists():
                    try:
                        wpscan_data = json.loads(wpscan_json.read_text(encoding="utf-8"))
                        scan_aborted = str(wpscan_data.get("scan_aborted", "")).strip()

                        if "does not seem to be running WordPress" in scan_aborted:
                            result["status"] = "OK_NOT_WORDPRESS"
                            result["notes"].append(
                                "WPScan executou corretamente e indicou que o alvo não aparenta usar WordPress."
                            )
                        elif scan_aborted:
                            result["notes"].append(
                                f"WPScan scan_aborted: {scan_aborted}"
                            )
                    except Exception as exc:
                        result["notes"].append(
                            f"Não foi possível interpretar o JSON do WPScan: {exc}"
                        )

            # Normalização semântica de ferramentas cujo exit code
            # pode representar um resultado válido, e não falha operacional.
            if tool_id == "wpscan_passive":
                wpscan_json = tool_out / "wpscan_passive.json"
                if wpscan_json.exists():
                    try:
                        wpscan_data = json.loads(wpscan_json.read_text(encoding="utf-8"))
                        scan_aborted = str(wpscan_data.get("scan_aborted", "")).strip()

                        if "does not seem to be running WordPress" in scan_aborted:
                            result["status"] = "OK_NOT_WORDPRESS"
                            result["notes"].append(
                                "WPScan executou corretamente e indicou que o alvo não aparenta usar WordPress."
                            )
                        elif scan_aborted:
                            result["notes"].append(
                                f"WPScan scan_aborted: {scan_aborted}"
                            )
                    except Exception as exc:
                        result["notes"].append(
                            f"Não foi possível interpretar o JSON do WPScan: {exc}"
                        )

        except subprocess.TimeoutExpired:
            result["status"] = "TIMEOUT"
            result["notes"].append(f"Timeout após {timeout}s.")

        except Exception as exc:
            result["status"] = "ERROR"
            result["notes"].append(str(exc))

    result["finished_at"] = now_iso()
    return result


def write_summary(
    target: str,
    profile: str,
    scan_dir: Path,
    out_dir: Path,
    results: List[Dict[str, Any]],
) -> None:
    ok = [r for r in results if str(r["status"]).startswith("OK")]
    skipped = [r for r in results if r["status"].startswith("SKIPPED")]
    errors = [r for r in results if r["status"] not in ("OK",) and not r["status"].startswith("SKIPPED")]

    summary = {
        "module": "CyberLab Tool Orchestrator",
        "target": target,
        "profile": profile,
        "generated_at": now_iso(),
        "scan_dir": str(scan_dir),
        "output_dir": str(out_dir),
        "summary": {
            "total": len(results),
            "ok": len(ok),
            "skipped": len(skipped),
            "errors": len(errors)
        },
        "results": results
    }

    (out_dir / "tool_run_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )

    lines = []
    lines.append("# CyberLab Tool Orchestrator")
    lines.append("")
    lines.append(f"**Alvo:** {target}")
    lines.append(f"**Perfil:** {profile}")
    lines.append(f"**Gerado em:** {summary['generated_at']}")
    lines.append(f"**Pasta do scan:** `{scan_dir}`")
    lines.append("")
    lines.append("## Resumo")
    lines.append("")
    lines.append(f"- Total: **{len(results)}**")
    lines.append(f"- OK: **{len(ok)}**")
    lines.append(f"- Ignorados: **{len(skipped)}**")
    lines.append(f"- Erros/alertas: **{len(errors)}**")
    lines.append("")
    lines.append("## Execuções")
    lines.append("")

    for r in results:
        lines.append(f"### {r['tool_id']}")
        lines.append("")
        lines.append(f"- Status: **{r['status']}**")
        lines.append(f"- Binário: `{r['binary']}`")
        lines.append(f"- Categoria: `{r.get('category')}`")
        lines.append(f"- Risco: `{r.get('risk')}`")
        lines.append(f"- Aprovação exigida: `{r.get('requires_approval')}`")
        lines.append(f"- Exit code: `{r.get('exit_code')}`")
        if r.get("command"):
            lines.append(f"- Comando auditado: `{r.get('command')}`")
        if r.get("stdout_log"):
            lines.append(f"- STDOUT: `{r.get('stdout_log')}`")
        if r.get("stderr_log"):
            lines.append(f"- STDERR: `{r.get('stderr_log')}`")
        for note in r.get("notes", []):
            lines.append(f"- Nota: {note}")
        lines.append("")

    (out_dir / "tool_run_summary.md").write_text("\n".join(lines), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="CyberLab controlled tool orchestrator")
    parser.add_argument("--target", required=True)
    parser.add_argument("--profile", default="safe", choices=["safe", "active", "active-plus", "max-controlled"])
    parser.add_argument("--approve", action="store_true", help="permite ferramentas que exigem aprovação")
    args = parser.parse_args()

    target = clean_target(args.target)
    registry = load_registry()

    print("============================================================")
    print(" CyberLab - Tool Orchestrator")
    print("============================================================")
    print(f"Alvo: {target}")
    print(f"Perfil: {args.profile}")
    print(f"Aprovação extra: {args.approve}")
    print("============================================================")

    if not is_in_scope(target):
        print(f"[BLOQUEADO] Alvo não encontrado no escopo de clientes: {target}")
        print("Adicione o cliente/escopo antes de executar.")
        sys.exit(1)

    profile_tools = registry["profiles"].get(args.profile, [])
    if not profile_tools:
        print(f"[ERRO] Perfil vazio ou inexistente: {args.profile}")
        sys.exit(1)

    scan_dir = latest_scan_dir(target)
    out_dir = scan_dir / "11-tool-orchestrator"
    out_dir.mkdir(parents=True, exist_ok=True)

    audit_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    audit_dir = AUDIT_ROOT / target / audit_id
    audit_dir.mkdir(parents=True, exist_ok=True)

    results = []

    for tool_id in profile_tools:
        tool = registry["tools"].get(tool_id)
        if not tool:
            results.append({
                "tool_id": tool_id,
                "status": "SKIPPED",
                "notes": ["Tool não encontrado no registry."]
            })
            continue

        print(f"[RUN] {tool_id}")
        result = run_tool(tool_id, tool, target, out_dir, args.approve)
        print(f"[{result['status']}] {tool_id}")
        results.append(result)

    write_summary(target, args.profile, scan_dir, out_dir, results)

    audit_copy = audit_dir / "tool_run_summary.json"
    audit_copy.write_text(
        (out_dir / "tool_run_summary.json").read_text(encoding="utf-8"),
        encoding="utf-8"
    )

    print("")
    print("[OK] Orquestração finalizada")
    print(f"Scan: {scan_dir}")
    print(f"Saída: {out_dir}")
    print(f"Auditoria: {audit_copy}")


if __name__ == "__main__":
    main()
