#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

CYBERLAB_HOME = Path(__file__).resolve().parents[1]
STATE_DIR = CYBERLAB_HOME / "state" / "audit"
CONTEXT_FILE = STATE_DIR / "current_audit_context.json"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ensure_dirs() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)


def atomic_write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".audit-context-", suffix=".json", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")
        tmp_path.replace(path)
    finally:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)


def load_context(required: bool = False) -> Dict[str, Any]:
    if not CONTEXT_FILE.exists():
        if required:
            raise FileNotFoundError(f"Contexto não encontrado: {CONTEXT_FILE}")
        return {}
    try:
        return json.loads(CONTEXT_FILE.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"Contexto JSON inválido em {CONTEXT_FILE}: {exc}") from exc


def save_context(ctx: Dict[str, Any]) -> Dict[str, Any]:
    ensure_dirs()
    ctx["updated_at"] = now_iso()
    atomic_write_json(CONTEXT_FILE, ctx)
    mirror_into_scan(ctx)
    return ctx


def normalize_target(target: str) -> str:
    target = (target or "").strip()
    target = target.replace("https://", "").replace("http://", "")
    target = target.strip().strip("/")
    return target


def session_id_for(target: str) -> str:
    safe_target = normalize_target(target).replace("/", "_") or "unknown-target"
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{stamp}__{safe_target}"


def start_context(client_name: str, target: str, profile: str) -> Dict[str, Any]:
    target = normalize_target(target)
    ctx: Dict[str, Any] = {
        "schema": "cyberlab.audit-context.v1",
        "session_id": session_id_for(target),
        "client_name": client_name,
        "target": target,
        "profile": profile,
        "status": "RUNNING",
        "started_at": now_iso(),
        "updated_at": now_iso(),
        "finished_at": None,
        "scan_dir": None,
        "paths": {
            "cyberlab_home": str(CYBERLAB_HOME),
            "context_file": str(CONTEXT_FILE),
            "results_web_root": str(CYBERLAB_HOME / "results" / "web" / target),
        },
        "stages": {},
        "artifacts": {},
        "warnings": [],
        "errors": [],
        "notes": [
            "Contexto oficial iniciado pela Camada 3.",
            "Todos os módulos devem preferir este contexto à descoberta manual de latest scan."
        ]
    }
    return save_context(ctx)


def set_scan_dir(scan_dir: str | Path) -> Dict[str, Any]:
    ctx = load_context(required=True)
    p = Path(scan_dir).expanduser().resolve()
    ctx["scan_dir"] = str(p)
    ctx.setdefault("paths", {})["scan_dir"] = str(p)
    ctx["paths"]["block16_dir"] = str(p / "block_16_unified_audit")
    return save_context(ctx)


def mark_stage(
    stage: str,
    status: str,
    message: str = "",
    stdout_log: Optional[str] = None,
    stderr_log: Optional[str] = None,
) -> Dict[str, Any]:
    ctx = load_context(required=True)
    stages = ctx.setdefault("stages", {})
    prev = stages.get(stage, {})
    stages[stage] = {
        "status": status,
        "message": message,
        "updated_at": now_iso(),
        "stdout_log": stdout_log or prev.get("stdout_log"),
        "stderr_log": stderr_log or prev.get("stderr_log"),
    }
    return save_context(ctx)


def add_artifact(name: str, path: str | Path, kind: str = "file") -> Dict[str, Any]:
    ctx = load_context(required=True)
    p = Path(path).expanduser()
    ctx.setdefault("artifacts", {})[name] = {
        "path": str(p),
        "kind": kind,
        "exists": p.exists(),
        "registered_at": now_iso(),
    }
    return save_context(ctx)


def add_warning(message: str) -> Dict[str, Any]:
    ctx = load_context(required=True)
    ctx.setdefault("warnings", []).append({
        "at": now_iso(),
        "message": message,
    })
    return save_context(ctx)


def add_error(message: str) -> Dict[str, Any]:
    ctx = load_context(required=True)
    ctx.setdefault("errors", []).append({
        "at": now_iso(),
        "message": message,
    })
    return save_context(ctx)


def finish_context(status: str) -> Dict[str, Any]:
    ctx = load_context(required=True)
    ctx["status"] = status
    ctx["finished_at"] = now_iso()
    return save_context(ctx)


def mirror_into_scan(ctx: Dict[str, Any]) -> None:
    scan_dir = ctx.get("scan_dir")
    if not scan_dir:
        return
    try:
        scan_path = Path(scan_dir)
        block16_dir = scan_path / "block_16_unified_audit"
        block16_dir.mkdir(parents=True, exist_ok=True)
        atomic_write_json(block16_dir / "audit_context.json", ctx)
    except Exception:
        # Nunca derrubar pipeline por falha no espelhamento secundário.
        pass


def validate_context() -> int:
    try:
        ctx = load_context(required=True)
    except Exception as exc:
        print(f"[ERRO] {exc}")
        return 1

    required = ["schema", "session_id", "client_name", "target", "profile", "status"]
    missing = [k for k in required if not ctx.get(k)]
    if missing:
        print(f"[ERRO] Campos obrigatórios ausentes: {', '.join(missing)}")
        return 1

    print("[OK] Contexto encontrado e JSON válido.")
    print(f"[OK] Sessão: {ctx.get('session_id')}")
    print(f"[OK] Cliente: {ctx.get('client_name')}")
    print(f"[OK] Alvo: {ctx.get('target')}")
    print(f"[OK] Perfil: {ctx.get('profile')}")
    print(f"[OK] Status: {ctx.get('status')}")

    scan_dir = ctx.get("scan_dir")
    if scan_dir:
        if Path(scan_dir).exists():
            print(f"[OK] Scan oficial: {scan_dir}")
        else:
            print(f"[WARN] Scan oficial registrado, mas diretório não existe: {scan_dir}")
    else:
        print("[WARN] Scan oficial ainda não registrado.")

    return 0


def show_context() -> int:
    ctx = load_context(required=False)
    if not ctx:
        print("=== CyberLab Audit Context ===")
        print("[WARN] Nenhum contexto de auditoria ativo encontrado.")
        return 0

    print("=== CyberLab Audit Context ===")
    print(f"Status:      {ctx.get('status')}")
    print(f"Sessão:      {ctx.get('session_id')}")
    print(f"Cliente:     {ctx.get('client_name')}")
    print(f"Alvo:        {ctx.get('target')}")
    print(f"Perfil:      {ctx.get('profile')}")
    print(f"Iniciado:    {ctx.get('started_at')}")
    print(f"Atualizado:  {ctx.get('updated_at')}")
    print(f"Finalizado:  {ctx.get('finished_at') or '-'}")
    print(f"Scan oficial:{' ' + ctx.get('scan_dir') if ctx.get('scan_dir') else ' [pendente]'}")

    stages = ctx.get("stages", {})
    print("")
    print("Etapas:")
    if not stages:
        print("  [WARN] Nenhuma etapa registrada.")
    else:
        for name, data in stages.items():
            print(f"  - {name}: {data.get('status')}")

    artifacts = ctx.get("artifacts", {})
    print("")
    print("Artefatos registrados:")
    if not artifacts:
        print("  [WARN] Nenhum artefato registrado.")
    else:
        for name, data in artifacts.items():
            exists = "OK" if data.get("exists") else "MISSING"
            print(f"  - [{exists}] {name}: {data.get('path')}")

    if ctx.get("warnings"):
        print("")
        print(f"Warnings: {len(ctx['warnings'])}")

    if ctx.get("errors"):
        print(f"Erros:    {len(ctx['errors'])}")

    return 0


def print_context_path() -> int:
    print(CONTEXT_FILE)
    return 0


def print_json() -> int:
    ctx = load_context(required=False)
    print(json.dumps(ctx, ensure_ascii=False, indent=2))
    return 0


def main(argv: list[str]) -> int:
    cmd = argv[1] if len(argv) > 1 else "show"

    if cmd in ("show", "status"):
        return show_context()
    if cmd == "path":
        return print_context_path()
    if cmd == "json":
        return print_json()
    if cmd in ("validate", "check"):
        return validate_context()

    print("[ERRO] Subcomando desconhecido.")
    print("Uso:")
    print("  cyberlab audit-context show")
    print("  cyberlab audit-context path")
    print("  cyberlab audit-context json")
    print("  cyberlab audit-context validate")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
