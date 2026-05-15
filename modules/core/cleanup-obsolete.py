#!/usr/bin/env python3
from __future__ import annotations

import json
import shutil
import hashlib
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
import sys


HOME = Path.home() / "CyberLab"
QUARANTINE_ROOT = HOME / "quarantine" / "obsolete"
STATE_DIR = HOME / "state" / "cleanup"
RESULTS_DIR = HOME / "results"


@dataclass
class CleanupItem:
    source: str
    destination: str
    category: str
    reason: str
    size_bytes: int
    sha256: str
    action: str


def sha256_file(path: Path) -> str:
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def folder_size(path: Path) -> int:
    if path.is_file():
        try:
            return path.stat().st_size
        except Exception:
            return 0

    total = 0
    for item in path.rglob("*"):
        if item.is_file():
            try:
                total += item.stat().st_size
            except Exception:
                pass
    return total


def safe_sha(path: Path) -> str:
    if path.is_file():
        return sha256_file(path)
    return ""


def is_inside(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except Exception:
        return False


def latest_web_scans() -> set[Path]:
    keep: set[Path] = set()
    web_root = RESULTS_DIR / "web"
    if not web_root.exists():
        return keep

    for domain_dir in web_root.iterdir():
        if not domain_dir.is_dir():
            continue
        scans = sorted([p for p in domain_dir.iterdir() if p.is_dir()])
        if scans:
            keep.add(scans[-1].resolve())
    return keep


def candidate_backup_roots() -> list[tuple[Path, str, str]]:
    candidates: list[tuple[Path, str, str]] = []

    patterns = [
        ("tools.backup.*", "BACKUP_TREE", "Backup antigo da árvore tools"),
        ("modules.backup.*", "BACKUP_TREE", "Backup antigo da árvore modules"),
        ("core.backup.*", "BACKUP_TREE", "Backup antigo da árvore core"),
        ("bin.backup.*", "BACKUP_TREE", "Backup antigo da árvore bin"),
        ("results.backup.*", "BACKUP_TREE", "Backup antigo da árvore results"),
    ]

    for pattern, category, reason in patterns:
        for path in HOME.glob(pattern):
            if path.exists():
                candidates.append((path, category, reason))

    return candidates


def candidate_backup_files() -> list[tuple[Path, str, str]]:
    candidates: list[tuple[Path, str, str]] = []

    scan_roots = [
        HOME / "modules",
        HOME / "core",
        HOME / "tools",
        HOME / "bin",
    ]

    for root in scan_roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue

            name = path.name.lower()
            if ".backup." in name or name.endswith(".bak") or name.endswith(".old"):
                candidates.append((
                    path,
                    "BACKUP_FILE",
                    "Arquivo de backup antigo gerado por correção manual"
                ))

    return candidates


def candidate_broken_threat_json() -> list[tuple[Path, str, str]]:
    candidates: list[tuple[Path, str, str]] = []
    threat_root = RESULTS_DIR / "threat"

    if not threat_root.exists():
        return candidates

    for path in threat_root.rglob("*.json"):
        if not path.is_file():
            continue

        try:
            json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            candidates.append((
                path,
                "BROKEN_LEGACY_JSON",
                "JSON legado inválido em results/threat"
            ))

    return candidates


def destination_for(path: Path, batch_dir: Path, category: str) -> Path:
    try:
        rel = path.resolve().relative_to(HOME.resolve())
    except Exception:
        rel = Path(path.name)

    return batch_dir / category.lower() / rel


def move_item(path: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(path), str(dst))


def write_reports(
    batch_dir: Path,
    mode: str,
    items: list[CleanupItem],
    summary: dict
) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    batch_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "module": "CyberLab Cleanup Obsolete",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "mode": mode,
        "summary": summary,
        "items": [asdict(i) for i in items],
    }

    manifest_path = batch_dir / "cleanup_manifest.json"
    state_manifest = STATE_DIR / "latest_cleanup_manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )
    state_manifest.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    report_lines = [
        "# CyberLab — Cleanup Obsolete Report",
        "",
        f"**Gerado em:** {manifest['generated_at']}",
        f"**Modo:** `{mode}`",
        "",
        "## Resumo",
        "",
        f"- Itens avaliados: **{summary['candidates']}**",
        f"- Itens processados: **{summary['processed']}**",
        f"- Tamanho total estimado: **{summary['total_size_bytes']} bytes**",
        f"- Pasta de quarentena: `{batch_dir}`",
        "",
        "## Itens",
        "",
    ]

    if not items:
        report_lines.append("Nenhum item obsoleto identificado.")
    else:
        for idx, item in enumerate(items, start=1):
            report_lines.extend([
                f"### {idx}. {item.category}",
                "",
                f"- **Origem:** `{item.source}`",
                f"- **Destino:** `{item.destination}`",
                f"- **Motivo:** {item.reason}",
                f"- **Ação:** `{item.action}`",
                f"- **Tamanho:** `{item.size_bytes}` bytes",
                f"- **SHA256:** `{item.sha256 or 'N/A para diretório'}`",
                "",
            ])

    report = "\n".join(report_lines) + "\n"

    report_path = batch_dir / "cleanup_report.md"
    state_report = STATE_DIR / "latest_cleanup_report.md"
    report_path.write_text(report, encoding="utf-8")
    state_report.write_text(report, encoding="utf-8")


def main() -> int:
    mode = sys.argv[1].strip().lower() if len(sys.argv) > 1 else "dry-run"

    if mode not in {"dry-run", "apply"}:
        print("[ERRO] Uso: cleanup-obsolete.py [dry-run|apply]")
        return 2

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    batch_dir = QUARANTINE_ROOT / timestamp

    keep_scans = latest_web_scans()

    raw_candidates: list[tuple[Path, str, str]] = []
    raw_candidates.extend(candidate_backup_roots())
    raw_candidates.extend(candidate_backup_files())
    raw_candidates.extend(candidate_broken_threat_json())

    seen = set()
    candidates: list[tuple[Path, str, str]] = []

    for path, category, reason in raw_candidates:
        if not path.exists():
            continue

        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)

        # Segurança: nunca tocar no scan web atual de cada domínio
        if any(is_inside(resolved, scan) for scan in keep_scans):
            continue

        candidates.append((path, category, reason))

    items: list[CleanupItem] = []
    total_size = 0

    print("==============================================================")
    print(" CyberLab — Cleanup Obsolete")
    print("==============================================================")
    print(f"Modo: {mode}")
    print(f"Candidatos encontrados: {len(candidates)}")
    print("")

    for path, category, reason in candidates:
        dst = destination_for(path, batch_dir, category)
        size = folder_size(path)
        digest = safe_sha(path)
        total_size += size

        action = "WOULD_MOVE" if mode == "dry-run" else "MOVED"

        print(f"[{action}] {path}")
        print(f"         -> {dst}")
        print(f"         categoria={category} | tamanho={size} bytes")
        print("")

        if mode == "apply":
            move_item(path, dst)

        items.append(CleanupItem(
            source=str(path),
            destination=str(dst),
            category=category,
            reason=reason,
            size_bytes=size,
            sha256=digest,
            action=action
        ))

    summary = {
        "candidates": len(candidates),
        "processed": len(items),
        "total_size_bytes": total_size,
        "quarantine_dir": str(batch_dir),
    }

    write_reports(batch_dir, mode, items, summary)

    print("==============================================================")
    print("[OK] Camada 2 concluída.")
    print(f"[OK] Manifesto: {batch_dir / 'cleanup_manifest.json'}")
    print(f"[OK] Relatório: {batch_dir / 'cleanup_report.md'}")
    print(f"[OK] Estado atual: {STATE_DIR / 'latest_cleanup_manifest.json'}")
    print("==============================================================")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
