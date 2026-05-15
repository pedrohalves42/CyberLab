#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CyberLab — Camada 4C.2
Integridade de Severidade Técnica nos relatórios finais ao cliente.

Função:
- Lê findings_classified.json como fonte de verdade;
- Preserva severidade técnica original pós-calibração;
- Corrige relatórios polidos da 4C.1;
- Regrava os mesmos arquivos *_polished.md;
- Gera manifesto, status e resumo da correção;
- Atualiza o contexto oficial da auditoria.
"""

from __future__ import annotations

import json
import re
import shutil
import sys
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


CYBERLAB_HOME = Path.home() / "CyberLab"
GLOBAL_CONTEXT = CYBERLAB_HOME / "state" / "audit" / "current_audit_context.json"

OUTDIR_NAME = "block_17_client_final_delivery"

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

SEVERITY_LABELS_PT = {
    "CRITICAL": "Crítico",
    "HIGH": "Alto",
    "MEDIUM": "Médio",
    "LOW": "Baixo",
    "INFO": "Informativo",
}

CLIENT_CLASS_ORDER = [
    "RISCO_REAL",
    "REVISAR_MANUALMENTE",
    "PREVENCAO",
]


# ============================================================
# Utilitários
# ============================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat()


def load_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def file_record(path: Path) -> Dict[str, Any]:
    return {
        "path": str(path),
        "kind": "file",
        "exists": path.exists(),
        "size_bytes": path.stat().st_size if path.exists() else 0,
        "registered_at": now_iso(),
    }


def normalize_severity(value: Any) -> str:
    raw = str(value or "INFO").strip().upper()

    aliases = {
        "CRITICO": "CRITICAL",
        "CRÍTICO": "CRITICAL",
        "CRITICAL": "CRITICAL",

        "ALTO": "HIGH",
        "HIGH": "HIGH",

        "MEDIO": "MEDIUM",
        "MÉDIO": "MEDIUM",
        "MEDIUM": "MEDIUM",

        "BAIXO": "LOW",
        "LOW": "LOW",

        "INFORMATIVO": "INFO",
        "INFO": "INFO",
        "INFORMATIONAL": "INFO",
    }

    return aliases.get(raw, "INFO")


def severity_label_pt(value: Any) -> str:
    sev = normalize_severity(value)
    return SEVERITY_LABELS_PT.get(sev, "Informativo")


def normalize_client_class(value: Any) -> str:
    raw = str(value or "PREVENCAO").strip().upper()
    raw = raw.replace("ÇÃO", "CAO").replace("Ç", "C")
    raw = raw.replace(" ", "_").replace("-", "_")

    aliases = {
        "RISCO_REAL": "RISCO_REAL",
        "REVISAR_MANUALMENTE": "REVISAR_MANUALMENTE",
        "REVISAO_MANUAL": "REVISAR_MANUALMENTE",
        "REVISÃO_MANUAL": "REVISAR_MANUALMENTE",
        "PREVENCAO": "PREVENCAO",
        "PREVENÇÃO": "PREVENCAO",
        "MELHORIA_PREVENTIVA": "PREVENCAO",
    }

    return aliases.get(raw, raw)


def must_exist(path: Path, label: str) -> None:
    if not path.exists():
        raise SystemExit(f"[ERRO] {label} não encontrado: {path}")


def safe_backup(path: Path, backup_dir: Path) -> Path:
    backup_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = backup_dir / f"{path.stem}.pre_4c2.{ts}{path.suffix}"
    shutil.copy2(path, backup_path)
    return backup_path


# ============================================================
# Leitura de achados
# ============================================================

def load_findings(findings_path: Path) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    data = load_json(findings_path, {})
    if not isinstance(data, dict):
        raise SystemExit("[ERRO] findings_classified.json inválido.")

    findings = data.get("findings", [])
    if not isinstance(findings, list):
        raise SystemExit("[ERRO] Campo findings inválido em findings_classified.json.")

    normalized: List[Dict[str, Any]] = []

    for item in findings:
        if not isinstance(item, dict):
            continue

        normalized.append({
            **item,
            "_title": str(item.get("title") or "Achado técnico").strip(),
            "_severity": normalize_severity(item.get("severity")),
            "_severity_label_pt": severity_label_pt(item.get("severity")),
            "_client_class": normalize_client_class(item.get("client_classification")),
        })

    return data, normalized


def severity_counts(findings: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    counter = Counter(item["_severity"] for item in findings)
    return {sev: int(counter.get(sev, 0)) for sev in SEVERITY_ORDER}


def client_class_counts(findings: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    counter = Counter(item["_client_class"] for item in findings)
    return {cls: int(counter.get(cls, 0)) for cls in CLIENT_CLASS_ORDER}


def finding_queues_by_title(findings: Iterable[Dict[str, Any]]) -> Dict[str, deque]:
    buckets: Dict[str, deque] = defaultdict(deque)
    for item in findings:
        buckets[item["_title"]].append(item)
    return buckets


# ============================================================
# Correções de Markdown
# ============================================================

def build_severity_distribution_section(counts: Dict[str, int]) -> str:
    lines = [
        "## 3. Distribuição por severidade",
        "",
    ]

    for sev in SEVERITY_ORDER:
        value = int(counts.get(sev, 0))
        if value > 0:
            lines.append(f"- **{SEVERITY_LABELS_PT[sev]}:** {value}")

    if all(int(counts.get(sev, 0)) == 0 for sev in SEVERITY_ORDER):
        lines.append("- **Informativo:** 0")

    return "\n".join(lines).rstrip() + "\n\n"



def patch_technical_distribution(text: str, counts: Dict[str, int]) -> Tuple[str, bool]:
    """
    Reconstrói ou insere a distribuição por severidade no relatório técnico,
    aceitando variações reais de formatação das camadas 4C/4C.1.
    """
    replacement = build_severity_distribution_section(counts).rstrip().splitlines()

    lines = text.splitlines()

    start = None
    end = None

    for i, line in enumerate(lines):
        normalized = line.lower()
        if "distribui" in normalized and "severidade" in normalized:
            start = i
            break

    if start is not None:
        end = len(lines)
        for j in range(start + 1, len(lines)):
            stripped = lines[j].strip()
            if stripped.startswith("## ") or stripped.startswith("# "):
                end = j
                break

        new_lines = lines[:start] + replacement + [""] + lines[end:]
        return "\n".join(new_lines).rstrip() + "\n", True

    insert_at = None

    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("## 4.") or stripped.startswith("## Achados") or stripped.startswith("## Itens"):
            insert_at = i
            break

    if insert_at is None:
        insert_at = len(lines)

    new_lines = lines[:insert_at] + [""] + replacement + [""] + lines[insert_at:]
    return "\n".join(new_lines).rstrip() + "\n", True



def patch_technical_item_levels(
    text: str,
    findings: List[Dict[str, Any]],
) -> Tuple[str, int]:
    """
    Corrige severidade técnica no relatório técnico.
    Formato real encontrado:
    ### 1. Título do achado
    - **Nível técnico:** Informativo
    """
    corrections = 0
    lines = text.splitlines()

    title_to_severities: Dict[str, List[str]] = defaultdict(list)

    for item in findings:
        title_to_severities[item["_title"]].append(item["_severity_label_pt"])

    title_index: Dict[str, int] = defaultdict(int)
    current_title = None

    for i, line in enumerate(lines):
        stripped = line.strip()

        if stripped.startswith("###"):
            current_title = None

            for title in title_to_severities:
                if title in stripped:
                    current_title = title
                    break

            continue

        if current_title and "Nível técnico:" in line:
            idx = title_index[current_title]
            severities = title_to_severities[current_title]
            wanted = severities[idx] if idx < len(severities) else severities[-1]

            prefix = line.split("**Nível técnico:**", 1)[0]
            new_line = f"{prefix}**Nível técnico:** {wanted}"

            if line != new_line:
                lines[i] = new_line
                corrections += 1

            title_index[current_title] += 1
            current_title = None

    return "\n".join(lines).rstrip() + "\n", corrections


def patch_executive_real_risk_lines(
    text: str,
    real_findings: List[Dict[str, Any]],
) -> Tuple[str, int]:
    """
    Corrige a severidade exibida no relatório executivo.
    Formato real encontrado:
    - **Título do achado** — Informativo — Tema
    """
    corrections = 0
    lines = text.splitlines()

    for item in real_findings:
        title = item["_title"]
        wanted = item["_severity_label_pt"]

        for i, line in enumerate(lines):
            if title in line and "—" in line:
                parts = line.split("—")
                if len(parts) >= 3:
                    current = parts[1].strip()
                    if current != wanted:
                        parts[1] = f" {wanted} "
                        lines[i] = "—".join(parts)
                        corrections += 1
                break

    return "\n".join(lines).rstrip() + "\n", corrections



def patch_remediation_real_risk_levels(
    text: str,
    real_findings: List[Dict[str, Any]],
) -> Tuple[str, int]:
    """
    Corrige a severidade técnica no plano de remediação.
    Formato real encontrado:
    ### 1. Título
    - **Nível técnico:** Informativo
    """
    corrections = 0
    lines = text.splitlines()

    for item in real_findings:
        title = item["_title"]
        wanted = item["_severity_label_pt"]

        in_target_block = False

        for i, line in enumerate(lines):
            stripped = line.strip()

            if stripped.startswith("###") and title in stripped:
                in_target_block = True
                continue

            if in_target_block and stripped.startswith("###"):
                in_target_block = False

            if in_target_block and "Nível técnico:" in line:
                prefix = line.split("**Nível técnico:**", 1)[0]
                new_line = f"{prefix}**Nível técnico:** {wanted}"

                if line != new_line:
                    lines[i] = new_line
                    corrections += 1

                break

    return "\n".join(lines).rstrip() + "\n", corrections


# ============================================================
# Validação de integridade pós-correção
# ============================================================


def validate_distribution(text: str, counts: Dict[str, int]) -> List[str]:
    """
    Valida a distribuição por severidade em formato textual,
    sem depender de uma marcação Markdown rígida.
    """
    errors: List[str] = []

    normalized_text = text.lower()

    for sev in SEVERITY_ORDER:
        amount = int(counts.get(sev, 0))
        if amount <= 0:
            continue

        label = SEVERITY_LABELS_PT[sev]
        expected_1 = f"{label.lower()}: {amount}"
        expected_2 = f"**{label.lower()}:** {amount}"

        if expected_1 not in normalized_text and expected_2 not in normalized_text:
            errors.append(
                f"Distribuição técnica não contém '{label}: {amount}'."
            )

    return errors


def find_wrong_real_risk_severity_mentions(
    text: str,
    real_findings: List[Dict[str, Any]],
) -> List[str]:
    """
    Verifica apenas se o bloco do achado real ainda possui
    'Nível técnico: Informativo' quando o JSON exige nível maior.
    """
    errors: List[str] = []
    lines = text.splitlines()

    for item in real_findings:
        title = item["_title"]
        wanted = item["_severity_label_pt"]

        if wanted == "Informativo":
            continue

        in_block = False
        for line in lines:
            stripped = line.strip()

            if title in stripped:
                in_block = True
                continue

            if in_block and stripped.startswith("###"):
                in_block = False

            if in_block and "Nível técnico:" in line and "Informativo" in line:
                errors.append(
                    f"Achado '{title}' ainda aparece como Informativo, mas deveria ser {wanted}."
                )
                break

    return errors

# ============================================================
# Contexto oficial
# ============================================================

def update_context_file(
    context_path: Path,
    stage_payload: Dict[str, Any],
    artifacts: Dict[str, Dict[str, Any]],
) -> None:
    if not context_path.exists():
        return

    ctx = load_json(context_path, {})
    if not isinstance(ctx, dict):
        return

    stages = ctx.setdefault("stages", {})
    stages["block17_4c2_technical_severity_integrity_fix"] = stage_payload

    ctx_artifacts = ctx.setdefault("artifacts", {})
    ctx_artifacts.update(artifacts)

    write_json(context_path, ctx)


# ============================================================
# Execução principal
# ============================================================

def main() -> int:
    if len(sys.argv) < 2:
        print("[ERRO] Informe a pasta oficial do scan.")
        print("Uso: python3 technical_severity_integrity_fix.py /caminho/do/scan")
        return 1

    scan_dir = Path(sys.argv[1]).expanduser().resolve()
    out_dir = scan_dir / OUTDIR_NAME

    findings_path = out_dir / "findings_classified.json"

    executive_md = out_dir / "client_final_executive_report_polished.md"
    technical_md = out_dir / "client_final_technical_report_polished.md"
    remediation_md = out_dir / "client_final_remediation_plan_polished.md"

    status_json = out_dir / "block_17_4c2_status.json"
    summary_md = out_dir / "block_17_4c2_summary.md"
    manifest_json = out_dir / "client_final_severity_integrity_manifest.json"

    backup_dir = out_dir / "4c2_integrity_backups"

    must_exist(scan_dir, "Pasta do scan")
    must_exist(out_dir, "Diretório de entrega final")
    must_exist(findings_path, "findings_classified.json")
    must_exist(executive_md, "Relatório executivo polido")
    must_exist(technical_md, "Relatório técnico polido")
    must_exist(remediation_md, "Plano de remediação polido")

    started_at = now_iso()

    findings_data, findings = load_findings(findings_path)

    sev_counts = severity_counts(findings)
    cls_counts = client_class_counts(findings)

    real_findings = [
        item for item in findings
        if item["_client_class"] == "RISCO_REAL"
    ]

    # Backup dos markdowns antes da correção
    backups = {
        "executive_before_4c2": safe_backup(executive_md, backup_dir),
        "technical_before_4c2": safe_backup(technical_md, backup_dir),
        "remediation_before_4c2": safe_backup(remediation_md, backup_dir),
    }

    executive_text = executive_md.read_text(encoding="utf-8")
    technical_text = technical_md.read_text(encoding="utf-8")
    remediation_text = remediation_md.read_text(encoding="utf-8")

    # Correções
    technical_text, distribution_rebuilt = patch_technical_distribution(
        technical_text,
        sev_counts,
    )

    technical_text, tech_item_corrections = patch_technical_item_levels(
        technical_text,
        findings,
    )

    executive_text, executive_corrections = patch_executive_real_risk_lines(
        executive_text,
        real_findings,
    )

    remediation_text, remediation_corrections = patch_remediation_real_risk_levels(
        remediation_text,
        real_findings,
    )

    # Validações
    validation_errors: List[str] = []

    if not distribution_rebuilt:
        validation_errors.append(
            "Não foi possível localizar a seção de distribuição por severidade no relatório técnico."
        )

    validation_errors.extend(
        validate_distribution(technical_text, sev_counts)
    )

    validation_errors.extend(
        find_wrong_real_risk_severity_mentions(executive_text, real_findings)
    )

    validation_errors.extend(
        find_wrong_real_risk_severity_mentions(remediation_text, real_findings)
    )

    if validation_errors:
        status = {
            "ok": False,
            "status": "FAILED_VALIDATION",
            "stage": "block17_4c2_technical_severity_integrity_fix",
            "scan_dir": str(scan_dir),
            "started_at": started_at,
            "finished_at": now_iso(),
            "errors": validation_errors,
            "severity_counts": sev_counts,
            "client_classification_counts": cls_counts,
        }
        write_json(status_json, status)

        print("[ERRO] A Camada 4C.2 encontrou inconsistências e não concluiu.")
        for err in validation_errors:
            print(f"  - {err}")
        return 2

    # Escrita final dos relatórios polidos corrigidos
    write_text(executive_md, executive_text)
    write_text(technical_md, technical_text)
    write_text(remediation_md, remediation_text)

    total_corrections = (
        tech_item_corrections
        + executive_corrections
        + remediation_corrections
        + (1 if distribution_rebuilt else 0)
    )

    manifest = {
        "schema": "cyberlab.block17.4c2.severity_integrity_manifest.v1",
        "stage": "block17_4c2_technical_severity_integrity_fix",
        "scan_dir": str(scan_dir),
        "generated_at": now_iso(),
        "source_of_truth": str(findings_path),
        "severity_counts": sev_counts,
        "client_classification_counts": cls_counts,
        "corrections": {
            "distribution_section_rebuilt": distribution_rebuilt,
            "technical_item_level_corrections": tech_item_corrections,
            "executive_real_risk_corrections": executive_corrections,
            "remediation_real_risk_corrections": remediation_corrections,
            "total_corrections": total_corrections,
        },
        "outputs": {
            "executive_polished_md": str(executive_md),
            "technical_polished_md": str(technical_md),
            "remediation_polished_md": str(remediation_md),
            "backup_dir": str(backup_dir),
        },
        "backups": {k: str(v) for k, v in backups.items()},
    }

    status = {
        "ok": True,
        "status": "OK",
        "stage": "block17_4c2_technical_severity_integrity_fix",
        "scan_dir": str(scan_dir),
        "started_at": started_at,
        "finished_at": now_iso(),
        "severity_counts": sev_counts,
        "client_classification_counts": cls_counts,
        "corrections": manifest["corrections"],
        "status_json": str(status_json),
        "summary_md": str(summary_md),
        "manifest_json": str(manifest_json),
    }

    summary = f"""# CyberLab — Camada 4C.2

## Integridade de Severidade Técnica

- **Scan oficial:** `{scan_dir}`
- **Fonte de verdade:** `{findings_path}`
- **Status:** OK
- **Gerado em:** {status["finished_at"]}

## Classificação final preservada

- **Risco real:** {cls_counts.get("RISCO_REAL", 0)}
- **Revisar manualmente:** {cls_counts.get("REVISAR_MANUALMENTE", 0)}
- **Prevenção / melhoria:** {cls_counts.get("PREVENCAO", 0)}

## Distribuição técnica restaurada

- **Crítico:** {sev_counts.get("CRITICAL", 0)}
- **Alto:** {sev_counts.get("HIGH", 0)}
- **Médio:** {sev_counts.get("MEDIUM", 0)}
- **Baixo:** {sev_counts.get("LOW", 0)}
- **Informativo:** {sev_counts.get("INFO", 0)}

## Ajustes executados

- **Distribuição técnica reconstruída:** {"sim" if distribution_rebuilt else "não"}
- **Correções em itens do relatório técnico:** {tech_item_corrections}
- **Correções no relatório executivo:** {executive_corrections}
- **Correções no plano de remediação:** {remediation_corrections}
- **Total de ajustes registrados:** {total_corrections}

## Arquivos corrigidos

- `{executive_md}`
- `{technical_md}`
- `{remediation_md}`

## Backups preservados

- `{backups["executive_before_4c2"]}`
- `{backups["technical_before_4c2"]}`
- `{backups["remediation_before_4c2"]}`

## Observação metodológica

Esta camada impede que o polimento editorial ou a montagem dos relatórios finais
achatem a severidade técnica real dos achados.  
A classificação para cliente final continua separada da severidade técnica,
preservando clareza comercial sem perder fidelidade analítica.
"""

    write_json(manifest_json, manifest)
    write_json(status_json, status)
    write_text(summary_md, summary)

    artifacts = {
        "block17_4c2_status_json": file_record(status_json),
        "block17_4c2_summary_md": file_record(summary_md),
        "block17_4c2_manifest_json": file_record(manifest_json),
        "block17_4c2_executive_polished_md": file_record(executive_md),
        "block17_4c2_technical_polished_md": file_record(technical_md),
        "block17_4c2_remediation_polished_md": file_record(remediation_md),
    }

    stage_payload = {
        "schema": "cyberlab.block17.4c2.status.v1",
        "status": "OK",
        "message": "Severidade técnica preservada e relatórios finais corrigidos antes dos PDFs.",
        "updated_at": now_iso(),
        "scan_dir": str(scan_dir),
        "severity_counts": sev_counts,
        "client_classification_counts": cls_counts,
        "corrections": manifest["corrections"],
        "status_json": str(status_json),
        "summary_md": str(summary_md),
        "manifest_json": str(manifest_json),
    }

    update_context_file(GLOBAL_CONTEXT, stage_payload, artifacts)

    scan_local_context = scan_dir / "block_16_unified_audit" / "audit_context.json"
    update_context_file(scan_local_context, stage_payload, artifacts)

    print("")
    print("=" * 72)
    print(" CyberLab — Camada 4C.2")
    print(" Integridade de severidade técnica dos relatórios finais")
    print("=" * 72)
    print(f"[OK] Scan oficial: {scan_dir}")
    print(f"[OK] Achados avaliados: {len(findings)}")
    print("")
    print("[SEVERIDADE TÉCNICA RESTAURADA]")
    print(f" - CRITICAL: {sev_counts.get('CRITICAL', 0)}")
    print(f" - HIGH:     {sev_counts.get('HIGH', 0)}")
    print(f" - MEDIUM:   {sev_counts.get('MEDIUM', 0)}")
    print(f" - LOW:      {sev_counts.get('LOW', 0)}")
    print(f" - INFO:     {sev_counts.get('INFO', 0)}")
    print("")
    print("[CORREÇÕES]")
    print(f" - Distribuição técnica reconstruída: {'SIM' if distribution_rebuilt else 'NÃO'}")
    print(f" - Itens técnicos corrigidos:         {tech_item_corrections}")
    print(f" - Executivo corrigido:               {executive_corrections}")
    print(f" - Remediação corrigida:              {remediation_corrections}")
    print(f" - Total de ajustes:                   {total_corrections}")
    print("")
    print("[ARQUIVOS GERADOS]")
    print(f" - {status_json}")
    print(f" - {summary_md}")
    print(f" - {manifest_json}")
    print("")
    print("[OK] Contexto oficial da auditoria atualizado com a Camada 4C.2.")
    print("[OK] Camada 4C.2 finalizada.")
    print("=" * 72)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
