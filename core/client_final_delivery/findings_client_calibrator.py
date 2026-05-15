#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CyberLab — Camada 4A.1
Calibração final de achados para linguagem e classificação de entrega ao cliente.

Objetivo:
- Reclassificar os achados consolidados da 4A em:
  - RISCO_REAL
  - REVISAR_MANUALMENTE
  - PREVENCAO
- Evitar que achados genéricos ou informativos sejam apresentados como risco real.
- Atualizar:
  - findings_classified.json
  - block_17_4a_summary.md
  - block_17_4a_status.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter
from typing import Any, Dict, List, Tuple


GENERIC_TITLES = {
    "",
    "achado técnico",
    "achado tecnico",
    "technical finding",
    "finding",
    "generic finding",
}

GENERIC_CATEGORIES = {
    "",
    "GENERIC",
    "INFO",
    "INFORMATIONAL",
    "UNKNOWN",
    "UNCLASSIFIED",
}

REAL_STATUSES = {
    "CONFIRMADO",
    "CONFIRMADO_PROVAVEL",
    "CONFIRMADO_POTENCIAL",
    "CONFIRMED",
    "LIKELY_CONFIRMED",
}

MANUAL_STATUSES = {
    "REVISAR_MANUALMENTE",
    "SUSPEITO_FORTE",
    "MANUAL_REVIEW",
    "NEEDS_REVIEW",
}

PREVENTION_STATUSES = {
    "INFORMATIVO",
    "INFO",
    "PREVENCAO",
    "PREVENTION",
    "OBSERVACAO",
}


def norm(value: Any) -> str:
    return str(value or "").strip()


def upper(value: Any) -> str:
    return norm(value).upper()


def lower(value: Any) -> str:
    return norm(value).lower()


def first_text(obj: Dict[str, Any], keys: List[str]) -> str:
    for key in keys:
        val = obj.get(key)
        if val is not None and str(val).strip():
            return str(val).strip()
    return ""


def find_findings_container(data: Dict[str, Any]) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Localiza de forma tolerante a lista de achados dentro do JSON 4A.
    """
    preferred_keys = [
        "findings",
        "classified_findings",
        "items",
        "records",
        "results",
    ]

    for key in preferred_keys:
        value = data.get(key)
        if isinstance(value, list) and all(isinstance(x, dict) for x in value):
            return key, value

    # fallback: primeira lista de dicts suficientemente parecida com achados
    for key, value in data.items():
        if isinstance(value, list) and value and all(isinstance(x, dict) for x in value):
            sample = value[0]
            probable_fields = {"title", "severity", "category", "status", "review_status"}
            if probable_fields.intersection(sample.keys()):
                return key, value

    raise SystemExit("[ERRO] Não encontrei a lista de achados dentro do findings_classified.json.")


def has_meaningful_evidence(f: Dict[str, Any]) -> bool:
    evidence = first_text(f, ["evidence", "proof", "details", "description", "impact"])
    if not evidence:
        return False

    weak = {
        "n/a",
        "none",
        "null",
        "-",
        "sem evidência",
        "sem evidencia",
        "not available",
    }
    return lower(evidence) not in weak


def is_generic_title(title: str) -> bool:
    t = lower(title)
    return t in GENERIC_TITLES or t.startswith("achado técnico") or t.startswith("achado tecnico")


def classify_for_client(f: Dict[str, Any]) -> Tuple[str, str, int]:
    """
    Retorna:
    - classificação cliente
    - justificativa
    - confiança 0-100
    """
    title = first_text(f, ["title", "name", "finding_title"])
    category = upper(first_text(f, ["category", "type", "class"]))
    severity = upper(first_text(f, ["severity", "level", "risk"]))
    review_status = upper(first_text(f, ["review_status", "status", "validation_status"]))
    source_type = upper(first_text(f, ["source_type", "source", "origin"]))
    evidence_ok = has_meaningful_evidence(f)

    generic_title = is_generic_title(title)
    generic_category = category in GENERIC_CATEGORIES

    # 1) Nunca promover achado genérico vazio para risco real
    if generic_title and generic_category:
        return (
            "PREVENCAO",
            "Registro técnico genérico sem descrição suficientemente específica para entrega como risco real.",
            92,
        )

    # 2) Itens explicitamente informativos/preventivos
    if review_status in PREVENTION_STATUSES:
        return (
            "PREVENCAO",
            "Achado informativo ou preventivo, útil para melhoria de postura, sem confirmação de exploração real.",
            95,
        )

    # 3) Confirmações reais, mas exigindo especificidade mínima
    if review_status in REAL_STATUSES:
        if not generic_title and not generic_category:
            return (
                "RISCO_REAL",
                "Achado com validação positiva e descrição específica suficiente para tratamento como risco real.",
                96,
            )
        if severity in {"HIGH", "CRITICAL"} and evidence_ok:
            return (
                "RISCO_REAL",
                "Achado confirmado com severidade elevada e evidência técnica registrada.",
                93,
            )
        return (
            "REVISAR_MANUALMENTE",
            "Sinal validado tecnicamente, porém com metadados genéricos demais para entrega direta como risco real.",
            84,
        )

    # 4) Suspeitas fortes e revisão manual
    if review_status in MANUAL_STATUSES:
        return (
            "REVISAR_MANUALMENTE",
            "O achado possui indícios relevantes, mas ainda exige confirmação humana antes de ser tratado como risco real.",
            91,
        )

    # 5) High/Critical com evidência clara e sem genericidade
    if severity in {"HIGH", "CRITICAL"} and evidence_ok and not generic_title:
        return (
            "RISCO_REAL",
            "Severidade elevada com evidência registrada e descrição específica.",
            88,
        )

    # 6) Medium específico com evidência -> revisão humana
    if severity == "MEDIUM" and evidence_ok and not generic_title:
        return (
            "REVISAR_MANUALMENTE",
            "Achado de média severidade com evidência inicial, recomendando validação final antes da entrega conclusiva.",
            86,
        )

    # 7) Low/Info e genéricos -> prevenção
    if severity in {"LOW", "INFO", "INFORMATIONAL", ""}:
        return (
            "PREVENCAO",
            "Achado de baixo impacto ou caráter informativo, classificado como melhoria preventiva.",
            93,
        )

    # 8) Fallback seguro
    return (
        "REVISAR_MANUALMENTE",
        "Achado mantido para validação manual por não atender critérios fortes de risco real nem de prevenção.",
        78,
    )


def rebuild_stats(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    client_cls = Counter()
    severity = Counter()

    for f in findings:
        client_cls[upper(f.get("client_classification"))] += 1
        severity[upper(f.get("severity", "UNKNOWN"))] += 1

    # Ordem padrão
    normalized_client = {
        "RISCO_REAL": client_cls.get("RISCO_REAL", 0),
        "REVISAR_MANUALMENTE": client_cls.get("REVISAR_MANUALMENTE", 0),
        "PREVENCAO": client_cls.get("PREVENCAO", 0),
    }

    normalized_severity = {
        "CRITICAL": severity.get("CRITICAL", 0),
        "HIGH": severity.get("HIGH", 0),
        "MEDIUM": severity.get("MEDIUM", 0),
        "LOW": severity.get("LOW", 0),
        "INFO": severity.get("INFO", 0) + severity.get("INFORMATIONAL", 0),
    }

    return {
        "by_client_classification": normalized_client,
        "by_severity": normalized_severity,
    }


def short_title(f: Dict[str, Any]) -> str:
    return first_text(f, ["title", "name", "finding_title"]) or "Achado técnico"


def write_summary(data: Dict[str, Any], findings: List[Dict[str, Any]], output_md: Path) -> None:
    stats = data.get("stats", {})
    client_stats = stats.get("by_client_classification", {})
    severity_stats = stats.get("by_severity", {})

    real = [f for f in findings if upper(f.get("client_classification")) == "RISCO_REAL"]
    manual = [f for f in findings if upper(f.get("client_classification")) == "REVISAR_MANUALMENTE"]

    lines: List[str] = []

    lines.append("# CyberLab — Camada 4A")
    lines.append("")
    lines.append("## Consolidação e calibração final de achados")
    lines.append("")
    lines.append(f"- **Cliente:** {data.get('client', 'N/D')}")
    lines.append(f"- **Alvo:** {data.get('target', 'N/D')}")
    lines.append(f"- **Perfil:** {data.get('profile', 'N/D')}")
    lines.append(f"- **Pasta do scan:** `{data.get('scan_dir', 'N/D')}`")
    lines.append(f"- **Gerado em:** {datetime.now(timezone.utc).isoformat()}")
    lines.append("")
    lines.append("## Resumo")
    lines.append("")
    lines.append(f"- **Achados consolidados:** **{len(findings)}**")
    lines.append("")
    lines.append("### Classificação final para entrega ao cliente")
    lines.append("")
    lines.append(f"- **Risco real:** **{client_stats.get('RISCO_REAL', 0)}**")
    lines.append(f"- **Revisar manualmente:** **{client_stats.get('REVISAR_MANUALMENTE', 0)}**")
    lines.append(f"- **Prevenção / melhoria:** **{client_stats.get('PREVENCAO', 0)}**")
    lines.append("")
    lines.append("### Severidade técnica consolidada")
    lines.append("")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        lines.append(f"- **{sev}:** {severity_stats.get(sev, 0)}")
    lines.append("")
    lines.append("## Riscos reais priorizados")
    lines.append("")

    if real:
        for f in real[:15]:
            title = short_title(f)
            sev = upper(f.get("severity", "N/D"))
            cat = upper(f.get("category", "N/D"))
            why = norm(f.get("client_classification_reason", ""))
            lines.append(f"- **{title}** — {sev} — {cat}")
            if why:
                lines.append(f"  - Motivo da classificação: {why}")
    else:
        lines.append("- Nenhum risco real foi confirmado automaticamente após a calibração.")

    lines.append("")
    lines.append("## Itens que pedem revisão manual")
    lines.append("")

    if manual:
        for f in manual[:12]:
            title = short_title(f)
            sev = upper(f.get("severity", "N/D"))
            cat = upper(f.get("category", "N/D"))
            lines.append(f"- **{title}** — {sev} — {cat}")
    else:
        lines.append("- Nenhum item pendente de revisão manual.")

    lines.append("")
    lines.append("## Observação metodológica")
    lines.append("")
    lines.append(
        "Esta camada separa automaticamente evidências confirmadas, sinais que precisam de validação humana "
        "e recomendações preventivas, evitando apresentar ao cliente final itens genéricos como riscos reais."
    )

    output_md.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit(
            "Uso: findings_client_calibrator.py <scan_dir>"
        )

    scan_dir = Path(sys.argv[1]).expanduser().resolve()
    delivery_dir = scan_dir / "block_17_client_final_delivery"

    findings_json = delivery_dir / "findings_classified.json"
    status_json = delivery_dir / "block_17_4a_status.json"
    summary_md = delivery_dir / "block_17_4a_summary.md"

    if not findings_json.exists():
        raise SystemExit(f"[ERRO] findings_classified.json não encontrado: {findings_json}")

    data = json.loads(findings_json.read_text(encoding="utf-8"))

    findings_key, findings = find_findings_container(data)

    before = Counter(
        upper(f.get("client_classification", "")) for f in findings
    )

    for f in findings:
        new_class, reason, confidence = classify_for_client(f)

        f["client_classification_original"] = f.get("client_classification", "")
        f["client_classification"] = new_class
        f["client_classification_reason"] = reason
        f["client_classification_confidence"] = confidence

    data[findings_key] = findings

    rebuilt = rebuild_stats(findings)

    if "stats" not in data or not isinstance(data["stats"], dict):
        data["stats"] = {}

    data["stats"]["by_client_classification"] = rebuilt["by_client_classification"]
    data["stats"]["by_severity"] = rebuilt["by_severity"]
    data["stats"]["calibrated_findings"] = len(findings)
    data["stats"]["calibration_version"] = "4A.1-client-calibration-v1"

    findings_json.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    status_payload = {}
    if status_json.exists():
        try:
            status_payload = json.loads(status_json.read_text(encoding="utf-8"))
        except Exception:
            status_payload = {}

    status_payload["calibration"] = {
        "enabled": True,
        "version": "4A.1-client-calibration-v1",
        "executed_at": datetime.now(timezone.utc).isoformat(),
        "before": dict(before),
        "after": rebuilt["by_client_classification"],
    }

    status_json.write_text(
        json.dumps(status_payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    write_summary(data, findings, summary_md)

    after = rebuilt["by_client_classification"]

    print("============================================================")
    print(" CyberLab — Camada 4A.1")
    print(" Calibração final para entrega ao cliente")
    print("============================================================")
    print("")
    print(f"[OK] JSON calibrado: {findings_json}")
    print(f"[OK] Status atualizado: {status_json}")
    print(f"[OK] Resumo atualizado: {summary_md}")
    print("")
    print("[ANTES]")
    print(f"  - RISCO_REAL: {before.get('RISCO_REAL', 0)}")
    print(f"  - REVISAR_MANUALMENTE: {before.get('REVISAR_MANUALMENTE', 0)}")
    print(f"  - PREVENCAO: {before.get('PREVENCAO', 0)}")
    print("")
    print("[DEPOIS]")
    print(f"  - RISCO_REAL: {after.get('RISCO_REAL', 0)}")
    print(f"  - REVISAR_MANUALMENTE: {after.get('REVISAR_MANUALMENTE', 0)}")
    print(f"  - PREVENCAO: {after.get('PREVENCAO', 0)}")
    print("")
    print("[OK] Camada 4A.1 concluída.")


if __name__ == "__main__":
    main()
