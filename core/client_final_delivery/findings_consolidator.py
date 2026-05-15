#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


HOME = Path.home() / "CyberLab"
DEFAULT_CONTEXT = HOME / "state" / "audit" / "current_audit_context.json"


# ============================================================
# Utilidades
# ============================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def safe_read_json(path: Path) -> Optional[Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def safe_write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )


def safe_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def norm_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def norm_upper(value: Any) -> str:
    return norm_text(value).upper().replace(" ", "_")


def slugify(text: str) -> str:
    text = norm_text(text).lower()
    text = re.sub(r"[^a-z0-9áéíóúãõâêîôûç]+", "-", text, flags=re.I)
    text = re.sub(r"-+", "-", text).strip("-")
    return text or "finding"


def existing_path(value: Any) -> Optional[Path]:
    raw = norm_text(value)
    if not raw:
        return None
    p = Path(raw).expanduser()
    return p if p.exists() else None


def recursive_find_first(obj: Any, preferred_keys: List[str]) -> Optional[Any]:
    if isinstance(obj, dict):
        for key in preferred_keys:
            if key in obj and obj[key] not in (None, "", [], {}):
                return obj[key]
        for value in obj.values():
            found = recursive_find_first(value, preferred_keys)
            if found not in (None, "", [], {}):
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = recursive_find_first(item, preferred_keys)
            if found not in (None, "", [], {}):
                return found
    return None


def recursive_strings(obj: Any) -> Iterable[str]:
    if isinstance(obj, dict):
        for value in obj.values():
            yield from recursive_strings(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from recursive_strings(item)
    elif isinstance(obj, str):
        yield obj


# ============================================================
# Contexto oficial da auditoria
# ============================================================

def derive_scan_dir(context: Dict[str, Any]) -> Path:
    preferred = recursive_find_first(
        context,
        [
            "scan_official",
            "official_scan",
            "scan_dir",
            "scan_path",
            "latest_scan",
            "current_scan",
            "scan"
        ]
    )

    path = existing_path(preferred)
    if path and path.is_dir():
        return path

    # fallback seguro: procurar qualquer string existente que pareça pasta de scan web
    for raw in recursive_strings(context):
        p = existing_path(raw)
        if p and p.is_dir() and "/results/web/" in str(p):
            return p

    raise SystemExit(
        "[ERRO] Não consegui localizar a pasta oficial do scan dentro do current_audit_context.json"
    )


def derive_metadata(context: Dict[str, Any]) -> Dict[str, str]:
    def pick(keys: List[str], default: str = "") -> str:
        value = recursive_find_first(context, keys)
        return norm_text(value) or default

    return {
        "client": pick(["client", "cliente", "client_name", "nome_cliente"], "Cliente não identificado"),
        "target": pick(["target", "alvo", "domain", "dominio", "host"], "Alvo não identificado"),
        "profile": pick(["profile", "perfil"], "perfil não informado"),
        "session": pick(["session", "sessao", "audit_session"], ""),
        "status": pick(["status", "final_status"], ""),
    }


# ============================================================
# Fontes conhecidas da auditoria
# ============================================================

def candidate_input_files(scan_dir: Path) -> List[Tuple[str, Path]]:
    candidates: List[Tuple[str, Path]] = [
        # Bloco 12
        ("block12_findings", scan_dir / "block_12_intelligence" / "block_12_findings.json"),
        ("block12_status", scan_dir / "block_12_intelligence" / "block_12_status.json"),

        # Bloco 13
        ("block13_status", scan_dir / "block_13_delivery" / "block_13_status.json"),

        # Bloco 14
        ("block14_validated_findings", scan_dir / "block_14_validation" / "block_14_validated_findings.json"),
        ("block14_insights", scan_dir / "block_14_validation" / "block_14_insights.json"),
        ("block14_status", scan_dir / "block_14_validation" / "block_14_status.json"),

        # Bloco 15
        ("block15_confirmed_findings", scan_dir / "block_15_controlled_validation" / "block_15_confirmed_findings.json"),
        ("block15_validations", scan_dir / "block_15_controlled_validation" / "block_15_validations.json"),
        ("block15_status", scan_dir / "block_15_controlled_validation" / "block_15_status.json"),

        # Orquestrador de ferramentas
        ("tool_orchestrator_summary", scan_dir / "11-tool-orchestrator" / "tool_run_summary.json"),

        # Resumos legados ainda úteis como fonte auxiliar
        ("legacy_summary", scan_dir / "10-json" / "summary.json"),
        ("legacy_risk_summary", scan_dir / "10-json" / "risk-summary.json"),
    ]

    # Mantém apenas existentes
    return [(label, path) for label, path in candidates if path.exists() and path.is_file()]


# ============================================================
# Extração flexível de achados
# ============================================================

FINDING_HINT_KEYS = {
    "title",
    "titulo",
    "name",
    "nome",
    "category",
    "categoria",
    "severity",
    "severidade",
    "risk_score",
    "review_status",
    "status",
    "impact",
    "impacto",
    "recommendation",
    "recomendacao",
    "evidence",
    "evidencia",
    "target",
    "alvo",
}


def looks_like_finding(obj: Dict[str, Any]) -> bool:
    keys = {str(k).lower() for k in obj.keys()}
    hits = keys.intersection(FINDING_HINT_KEYS)

    # evita capturar status.json genéricos sem conteúdo de achado
    has_identity = any(k in keys for k in ("title", "titulo", "name", "nome"))
    has_security_fields = any(
        k in keys for k in (
            "category", "categoria", "severity", "severidade",
            "risk_score", "review_status", "impact", "impacto",
            "recommendation", "recomendacao", "evidence", "evidencia"
        )
    )

    return len(hits) >= 2 and (has_identity or has_security_fields)


def extract_candidate_findings(obj: Any) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if looks_like_finding(node):
                findings.append(node)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(obj)
    return findings


# ============================================================
# Normalização dos achados
# ============================================================

def first_value(raw: Dict[str, Any], keys: List[str], default: Any = "") -> Any:
    for key in keys:
        if key in raw and raw[key] not in (None, "", [], {}):
            return raw[key]
    return default


def normalize_severity(value: Any) -> str:
    sev = norm_upper(value)
    mapping = {
        "CRITICAL": "CRITICAL",
        "CRITICO": "CRITICAL",
        "CRÍTICO": "CRITICAL",
        "HIGH": "HIGH",
        "ALTO": "HIGH",
        "MEDIUM": "MEDIUM",
        "MEDIO": "MEDIUM",
        "MÉDIO": "MEDIUM",
        "LOW": "LOW",
        "BAIXO": "LOW",
        "INFO": "INFO",
        "INFORMATIVO": "INFO",
        "INFORMATIONAL": "INFO",
    }
    return mapping.get(sev, sev or "INFO")


def normalize_review_status(value: Any) -> str:
    status = norm_upper(value)
    mapping = {
        "CONFIRMADO": "CONFIRMADO",
        "CONFIRMED": "CONFIRMADO",
        "CONFIRMADO_PROVAVEL": "CONFIRMADO_PROVAVEL",
        "CONFIRMADO_PROVÁVEL": "CONFIRMADO_PROVAVEL",
        "CONFIRMED_LIKELY": "CONFIRMADO_PROVAVEL",
        "CONFIRMADO_POTENCIAL": "CONFIRMADO_POTENCIAL",
        "REVISAR_MANUALMENTE": "REVISAR_MANUALMENTE",
        "MANUAL_REVIEW": "REVISAR_MANUALMENTE",
        "SUSPEITO_FORTE": "SUSPEITO_FORTE",
        "STRONG_SUSPECT": "SUSPEITO_FORTE",
        "INFORMATIVO": "INFORMATIVO",
        "INFO": "INFORMATIVO",
    }
    return mapping.get(status, status or "INFORMATIVO")


def infer_title(raw: Dict[str, Any]) -> str:
    value = first_value(raw, ["title", "titulo", "name", "nome"])
    title = norm_text(value)
    if title:
        return title

    category = norm_text(first_value(raw, ["category", "categoria"], "Achado técnico"))
    return category or "Achado técnico"


def as_string(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return norm_text(value)


def compute_signature(finding: Dict[str, Any]) -> str:
    base = "|".join([
        slugify(finding.get("title", "")),
        slugify(finding.get("category", "")),
        slugify(finding.get("target", "")),
    ])
    return hashlib.sha256(base.encode("utf-8")).hexdigest()[:16]


def normalize_finding(raw: Dict[str, Any], source_label: str, source_path: Path) -> Dict[str, Any]:
    title = infer_title(raw)
    category = norm_upper(first_value(raw, ["category", "categoria"], "GENERIC"))
    severity = normalize_severity(first_value(raw, ["severity", "severidade"], "INFO"))
    review_status = normalize_review_status(first_value(raw, ["review_status", "status"], "INFORMATIVO"))

    risk_score_raw = first_value(raw, ["risk_score", "score", "risk"], 0)
    try:
        risk_score = int(risk_score_raw)
    except Exception:
        risk_score = 0

    confidence_raw = first_value(raw, ["confidence", "confianca", "confiança"], 0)
    try:
        confidence = int(confidence_raw)
    except Exception:
        confidence = 0

    normalized = {
        "id": "",
        "signature": "",
        "title": title,
        "category": category or "GENERIC",
        "severity": severity,
        "review_status": review_status,
        "risk_score": risk_score,
        "confidence": confidence,
        "target": norm_text(first_value(raw, ["target", "alvo", "url", "endpoint"], "")),
        "impact": as_string(first_value(raw, ["impact", "impacto"], "")),
        "recommendation": as_string(first_value(raw, ["recommendation", "recomendacao", "recomendação"], "")),
        "evidence": as_string(first_value(raw, ["evidence", "evidencia", "evidência"], "")),
        "source_type": norm_upper(first_value(raw, ["source_type", "fonte"], "GENERIC")),
        "sources": [
            {
                "label": source_label,
                "path": str(source_path),
            }
        ],
        "raw_preview": {
            k: raw[k]
            for k in list(raw.keys())[:12]
        }
    }

    normalized["signature"] = compute_signature(normalized)
    normalized["id"] = f"fnd_{normalized['signature']}"

    return normalized


# ============================================================
# Classificação final ao cliente
# ============================================================

PREVENTIVE_KEYWORDS = (
    "hsts",
    "content-security-policy",
    "csp",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "header",
    "cabecalho",
    "cabeçalho",
    "cookie sem",
    "banner",
)


def is_preventive_by_title_or_category(finding: Dict[str, Any]) -> bool:
    haystack = " ".join([
        finding.get("title", ""),
        finding.get("category", ""),
        finding.get("impact", ""),
    ]).lower()

    return any(keyword in haystack for keyword in PREVENTIVE_KEYWORDS)


def classify_finding(finding: Dict[str, Any]) -> Tuple[str, str]:
    labels = {s["label"] for s in finding.get("sources", [])}
    review = finding.get("review_status", "")
    severity = finding.get("severity", "INFO")
    confidence = int(finding.get("confidence", 0) or 0)
    risk_score = int(finding.get("risk_score", 0) or 0)

    # 1) Confirmado pelo bloco 15 tem prioridade máxima
    if "block15_confirmed_findings" in labels:
        return (
            "RISCO_REAL",
            "Achado presente na validação controlada do Bloco 15."
        )

    # 2) Status de confirmação explícito
    if review in {"CONFIRMADO", "CONFIRMADO_PROVAVEL", "CONFIRMADO_POTENCIAL"}:
        return (
            "RISCO_REAL",
            f"Status de revisão indica confirmação: {review}."
        )

    # 3) Suspeito forte / revisão manual
    if review in {"SUSPEITO_FORTE", "REVISAR_MANUALMENTE"}:
        return (
            "REVISAR_MANUALMENTE",
            f"Achado marcado como {review}."
        )

    # 4) Alto impacto sem confirmação forte: revisão manual
    if severity in {"CRITICAL", "HIGH"} and (confidence >= 60 or risk_score >= 70):
        return (
            "REVISAR_MANUALMENTE",
            "Severidade elevada, porém sem confirmação final suficiente."
        )

    # 5) Boas práticas e hardening preventivo
    if is_preventive_by_title_or_category(finding):
        return (
            "PREVENCAO",
            "Ponto associado a endurecimento de segurança e redução de exposição futura."
        )

    # 6) Demais itens genéricos ficam como prevenção inicialmente
    return (
        "PREVENCAO",
        "Achado técnico sem evidência suficiente para ser tratado como risco real."
    )


# ============================================================
# Deduplicação e merge de fontes
# ============================================================

def merge_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}

    severity_rank = {
        "INFO": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    review_rank = {
        "INFORMATIVO": 0,
        "REVISAR_MANUALMENTE": 1,
        "SUSPEITO_FORTE": 2,
        "CONFIRMADO_POTENCIAL": 3,
        "CONFIRMADO_PROVAVEL": 4,
        "CONFIRMADO": 5,
    }

    for item in findings:
        sig = item["signature"]

        if sig not in merged:
            merged[sig] = item
            continue

        current = merged[sig]

        # agrega fontes
        existing_sources = {(s["label"], s["path"]) for s in current["sources"]}
        for source in item["sources"]:
            key = (source["label"], source["path"])
            if key not in existing_sources:
                current["sources"].append(source)

        # mantém maior severidade
        if severity_rank.get(item["severity"], 0) > severity_rank.get(current["severity"], 0):
            current["severity"] = item["severity"]

        # mantém revisão mais forte
        if review_rank.get(item["review_status"], 0) > review_rank.get(current["review_status"], 0):
            current["review_status"] = item["review_status"]

        # mantém score/confiança maior
        current["risk_score"] = max(int(current.get("risk_score", 0)), int(item.get("risk_score", 0)))
        current["confidence"] = max(int(current.get("confidence", 0)), int(item.get("confidence", 0)))

        # preenche campos úteis vazios
        for field in ("impact", "recommendation", "evidence", "target"):
            if not current.get(field) and item.get(field):
                current[field] = item[field]

    final_items = list(merged.values())

    for item in final_items:
        classification, reason = classify_finding(item)
        item["client_classification"] = classification
        item["classification_reason"] = reason

    final_items.sort(
        key=lambda x: (
            {"RISCO_REAL": 0, "REVISAR_MANUALMENTE": 1, "PREVENCAO": 2}.get(
                x["client_classification"], 9
            ),
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(
                x["severity"], 9
            ),
            -int(x.get("risk_score", 0))
        )
    )

    return final_items


# ============================================================
# Saída resumida MD
# ============================================================

def build_summary_md(payload: Dict[str, Any]) -> str:
    stats = payload["stats"]
    by_class = stats["by_client_classification"]
    by_sev = stats["by_severity"]

    lines = [
        "# CyberLab — Camada 4A",
        "",
        "## Consolidação e classificação final de achados",
        "",
        f"- **Cliente:** {payload['client']}",
        f"- **Alvo:** {payload['target']}",
        f"- **Perfil:** {payload['profile']}",
        f"- **Pasta do scan:** `{payload['scan_dir']}`",
        f"- **Gerado em:** {payload['generated_at']}",
        "",
        "## Resumo",
        "",
        f"- Arquivos de entrada encontrados: **{stats['input_files_found']}**",
        f"- Registros brutos extraídos: **{stats['raw_findings_extracted']}**",
        f"- Achados consolidados após deduplicação: **{stats['consolidated_findings']}**",
        "",
        "### Classificação para entrega ao cliente",
        "",
        f"- **Risco real:** {by_class.get('RISCO_REAL', 0)}",
        f"- **Revisar manualmente:** {by_class.get('REVISAR_MANUALMENTE', 0)}",
        f"- **Prevenção / melhoria:** {by_class.get('PREVENCAO', 0)}",
        "",
        "### Severidade técnica consolidada",
        "",
        f"- **CRITICAL:** {by_sev.get('CRITICAL', 0)}",
        f"- **HIGH:** {by_sev.get('HIGH', 0)}",
        f"- **MEDIUM:** {by_sev.get('MEDIUM', 0)}",
        f"- **LOW:** {by_sev.get('LOW', 0)}",
        f"- **INFO:** {by_sev.get('INFO', 0)}",
        "",
        "## Primeiros riscos reais consolidados",
        "",
    ]

    top_real = payload.get("top_real_risks", [])
    if not top_real:
        lines.append("- Nenhum risco real consolidado nesta etapa.")
    else:
        for finding in top_real[:10]:
            lines.append(
                f"- **{finding['title']}** — {finding['severity']} — {finding['category']}"
            )

    lines.extend([
        "",
        "## Arquivos gerados",
        "",
        f"- `{payload['outputs']['findings_classified_json']}`",
        f"- `{payload['outputs']['stage_status_json']}`",
        f"- `{payload['outputs']['stage_summary_md']}`",
        "",
    ])

    return "\n".join(lines)


# ============================================================
# Execução principal
# ============================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="CyberLab Camada 4A — Consolidação e classificação final de achados."
    )
    parser.add_argument(
        "--context",
        default=str(DEFAULT_CONTEXT),
        help="Caminho do current_audit_context.json"
    )
    args = parser.parse_args()

    context_path = Path(args.context).expanduser()

    if not context_path.exists():
        raise SystemExit(f"[ERRO] Contexto não encontrado: {context_path}")

    context = safe_read_json(context_path)
    if not isinstance(context, dict):
        raise SystemExit(f"[ERRO] Contexto inválido ou não é JSON objeto: {context_path}")

    scan_dir = derive_scan_dir(context)
    metadata = derive_metadata(context)

    output_dir = scan_dir / "block_17_client_final_delivery"
    output_dir.mkdir(parents=True, exist_ok=True)

    input_files = candidate_input_files(scan_dir)

    raw_normalized: List[Dict[str, Any]] = []
    source_load_status: List[Dict[str, Any]] = []

    for label, path in input_files:
        data = safe_read_json(path)
        if data is None:
            source_load_status.append({
                "label": label,
                "path": str(path),
                "status": "INVALID_JSON_OR_READ_ERROR",
                "findings_extracted": 0,
            })
            continue

        raw_items = extract_candidate_findings(data)

        for raw in raw_items:
            raw_normalized.append(normalize_finding(raw, label, path))

        source_load_status.append({
            "label": label,
            "path": str(path),
            "status": "OK",
            "findings_extracted": len(raw_items),
        })

    consolidated = merge_findings(raw_normalized)

    by_class = Counter(x["client_classification"] for x in consolidated)
    by_sev = Counter(x["severity"] for x in consolidated)
    by_review = Counter(x["review_status"] for x in consolidated)

    top_real_risks = [
        x for x in consolidated
        if x["client_classification"] == "RISCO_REAL"
    ][:15]

    findings_json = output_dir / "findings_classified.json"
    status_json = output_dir / "block_17_4a_status.json"
    summary_md = output_dir / "block_17_4a_summary.md"

    payload = {
        "block": "17",
        "stage": "4A",
        "module": "CyberLab Final Findings Consolidator",
        "status": "COMPLETED",
        "generated_at": now_iso(),
        "client": metadata["client"],
        "target": metadata["target"],
        "profile": metadata["profile"],
        "session": metadata["session"],
        "audit_context_status": metadata["status"],
        "context_file": str(context_path),
        "scan_dir": str(scan_dir),
        "inputs": source_load_status,
        "stats": {
            "input_files_found": len(input_files),
            "raw_findings_extracted": len(raw_normalized),
            "consolidated_findings": len(consolidated),
            "by_client_classification": dict(by_class),
            "by_severity": dict(by_sev),
            "by_review_status": dict(by_review),
        },
        "classification_policy": {
            "RISCO_REAL": [
                "Achado confirmado pelo Bloco 15.",
                "Achado com status explícito de confirmação."
            ],
            "REVISAR_MANUALMENTE": [
                "Achado marcado como suspeito forte ou revisar manualmente.",
                "Achado de alta severidade sem confirmação final suficiente."
            ],
            "PREVENCAO": [
                "Hardening, cabeçalhos e pontos de postura de segurança.",
                "Itens sem evidência suficiente para entrar como risco real."
            ]
        },
        "top_real_risks": top_real_risks,
        "findings": consolidated,
        "outputs": {
            "findings_classified_json": str(findings_json),
            "stage_status_json": str(status_json),
            "stage_summary_md": str(summary_md),
        }
    }

    safe_write_json(findings_json, payload)
    safe_write_json(status_json, {
        "block": "17",
        "stage": "4A",
        "status": "COMPLETED",
        "generated_at": payload["generated_at"],
        "client": payload["client"],
        "target": payload["target"],
        "scan_dir": payload["scan_dir"],
        "stats": payload["stats"],
        "outputs": payload["outputs"],
    })
    safe_write_text(summary_md, build_summary_md(payload))

    print("=" * 72)
    print("CyberLab — Camada 4A: Consolidação Final de Achados")
    print("=" * 72)
    print(f"[OK] Cliente: {payload['client']}")
    print(f"[OK] Alvo: {payload['target']}")
    print(f"[OK] Scan oficial: {payload['scan_dir']}")
    print(f"[OK] Arquivos de entrada encontrados: {len(input_files)}")
    print(f"[OK] Registros brutos extraídos: {len(raw_normalized)}")
    print(f"[OK] Achados consolidados: {len(consolidated)}")
    print("")
    print("[CLASSIFICAÇÃO FINAL]")
    print(f"  - RISCO_REAL: {by_class.get('RISCO_REAL', 0)}")
    print(f"  - REVISAR_MANUALMENTE: {by_class.get('REVISAR_MANUALMENTE', 0)}")
    print(f"  - PREVENCAO: {by_class.get('PREVENCAO', 0)}")
    print("")
    print("[ARQUIVOS GERADOS]")
    print(f"  - {findings_json}")
    print(f"  - {status_json}")
    print(f"  - {summary_md}")
    print("=" * 72)


if __name__ == "__main__":
    main()
