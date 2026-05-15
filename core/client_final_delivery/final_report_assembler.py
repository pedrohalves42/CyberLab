#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple


HOME = Path.home()
CYBERLAB = HOME / "CyberLab"
AUDIT_CONTEXT = CYBERLAB / "state" / "audit" / "current_audit_context.json"


# ============================================================
# Helpers
# ============================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json(path: Path, default: Any = None) -> Any:
    if default is None:
        default = {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def write_md(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.rstrip() + "\n", encoding="utf-8")


def human_count(n: int) -> str:
    return str(n)


def md_list(items: List[str], fallback: str = "- Nenhum item identificado.") -> str:
    if not items:
        return fallback
    return "\n".join(f"- {item}" for item in items)


def pick_artifact_path(ctx: Dict[str, Any], keys: List[str], fallback: Path | None = None) -> Path | None:
    artifacts = ctx.get("artifacts", {})
    for key in keys:
        item = artifacts.get(key)
        if isinstance(item, dict):
            p = item.get("path")
            if p:
                pp = Path(p)
                if pp.exists():
                    return pp
        elif isinstance(item, str):
            pp = Path(item)
            if pp.exists():
                return pp
    return fallback if fallback and fallback.exists() else None


def normalize_findings_payload(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Aceita variações de schema e retorna a lista de achados traduzidos/classificados.
    """
    for key in ("findings", "items", "translated_findings", "client_findings"):
        value = data.get(key)
        if isinstance(value, list):
            return [x for x in value if isinstance(x, dict)]
    return []


def classify_bucket(item: Dict[str, Any]) -> str:
    raw = (
        item.get("client_classification")
        or item.get("classification")
        or item.get("bucket")
        or ""
    )
    return str(raw).upper().strip()


def get_title(item: Dict[str, Any]) -> str:
    return str(
        item.get("client_title")
        or item.get("title")
        or item.get("name")
        or "Achado técnico"
    ).strip()


def get_severity(item: Dict[str, Any]) -> str:
    return str(
        item.get("severity")
        or item.get("technical_severity")
        or item.get("level")
        or "INFO"
    ).upper().strip()


def get_category(item: Dict[str, Any]) -> str:
    return str(
        item.get("category")
        or item.get("theme")
        or item.get("group")
        or "GENERIC"
    ).upper().strip()


def get_client_observed(item: Dict[str, Any]) -> str:
    return str(
        item.get("what_was_observed")
        or item.get("client_observation")
        or item.get("observed")
        or item.get("description")
        or "Foi identificado um ponto relevante durante a análise."
    ).strip()


def get_client_why(item: Dict[str, Any]) -> str:
    return str(
        item.get("why_it_matters")
        or item.get("client_impact")
        or item.get("impact")
        or "Este ponto merece atenção por poder influenciar a postura de segurança do ambiente."
    ).strip()


def get_client_recommendation(item: Dict[str, Any]) -> str:
    return str(
        item.get("recommendation")
        or item.get("client_recommendation")
        or item.get("remediation")
        or "Avaliar tecnicamente o item e aplicar a correção ou ajuste recomendado quando cabível."
    ).strip()


def get_classification_note(item: Dict[str, Any]) -> str:
    return str(
        item.get("classification_reading")
        or item.get("client_classification_reason")
        or item.get("reason")
        or ""
    ).strip()


def compact_title(title: str, max_len: int = 110) -> str:
    title = " ".join(title.split())
    if len(title) <= max_len:
        return title
    return title[: max_len - 3].rstrip() + "..."


# ============================================================
# Conteúdo
# ============================================================

def build_exec_risks(risks: List[Dict[str, Any]]) -> str:
    if not risks:
        return (
            "Nenhum risco real confirmado foi classificado nesta rodada. "
            "Isso não significa ausência completa de atenção, mas indica que os itens encontrados "
            "foram tratados principalmente como prevenção ou revisão complementar."
        )

    chunks = []
    for idx, item in enumerate(risks, 1):
        title = compact_title(get_title(item))
        severity = get_severity(item)
        observed = get_client_observed(item)
        why = get_client_why(item)
        rec = get_client_recommendation(item)

        chunks.append(
            f"""### {idx}. {title}

- **Prioridade técnica:** {severity}
- **O que foi observado:** {observed}
- **Por que isso importa:** {why}
- **Recomendação principal:** {rec}
"""
        )
    return "\n".join(chunks).rstrip()


def build_review_items(items: List[Dict[str, Any]]) -> str:
    if not items:
        return "Nenhum item ficou pendente de validação manual nesta rodada."

    chunks = []
    for idx, item in enumerate(items, 1):
        title = compact_title(get_title(item))
        severity = get_severity(item)
        observed = get_client_observed(item)
        why = get_client_why(item)
        rec = get_client_recommendation(item)
        note = get_classification_note(item)

        note_block = f"\n- **Leitura da classificação:** {note}" if note else ""

        chunks.append(
            f"""### {idx}. {title}

- **Nível técnico:** {severity}
- **O que foi observado:** {observed}
- **Por que merece validação:** {why}
- **Próximo passo recomendado:** {rec}{note_block}
"""
        )
    return "\n".join(chunks).rstrip()


def group_prevention_by_category(items: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for item in items:
        cat = get_category(item)
        grouped.setdefault(cat, []).append(item)
    return grouped


def build_prevention_summary(items: List[Dict[str, Any]]) -> str:
    if not items:
        return "Nenhuma recomendação preventiva adicional foi consolidada."

    grouped = group_prevention_by_category(items)
    blocks = []

    for category, group in sorted(grouped.items(), key=lambda x: (-len(x[1]), x[0])):
        titles = []
        for item in group[:5]:
            title = compact_title(get_title(item), 90)
            if title not in titles:
                titles.append(title)

        examples = md_list(titles, fallback="- Itens preventivos consolidados.")

        blocks.append(
            f"""### {category} — {len(group)} item(ns)

**Síntese:** Foram agrupadas recomendações preventivas relacionadas a esta categoria.  
**Exemplos observados:**
{examples}

**Tratamento sugerido:** Avaliar dentro do ciclo de melhoria contínua, priorizando ajustes que reduzam exposição futura sem superestimar o risco atual.
"""
        )

    return "\n".join(blocks).rstrip()


def build_technical_table(items: List[Dict[str, Any]]) -> str:
    if not items:
        return "| Classificação | Severidade | Categoria | Título |\n|---|---|---|---|\n| - | - | - | Nenhum item |"

    rows = [
        "| Classificação | Severidade | Categoria | Título |",
        "|---|---|---|---|",
    ]

    for item in items:
        cls = classify_bucket(item) or "-"
        sev = get_severity(item)
        cat = get_category(item)
        title = compact_title(get_title(item), 95).replace("|", "/")
        rows.append(f"| {cls} | {sev} | {cat} | {title} |")

    return "\n".join(rows)


def remediation_priority_for(item: Dict[str, Any]) -> str:
    cls = classify_bucket(item)
    sev = get_severity(item)

    if cls == "RISCO_REAL":
        if sev in ("CRITICAL", "HIGH"):
            return "Imediata"
        return "Alta"

    if cls == "REVISAR_MANUALMENTE":
        return "Validação técnica"

    return "Melhoria planejada"


def build_remediation_plan(risks: List[Dict[str, Any]], review: List[Dict[str, Any]], prevention: List[Dict[str, Any]]) -> str:
    rows = [
        "| Prioridade | Classificação | Achado | Ação recomendada |",
        "|---|---|---|---|",
    ]

    ordered = risks + review + prevention[:20]

    if not ordered:
        rows.append("| - | - | Nenhum item | Nenhuma ação necessária no momento |")
        return "\n".join(rows)

    for item in ordered:
        priority = remediation_priority_for(item)
        cls = classify_bucket(item) or "-"
        title = compact_title(get_title(item), 70).replace("|", "/")
        action = compact_title(get_client_recommendation(item), 130).replace("|", "/")
        rows.append(f"| {priority} | {cls} | {title} | {action} |")

    return "\n".join(rows)


# ============================================================
# Main
# ============================================================

def main() -> None:
    if not AUDIT_CONTEXT.exists():
        raise SystemExit(
            "[ERRO] Contexto oficial da auditoria não encontrado. "
            "Rode primeiro o fluxo completo até a Camada 3."
        )

    ctx = read_json(AUDIT_CONTEXT, {})
    scan_dir_raw = ctx.get("scan_dir")

    if not scan_dir_raw:
        raise SystemExit("[ERRO] scan_dir não encontrado no contexto oficial.")

    scan_dir = Path(scan_dir_raw)

    if not scan_dir.exists():
        raise SystemExit(f"[ERRO] Scan oficial não existe: {scan_dir}")

    client = str(ctx.get("client_name") or ctx.get("client") or "Cliente")
    target = str(ctx.get("target") or "alvo não informado")
    profile = str(ctx.get("profile") or "não informado")
    session_id = str(ctx.get("session_id") or "sem_sessao")

    out_dir = scan_dir / "block_17_client_final_delivery"
    out_dir.mkdir(parents=True, exist_ok=True)

    translated_json = pick_artifact_path(
        ctx,
        ["block17_4b_client_language_json"],
        out_dir / "client_language_findings.json",
    )

    classified_json = pick_artifact_path(
        ctx,
        ["block17_4a_findings_classified_json"],
        out_dir / "findings_classified.json",
    )

    if translated_json is None or not translated_json.exists():
        raise SystemExit(
            "[ERRO] client_language_findings.json da Camada 4B não encontrado. "
            "Rode novamente a Camada 4B."
        )

    translated_payload = read_json(translated_json, {})
    findings = normalize_findings_payload(translated_payload)

    if not findings and classified_json and classified_json.exists():
        classified_payload = read_json(classified_json, {})
        findings = normalize_findings_payload(classified_payload)

    risks = [f for f in findings if classify_bucket(f) == "RISCO_REAL"]
    review = [f for f in findings if classify_bucket(f) == "REVISAR_MANUALMENTE"]
    prevention = [f for f in findings if classify_bucket(f) == "PREVENCAO"]

    total = len(findings)

    technical_by_severity: Dict[str, int] = {}
    for item in findings:
        sev = get_severity(item)
        technical_by_severity[sev] = technical_by_severity.get(sev, 0) + 1

    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    severity_lines = "\n".join(
        f"- **{sev}:** {technical_by_severity.get(sev, 0)}"
        for sev in severity_order
    )

    created_at = now_iso()

    # --------------------------------------------------------
    # Executivo
    # --------------------------------------------------------
    executive_md = f"""# Relatório Executivo Final — Segurança Digital

## Identificação da análise

- **Cliente:** {client}
- **Alvo analisado:** {target}
- **Perfil utilizado:** {profile}
- **Sessão oficial:** {session_id}
- **Pasta técnica do scan:** `{scan_dir}`
- **Gerado em:** {created_at}

---

## Resumo para decisão

A auditoria consolidou informações de reconhecimento, scanners, validações controladas e correlação de achados.  
Após filtragem, deduplicação e calibração, os resultados foram separados em três grupos:

- **Riscos reais priorizados:** {len(risks)}
- **Pontos que exigem validação manual:** {len(review)}
- **Recomendações preventivas e melhorias:** {len(prevention)}

Essa separação evita tratar toda observação técnica como falha confirmada e torna o relatório mais justo para tomada de decisão.

---

## Leitura gerencial

- **Risco real**: evidência suficientemente relevante para tratamento como problema concreto.
- **Revisar manualmente**: sinal importante, mas que ainda exige confirmação humana ou checagem complementar.
- **Prevenção / melhoria**: boas práticas que fortalecem o ambiente, sem necessariamente representar uma vulnerabilidade confirmada.

---

## Principais riscos reais

{build_exec_risks(risks)}

---

## Pontos que merecem validação manual

{build_review_items(review)}

---

## Melhorias preventivas consolidadas

{build_prevention_summary(prevention)}

---

## Conclusão executiva

O ambiente analisado apresentou **{len(risks)} risco(s) real(is) priorizado(s)**, **{len(review)} ponto(s) que pedem validação técnica adicional** e **{len(prevention)} recomendação(ões) preventiva(s)**.

A recomendação é tratar primeiro os riscos reais, validar em seguida os itens pendentes e incorporar as melhorias preventivas ao plano contínuo de segurança.
"""

    # --------------------------------------------------------
    # Técnico
    # --------------------------------------------------------
    technical_md = f"""# Relatório Técnico Final — Consolidação da Auditoria

## Contexto oficial

- **Cliente:** {client}
- **Alvo:** {target}
- **Perfil:** {profile}
- **Sessão:** {session_id}
- **Scan oficial:** `{scan_dir}`
- **Gerado em:** {created_at}

---

## Consolidação quantitativa

- **Achados totais consolidados para cliente:** {total}
- **Risco real:** {len(risks)}
- **Revisar manualmente:** {len(review)}
- **Prevenção:** {len(prevention)}

### Severidade técnica consolidada

{severity_lines}

---

## Matriz final de achados

{build_technical_table(findings)}

---

## Riscos reais — Detalhamento técnico/funcional

{build_exec_risks(risks)}

---

## Itens que exigem validação manual

{build_review_items(review)}

---

## Recomendações preventivas agrupadas

{build_prevention_summary(prevention)}

---

## Observação metodológica

Este relatório é resultado de uma camada final de entrega ao cliente.  
Ele não substitui a evidência bruta de cada ferramenta, mas organiza os resultados para uso prático, separando:

1. evidências com tratamento prioritário;
2. sinais que ainda dependem de revisão;
3. recomendações preventivas que aumentam maturidade sem inflar artificialmente o risco.
"""

    # --------------------------------------------------------
    # Plano de Remediação
    # --------------------------------------------------------
    remediation_md = f"""# Plano Final de Remediação e Acompanhamento

## Identificação

- **Cliente:** {client}
- **Alvo:** {target}
- **Perfil:** {profile}
- **Gerado em:** {created_at}

---

## Estratégia de tratamento

A priorização recomendada segue três frentes:

1. **Resolver os riscos reais confirmados**
2. **Validar tecnicamente os itens em revisão manual**
3. **Aplicar melhorias preventivas dentro do ciclo de evolução da segurança**

---

## Plano de ação consolidado

{build_remediation_plan(risks, review, prevention)}

---

## Prioridades recomendadas

### Ação imediata
Tratar itens classificados como **RISCO_REAL**, especialmente os de severidade alta.

### Validação técnica
Confirmar itens classificados como **REVISAR_MANUALMENTE**, evitando tanto negligenciar sinais importantes quanto reportar como falha algo ainda não confirmado.

### Melhoria contínua
Avaliar itens de **PREVENÇÃO**, priorizando os que contribuem para redução de exposição pública, fortalecimento de headers, serviços e superfícies desnecessárias.

---

## Fechamento

Este plano deve servir como ponte entre o relatório técnico e a execução prática das correções.  
A recomendação é registrar o avanço de cada item e repetir a auditoria após as correções relevantes.
"""

    # --------------------------------------------------------
    # Summary / Manifest / Status
    # --------------------------------------------------------
    executive_path = out_dir / "client_final_executive_report.md"
    technical_path = out_dir / "client_final_technical_report.md"
    remediation_path = out_dir / "client_final_remediation_plan.md"
    summary_path = out_dir / "block_17_4c_summary.md"
    status_path = out_dir / "block_17_4c_status.json"
    manifest_path = out_dir / "client_final_report_manifest.json"

    write_md(executive_path, executive_md)
    write_md(technical_path, technical_md)
    write_md(remediation_path, remediation_md)

    summary_md = f"""# CyberLab — Camada 4C

## Montagem final dos relatórios-base

- **Cliente:** {client}
- **Alvo:** {target}
- **Perfil:** {profile}
- **Scan oficial:** `{scan_dir}`
- **Gerado em:** {created_at}

## Consolidação

- **Achados finais tratados:** {total}
- **Risco real:** {len(risks)}
- **Revisar manualmente:** {len(review)}
- **Prevenção:** {len(prevention)}

## Arquivos gerados

- `{executive_path}`
- `{technical_path}`
- `{remediation_path}`
- `{manifest_path}`
- `{status_path}`

## Próximo passo

A Camada 4D deve converter estes documentos em PDFs finais profissionais para entrega ao cliente.
"""
    write_md(summary_path, summary_md)

    manifest = {
        "schema": "cyberlab.block17.4c.client_final_report_manifest.v1",
        "status": "OK",
        "generated_at": created_at,
        "client": client,
        "target": target,
        "profile": profile,
        "scan_dir": str(scan_dir),
        "inputs": {
            "translated_findings_json": str(translated_json),
            "classified_findings_json": str(classified_json) if classified_json else None,
        },
        "counts": {
            "findings_total": total,
            "risco_real": len(risks),
            "revisar_manualmente": len(review),
            "prevencao": len(prevention),
        },
        "outputs": {
            "executive_report_md": str(executive_path),
            "technical_report_md": str(technical_path),
            "remediation_plan_md": str(remediation_path),
            "summary_md": str(summary_path),
            "status_json": str(status_path),
        },
    }
    write_json(manifest_path, manifest)

    status = {
        "schema": "cyberlab.block17.4c.status.v1",
        "status": "OK",
        "message": "Camada 4C executada e sincronizada.",
        "updated_at": created_at,
        "scan_dir": str(scan_dir),
        "counts": manifest["counts"],
        "outputs": manifest["outputs"],
    }
    write_json(status_path, status)

    # --------------------------------------------------------
    # Atualiza contexto oficial
    # --------------------------------------------------------
    ctx.setdefault("stages", {})
    ctx["stages"]["block17_4c_final_report_assembler"] = {
        "status": "OK",
        "message": "Relatórios finais-base do cliente montados.",
        "updated_at": created_at,
        "status_json": str(status_path),
        "manifest_json": str(manifest_path),
    }

    ctx.setdefault("artifacts", {})
    artifacts_to_register = {
        "block17_4c_executive_report_md": executive_path,
        "block17_4c_technical_report_md": technical_path,
        "block17_4c_remediation_plan_md": remediation_path,
        "block17_4c_summary_md": summary_path,
        "block17_4c_status_json": status_path,
        "block17_4c_manifest_json": manifest_path,
    }

    for key, path in artifacts_to_register.items():
        ctx["artifacts"][key] = {
            "path": str(path),
            "kind": "file",
            "exists": path.exists(),
            "registered_at": created_at,
        }

    ctx["updated_at"] = created_at
    write_json(AUDIT_CONTEXT, ctx)

    # --------------------------------------------------------
    # Terminal
    # --------------------------------------------------------
    print("=" * 72)
    print(" CyberLab — Camada 4C")
    print(" Montagem final e unificada dos relatórios do cliente")
    print("=" * 72)
    print()
    print(f"[OK] Cliente: {client}")
    print(f"[OK] Alvo: {target}")
    print(f"[OK] Scan oficial: {scan_dir}")
    print(f"[OK] Achados considerados: {total}")
    print()
    print("[CLASSIFICAÇÃO FINAL]")
    print(f" - RISCO_REAL: {len(risks)}")
    print(f" - REVISAR_MANUALMENTE: {len(review)}")
    print(f" - PREVENCAO: {len(prevention)}")
    print()
    print("[ARQUIVOS GERADOS]")
    print(f" - {executive_path}")
    print(f" - {technical_path}")
    print(f" - {remediation_path}")
    print(f" - {manifest_path}")
    print(f" - {summary_path}")
    print(f" - {status_path}")
    print()
    print("[OK] Contexto oficial atualizado com os artefatos da Camada 4C.")
    print("[OK] Camada 4C finalizada.")
    print("=" * 72)


if __name__ == "__main__":
    main()
