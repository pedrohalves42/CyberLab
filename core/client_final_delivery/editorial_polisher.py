#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


HOME = Path.home()
CYBERLAB = HOME / "CyberLab"
AUDIT_CONTEXT = CYBERLAB / "state/audit/current_audit_context.json"


# ============================================================
# Utilitários
# ============================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat()


def load_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def write_json(path: Path, data: Any) -> None:
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8"
    )


def write_text(path: Path, text: str) -> None:
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def fail(msg: str, code: int = 1) -> None:
    print(f"[ERRO] {msg}")
    raise SystemExit(code)


def file_record(path: Path, kind: str, description: str) -> Dict[str, Any]:
    return {
        "path": str(path),
        "kind": kind,
        "description": description,
        "exists": path.exists(),
        "registered_at": now_iso(),
    }


def normalize_text(value: Any, default: str = "-") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def first(item: Dict[str, Any], keys: List[str], default: str = "-") -> str:
    for key in keys:
        value = item.get(key)
        if value not in (None, "", [], {}):
            return normalize_text(value, default)
    return default


# ============================================================
# Traduções e polimento semântico
# ============================================================

CATEGORY_LABELS = {
    "EXPOSURE": "Exposição de informação ou recurso",
    "EXPOSED_PANEL": "Painel ou área administrativa potencialmente exposta",
    "HEADER": "Configuração de proteção do navegador",
    "SURFACE_PORT": "Serviço publicado na superfície externa",
    "SURFACE_CDN": "Infraestrutura pública de entrega de conteúdo",
    "SURFACE_WAF": "Camada de proteção perimetral observada",
    "SURFACE_HTTP": "Comportamento HTTP observado",
    "SURFACE_API": "Superfície de API identificada",
    "SURFACE_AUTH": "Superfície relacionada a autenticação",
    "SURFACE_SCRIPT": "Scripts ou ativos públicos observados",
    "WEB": "Componente da aplicação web",
    "WEB-DISCOVERY": "Rotas e recursos públicos mapeados",
    "NETWORK": "Exposição de rede observada",
    "GENERIC": "Observação técnica",
}


SEVERITY_LABELS = {
    "CRITICAL": "Crítico",
    "HIGH": "Alto",
    "MEDIUM": "Médio",
    "LOW": "Baixo",
    "INFO": "Informativo",
}


CLASSIFICATION_LABELS = {
    "RISCO_REAL": "Risco real priorizado",
    "REVISAR_MANUALMENTE": "Ponto que exige validação técnica",
    "PREVENCAO": "Recomendação preventiva",
}


def clean_category(category: str) -> str:
    cat = normalize_text(category, "GENERIC").upper()
    return CATEGORY_LABELS.get(cat, cat.replace("_", " ").title())


def clean_severity(severity: str) -> str:
    sev = normalize_text(severity, "INFO").upper()
    return SEVERITY_LABELS.get(sev, sev.title())


def clean_classification(cls: str) -> str:
    raw = normalize_text(cls, "PREVENCAO").upper()
    return CLASSIFICATION_LABELS.get(raw, raw.replace("_", " ").title())


def classification_key(item: Dict[str, Any]) -> str:
    raw = first(
        item,
        ["client_classification", "classification", "final_classification"],
        "PREVENCAO"
    ).upper()

    if raw not in {"RISCO_REAL", "REVISAR_MANUALMENTE", "PREVENCAO"}:
        return "PREVENCAO"
    return raw


def polished_title(item: Dict[str, Any]) -> str:
    return first(
        item,
        [
            "client_title",
            "translated_title",
            "title_client",
            "title",
        ],
        "Observação de segurança identificada"
    )


def polished_observed(item: Dict[str, Any]) -> str:
    value = first(
        item,
        [
            "what_was_observed",
            "observed",
            "o_que_foi_observado",
            "client_observed",
            "description",
        ],
        ""
    )

    if value and value != "-":
        return value

    category = clean_category(first(item, ["category"], "GENERIC"))
    return f"Foi observada uma evidência relacionada a {category.lower()}."


def polished_importance(item: Dict[str, Any]) -> str:
    value = first(
        item,
        [
            "why_it_matters",
            "importance",
            "por_que_importa",
            "client_importance",
        ],
        ""
    )

    if value and value != "-":
        return value

    cls = classification_key(item)
    if cls == "RISCO_REAL":
        return (
            "Este ponto merece prioridade porque há evidência suficiente para "
            "tratá-lo como risco concreto no contexto da auditoria."
        )
    if cls == "REVISAR_MANUALMENTE":
        return (
            "Este ponto possui indícios relevantes, mas ainda depende de "
            "confirmação técnica antes de ser tratado como falha confirmada."
        )
    return (
        "Este ponto não foi tratado como falha confirmada, mas contribui para "
        "reduzir exposição futura e fortalecer a postura de segurança."
    )


def polished_recommendation(item: Dict[str, Any]) -> str:
    value = first(
        item,
        [
            "recommendation",
            "recommended_action",
            "client_recommendation",
            "acao_recomendada",
        ],
        ""
    )

    if value and value != "-":
        return value

    cls = classification_key(item)
    category = clean_category(first(item, ["category"], "GENERIC"))

    if cls == "RISCO_REAL":
        return (
            f"Tratar este ponto como prioridade de correção, validar a causa raiz "
            f"e registrar evidência de resolução para {category.lower()}."
        )
    if cls == "REVISAR_MANUALMENTE":
        return (
            f"Confirmar tecnicamente se a evidência relacionada a "
            f"{category.lower()} representa exposição indevida ou comportamento esperado."
        )
    return (
        f"Avaliar este ponto no ciclo de melhoria contínua, priorizando ajustes "
        f"que fortaleçam {category.lower()} sem superestimar o risco atual."
    )


def polished_reading(item: Dict[str, Any]) -> str:
    value = first(
        item,
        [
            "classification_reading",
            "reading",
            "client_classification_reading",
        ],
        ""
    )

    if value and value != "-":
        return value

    cls = classification_key(item)

    if cls == "RISCO_REAL":
        return (
            "Este item foi priorizado como risco real porque a evidência analisada "
            "é suficientemente específica para orientar tratamento."
        )
    if cls == "REVISAR_MANUALMENTE":
        return (
            "Este item não foi tratado como falha confirmada. Ele requer validação "
            "técnica complementar antes de qualquer conclusão definitiva."
        )
    return (
        "Este item representa uma melhoria preventiva ou boa prática. Ele ajuda "
        "a aumentar maturidade de segurança, mas não foi classificado como risco confirmado."
    )


# ============================================================
# Renderização dos relatórios polidos
# ============================================================

def render_item(item: Dict[str, Any], index: int) -> str:
    title = polished_title(item)
    severity = clean_severity(first(item, ["severity"], "INFO"))
    category = clean_category(first(item, ["category"], "GENERIC"))
    cls = clean_classification(classification_key(item))

    return f"""### {index}. {title}

- **Classificação:** {cls}
- **Nível técnico:** {severity}
- **Tema:** {category}

**O que foi observado:** {polished_observed(item)}

**Por que isso importa:** {polished_importance(item)}

**Recomendação:** {polished_recommendation(item)}

**Leitura da classificação:** {polished_reading(item)}
"""


def render_prevention_group(category: str, items: List[Dict[str, Any]]) -> str:
    title = clean_category(category)
    count = len(items)

    examples = []
    for item in items[:3]:
        examples.append(polished_title(item))

    examples_md = "\n".join(f"- {ex}" for ex in examples) if examples else "- Sem exemplo textual disponível."

    return f"""### {title} — {count} item(ns)

**Síntese:** Foram agrupadas recomendações preventivas relacionadas a {title.lower()}.

**Exemplos observados:**
{examples_md}

**Tratamento sugerido:** Avaliar esses pontos dentro do ciclo de melhoria contínua, priorizando ajustes que reduzam exposição futura sem inflar artificialmente o risco atual.
"""


def render_executive_report(
    meta: Dict[str, Any],
    stats: Dict[str, int],
    risks: List[Dict[str, Any]],
    review: List[Dict[str, Any]],
    prevention: List[Dict[str, Any]],
) -> str:
    client = meta["client"]
    target = meta["target"]
    profile = meta["profile"]
    scan_dir = meta["scan_dir"]

    risk_count = stats["RISCO_REAL"]
    review_count = stats["REVISAR_MANUALMENTE"]
    preventive_count = stats["PREVENCAO"]

    top_risks = risks[:5]
    top_reviews = review[:5]

    risk_lines = "\n".join(
        f"- **{polished_title(item)}** — {clean_severity(first(item, ['severity'], 'INFO'))} — {clean_category(first(item, ['category'], 'GENERIC'))}"
        for item in top_risks
    ) or "- Nenhum risco real priorizado foi consolidado nesta rodada."

    review_lines = "\n".join(
        f"- **{polished_title(item)}** — exige confirmação técnica antes de conclusão definitiva."
        for item in top_reviews
    ) or "- Nenhum item pendente de revisão manual foi consolidado."

    return f"""# CyberLab — Relatório Executivo Polido

## 1. Identificação da auditoria

- **Cliente:** {client}
- **Alvo analisado:** {target}
- **Perfil de execução:** {profile}
- **Pasta oficial do scan:** `{scan_dir}`
- **Gerado em:** {now_iso()}

---

## 2. Leitura objetiva do resultado

A auditoria consolidada identificou:

- **{risk_count} risco(s) real(is) priorizado(s)**;
- **{review_count} ponto(s) que exigem validação técnica complementar**;
- **{preventive_count} recomendação(ões) preventiva(s)**.

A classificação final foi construída para separar com clareza:

1. o que representa evidência mais concreta de risco;
2. o que ainda depende de confirmação humana;
3. o que fortalece a segurança, mas não deve ser apresentado como falha confirmada.

---

## 3. O que exige ação primeiro

{risk_lines}

---

## 4. O que precisa de validação técnica

{review_lines}

---

## 5. Como interpretar as recomendações preventivas

As recomendações preventivas não significam, isoladamente, que o ambiente esteja vulnerável.  
Elas indicam oportunidades de amadurecimento técnico, redução de exposição futura e melhoria da postura de segurança.

Nesta auditoria, foram consolidadas **{preventive_count} recomendações preventivas**, tratadas de forma separada para evitar que pontos genéricos sejam confundidos com riscos reais.

---

## 6. Orientação executiva

A sequência recomendada é:

1. corrigir ou mitigar os riscos reais priorizados;
2. revisar manualmente os sinais que ainda dependem de confirmação;
3. incorporar as melhorias preventivas ao plano contínuo de segurança.

---

## 7. Conclusão executiva

O ambiente analisado apresentou **{risk_count} risco(s) real(is)** com prioridade de tratamento,  
**{review_count} item(ns)** que pedem validação adicional e  
**{preventive_count} recomendação(ões)** que podem fortalecer a maturidade de segurança.

Este relatório foi polido para comunicação com cliente final, reduzindo excesso de linguagem técnica e evitando transformar qualquer sinal de scanner em conclusão definitiva.
"""


def render_technical_report(
    meta: Dict[str, Any],
    stats: Dict[str, int],
    severity_stats: Dict[str, int],
    risks: List[Dict[str, Any]],
    review: List[Dict[str, Any]],
    prevention: List[Dict[str, Any]],
) -> str:
    client = meta["client"]
    target = meta["target"]
    profile = meta["profile"]
    scan_dir = meta["scan_dir"]

    severity_lines = "\n".join(
        f"- **{clean_severity(sev)}:** {qty}"
        for sev, qty in severity_stats.items()
    ) or "- Sem consolidação de severidade."

    risk_sections = "\n".join(
        render_item(item, idx)
        for idx, item in enumerate(risks, start=1)
    ) or "Nenhum risco real priorizado foi consolidado."

    review_sections = "\n".join(
        render_item(item, idx)
        for idx, item in enumerate(review, start=1)
    ) or "Nenhum item pendente de revisão manual foi consolidado."

    grouped_prevention: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for item in prevention:
        grouped_prevention[first(item, ["category"], "GENERIC")].append(item)

    prevention_sections = "\n".join(
        render_prevention_group(category, items)
        for category, items in sorted(grouped_prevention.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    ) or "Nenhuma recomendação preventiva foi consolidada."

    return f"""# CyberLab — Relatório Técnico Polido

## 1. Dados da auditoria

- **Cliente:** {client}
- **Alvo:** {target}
- **Perfil:** {profile}
- **Scan oficial:** `{scan_dir}`
- **Gerado em:** {now_iso()}

---

## 2. Resumo técnico consolidado

- **Risco real:** {stats["RISCO_REAL"]}
- **Revisar manualmente:** {stats["REVISAR_MANUALMENTE"]}
- **Prevenção / melhoria:** {stats["PREVENCAO"]}

### Distribuição por severidade

{severity_lines}

---

## 3. Riscos reais priorizados

{risk_sections}

---

## 4. Itens que pedem validação manual

{review_sections}

---

## 5. Recomendações preventivas agrupadas

{prevention_sections}

---

## 6. Observação metodológica

Este relatório é resultado da consolidação final dos dados coletados nas camadas anteriores do CyberLab.

A leitura técnica foi organizada em três níveis:

1. **Risco real:** achado com evidência específica e prioridade de tratamento;
2. **Revisar manualmente:** sinal relevante que ainda exige validação humana;
3. **Prevenção:** recomendação de melhoria que não deve ser tratada como falha confirmada.

Essa separação reduz falsos alarmes, melhora a qualidade da entrega e evita superestimar riscos diante do cliente.
"""


def render_remediation_plan(
    meta: Dict[str, Any],
    stats: Dict[str, int],
    risks: List[Dict[str, Any]],
    review: List[Dict[str, Any]],
    prevention: List[Dict[str, Any]],
) -> str:
    client = meta["client"]
    target = meta["target"]

    immediate = "\n".join(
        f"""### {idx}. {polished_title(item)}

- **Tema:** {clean_category(first(item, ['category'], 'GENERIC'))}
- **Nível técnico:** {clean_severity(first(item, ['severity'], 'INFO'))}
- **Ação recomendada:** {polished_recommendation(item)}
"""
        for idx, item in enumerate(risks, start=1)
    ) or "Nenhum risco real priorizado foi consolidado."

    validation = "\n".join(
        f"""### {idx}. {polished_title(item)}

- **Tema:** {clean_category(first(item, ['category'], 'GENERIC'))}
- **Motivo da revisão:** {polished_importance(item)}
- **Ação recomendada:** {polished_recommendation(item)}
"""
        for idx, item in enumerate(review, start=1)
    ) or "Nenhum item de revisão manual foi consolidado."

    grouped_prevention: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for item in prevention:
        grouped_prevention[first(item, ["category"], "GENERIC")].append(item)

    preventive_lines = []
    for category, items in sorted(grouped_prevention.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        preventive_lines.append(
            f"- **{clean_category(category)}:** {len(items)} recomendação(ões) preventiva(s)."
        )

    preventive_summary = "\n".join(preventive_lines) or "- Nenhuma recomendação preventiva consolidada."

    return f"""# CyberLab — Plano de Remediação Polido

## 1. Escopo

- **Cliente:** {client}
- **Alvo:** {target}
- **Gerado em:** {now_iso()}

---

## 2. Estratégia de tratamento

O plano de ação foi organizado em três frentes:

1. **Correção prioritária** dos riscos reais;
2. **Validação técnica** dos sinais que ainda exigem confirmação;
3. **Melhoria contínua** das recomendações preventivas.

---

## 3. Prioridade A — Tratar riscos reais

Quantidade consolidada: **{stats["RISCO_REAL"]}**

{immediate}

---

## 4. Prioridade B — Validar tecnicamente

Quantidade consolidada: **{stats["REVISAR_MANUALMENTE"]}**

{validation}

---

## 5. Prioridade C — Incorporar melhorias preventivas

Quantidade consolidada: **{stats["PREVENCAO"]}**

{preventive_summary}

Esses itens devem ser avaliados no ciclo de melhoria do ambiente, priorizando controles que reduzam exposição futura e aumentem consistência de segurança.

---

## 6. Checklist de encerramento

- [ ] Riscos reais priorizados foram tratados ou possuem plano formal de correção;
- [ ] Itens de revisão manual foram confirmados ou descartados;
- [ ] Melhorias preventivas foram organizadas por prioridade operacional;
- [ ] Evidências de correção foram anexadas ao processo;
- [ ] Nova validação foi agendada quando necessário.

---

## 7. Conclusão

O objetivo deste plano é transformar a saída técnica da auditoria em uma sequência prática de decisão:

- agir rapidamente no que importa;
- validar antes de afirmar;
- melhorar continuamente sem gerar alarmismo desnecessário.
"""


def render_summary(
    meta: Dict[str, Any],
    stats: Dict[str, int],
    outputs: Dict[str, Path],
) -> str:
    lines = [
        "# CyberLab — Camada 4C.1",
        "",
        "## Polimento editorial final dos relatórios do cliente",
        "",
        f"- **Cliente:** {meta['client']}",
        f"- **Alvo:** {meta['target']}",
        f"- **Perfil:** {meta['profile']}",
        f"- **Scan oficial:** `{meta['scan_dir']}`",
        f"- **Gerado em:** {now_iso()}",
        "",
        "## Classificação final considerada",
        "",
        f"- **Risco real:** {stats['RISCO_REAL']}",
        f"- **Revisar manualmente:** {stats['REVISAR_MANUALMENTE']}",
        f"- **Prevenção:** {stats['PREVENCAO']}",
        "",
        "## Arquivos gerados",
        "",
    ]

    for label, path in outputs.items():
        lines.append(f"- **{label}:** `{path}`")

    lines.extend([
        "",
        "## Resultado",
        "",
        "A Camada 4C.1 refinou a narrativa de entrega, preservando a classificação técnica consolidada e preparando os documentos para a geração dos PDFs finais da Camada 4D.",
    ])

    return "\n".join(lines)


# ============================================================
# Execução principal
# ============================================================

def main() -> None:
    context = load_json(AUDIT_CONTEXT, {})
    if not isinstance(context, dict) or not context:
        fail("Contexto oficial não encontrado em state/audit/current_audit_context.json")

    if len(sys.argv) >= 2 and sys.argv[1].strip():
        scan_dir = Path(sys.argv[1]).expanduser()
    else:
        raw_scan = context.get("scan_dir") or context.get("paths", {}).get("scan_dir")
        if not raw_scan:
            fail("scan_dir não encontrado no contexto oficial da auditoria.")
        scan_dir = Path(raw_scan)

    if not scan_dir.exists():
        fail(f"Pasta oficial do scan não encontrada: {scan_dir}")

    delivery_dir = scan_dir / "block_17_client_final_delivery"
    delivery_dir.mkdir(parents=True, exist_ok=True)

    classified_json = delivery_dir / "findings_classified.json"
    translated_json = delivery_dir / "client_language_findings.json"

    if not classified_json.exists():
        fail(f"Arquivo obrigatório ausente: {classified_json}")

    classified = load_json(classified_json, {})
    translated = load_json(translated_json, {})

    findings = translated.get("findings") if isinstance(translated, dict) else None
    if not isinstance(findings, list) or not findings:
        findings = classified.get("findings", [])

    if not isinstance(findings, list):
        fail("Não consegui localizar a lista de findings para polimento editorial.")

    client = (
        context.get("client_name")
        or classified.get("client")
        or translated.get("client")
        or "Cliente não informado"
    )

    target = (
        context.get("target")
        or classified.get("target")
        or translated.get("target")
        or "Alvo não informado"
    )

    profile = (
        context.get("profile")
        or classified.get("profile")
        or translated.get("profile")
        or "perfil não informado"
    )

    meta = {
        "client": client,
        "target": target,
        "profile": profile,
        "scan_dir": str(scan_dir),
    }

    by_class = Counter(classification_key(item) for item in findings)
    stats = {
        "RISCO_REAL": int(by_class.get("RISCO_REAL", 0)),
        "REVISAR_MANUALMENTE": int(by_class.get("REVISAR_MANUALMENTE", 0)),
        "PREVENCAO": int(by_class.get("PREVENCAO", 0)),
    }

    severity_counter = Counter(
        first(item, ["severity"], "INFO").upper()
        for item in findings
    )

    preferred_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    severity_stats = {
        sev: int(severity_counter.get(sev, 0))
        for sev in preferred_order
        if severity_counter.get(sev, 0) > 0
    }

    risks = [item for item in findings if classification_key(item) == "RISCO_REAL"]
    review = [item for item in findings if classification_key(item) == "REVISAR_MANUALMENTE"]
    prevention = [item for item in findings if classification_key(item) == "PREVENCAO"]

    executive_md = delivery_dir / "client_final_executive_report_polished.md"
    technical_md = delivery_dir / "client_final_technical_report_polished.md"
    remediation_md = delivery_dir / "client_final_remediation_plan_polished.md"
    manifest_json = delivery_dir / "client_final_editorial_manifest.json"
    summary_md = delivery_dir / "block_17_4c1_summary.md"
    status_json = delivery_dir / "block_17_4c1_status.json"

    write_text(
        executive_md,
        render_executive_report(meta, stats, risks, review, prevention)
    )
    write_text(
        technical_md,
        render_technical_report(meta, stats, severity_stats, risks, review, prevention)
    )
    write_text(
        remediation_md,
        render_remediation_plan(meta, stats, risks, review, prevention)
    )

    outputs = {
        "Relatório executivo polido": executive_md,
        "Relatório técnico polido": technical_md,
        "Plano de remediação polido": remediation_md,
        "Manifesto editorial": manifest_json,
        "Resumo da Camada 4C.1": summary_md,
        "Status da Camada 4C.1": status_json,
    }

    manifest = {
        "schema": "cyberlab.client_final.editorial_manifest.v1",
        "stage": "block17_4c1_editorial_polisher",
        "status": "OK",
        "generated_at": now_iso(),
        "client": client,
        "target": target,
        "profile": profile,
        "scan_dir": str(scan_dir),
        "inputs": {
            "findings_classified_json": str(classified_json),
            "client_language_findings_json": str(translated_json),
        },
        "stats": {
            "total_findings": len(findings),
            "by_client_classification": stats,
            "by_severity": severity_stats,
        },
        "outputs": {
            key: file_record(path, "file", key)
            for key, path in outputs.items()
        },
    }

    write_json(manifest_json, manifest)
    write_text(summary_md, render_summary(meta, stats, outputs))

    status = {
        "block": "17_4c1",
        "module": "CyberLab Editorial Polisher",
        "status": "OK",
        "message": "Relatórios finais do cliente polidos e sincronizados.",
        "updated_at": now_iso(),
        "scan_dir": str(scan_dir),
        "stats": {
            "total_findings": len(findings),
            "by_client_classification": stats,
            "by_severity": severity_stats,
        },
        "outputs": {
            "executive_polished_md": str(executive_md),
            "technical_polished_md": str(technical_md),
            "remediation_polished_md": str(remediation_md),
            "manifest_json": str(manifest_json),
            "summary_md": str(summary_md),
        },
    }

    write_json(status_json, status)

    # Atualiza o contexto oficial da auditoria
    context.setdefault("stages", {})
    context.setdefault("artifacts", {})
    context.setdefault("notes", [])

    context["updated_at"] = now_iso()
    context["stages"]["block17_4c1_editorial_polisher"] = {
        "status": "OK",
        "message": "Camada 4C.1 executada e sincronizada.",
        "updated_at": now_iso(),
        "status_json": str(status_json),
        "manifest_json": str(manifest_json),
    }

    context["artifacts"]["block17_4c1_executive_polished_md"] = file_record(
        executive_md,
        "file",
        "Relatório executivo polido para entrega final."
    )
    context["artifacts"]["block17_4c1_technical_polished_md"] = file_record(
        technical_md,
        "file",
        "Relatório técnico polido para entrega final."
    )
    context["artifacts"]["block17_4c1_remediation_polished_md"] = file_record(
        remediation_md,
        "file",
        "Plano de remediação polido para entrega final."
    )
    context["artifacts"]["block17_4c1_manifest_json"] = file_record(
        manifest_json,
        "file",
        "Manifesto editorial dos relatórios finais."
    )
    context["artifacts"]["block17_4c1_summary_md"] = file_record(
        summary_md,
        "file",
        "Resumo da Camada 4C.1."
    )
    context["artifacts"]["block17_4c1_status_json"] = file_record(
        status_json,
        "file",
        "Status da Camada 4C.1."
    )

    note = "Camada 4C.1 aplicada: relatórios finais-base foram polidos antes da futura geração de PDFs da Camada 4D."
    if note not in context["notes"]:
        context["notes"].append(note)

    write_json(AUDIT_CONTEXT, context)

    print("==============================================================")
    print(" CyberLab — Camada 4C.1")
    print(" Polimento editorial e preparação para PDFs finais")
    print("==============================================================")
    print()
    print(f"[OK] Cliente: {client}")
    print(f"[OK] Alvo: {target}")
    print(f"[OK] Scan oficial: {scan_dir}")
    print()
    print("[CLASSIFICAÇÃO FINAL PRESERVADA]")
    print(f" - RISCO_REAL: {stats['RISCO_REAL']}")
    print(f" - REVISAR_MANUALMENTE: {stats['REVISAR_MANUALMENTE']}")
    print(f" - PREVENCAO: {stats['PREVENCAO']}")
    print()
    print("[ARQUIVOS GERADOS]")
    print(f" - {executive_md}")
    print(f" - {technical_md}")
    print(f" - {remediation_md}")
    print(f" - {manifest_json}")
    print(f" - {summary_md}")
    print(f" - {status_json}")
    print()
    print("[OK] Contexto oficial atualizado com os artefatos da Camada 4C.1.")
    print("[OK] Camada 4C.1 finalizada.")


if __name__ == "__main__":
    main()
