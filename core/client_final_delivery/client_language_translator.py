#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple


HOME = Path.home()
CYBERLAB_HOME = HOME / "CyberLab"
AUDIT_CONTEXT = CYBERLAB_HOME / "state" / "audit" / "current_audit_context.json"


# ============================================================
# CAMADA 4B — TRADUTOR PARA LINGUAGEM DE CLIENTE FINAL
# ============================================================


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Dict[str, Any]) -> None:
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def md_escape(value: Any) -> str:
    return str(value or "-").replace("\n", " ").strip()


def load_context() -> Dict[str, Any]:
    if not AUDIT_CONTEXT.exists():
        raise SystemExit(
            f"[ERRO] Contexto oficial não encontrado: {AUDIT_CONTEXT}\n"
            "Rode primeiro o fluxo sincronizado da Camada 3 / Bloco 16."
        )
    return read_json(AUDIT_CONTEXT)


def resolve_scan_dir(cli_scan_dir: str | None, context: Dict[str, Any]) -> Path:
    if cli_scan_dir:
        scan_dir = Path(cli_scan_dir).expanduser().resolve()
    else:
        scan_value = (
            context.get("scan_dir")
            or context.get("paths", {}).get("scan_dir")
            or context.get("paths", {}).get("official_scan_dir")
        )
        if not scan_value:
            raise SystemExit(
                "[ERRO] Contexto oficial existe, mas não possui scan_dir."
            )
        scan_dir = Path(scan_value).expanduser().resolve()

    if not scan_dir.exists():
        raise SystemExit(f"[ERRO] Pasta do scan não existe: {scan_dir}")

    return scan_dir


def severity_label(severity: str) -> str:
    s = (severity or "INFO").upper()
    mapping = {
        "CRITICAL": "Crítico",
        "HIGH": "Alto",
        "MEDIUM": "Médio",
        "LOW": "Baixo",
        "INFO": "Informativo",
    }
    return mapping.get(s, s.title())


def attention_label(client_classification: str) -> str:
    c = (client_classification or "").upper()
    return {
        "RISCO_REAL": "Atenção prioritária",
        "REVISAR_MANUALMENTE": "Validar tecnicamente",
        "PREVENCAO": "Melhoria preventiva",
    }.get(c, "Análise complementar")


def public_classification_label(client_classification: str) -> str:
    c = (client_classification or "").upper()
    return {
        "RISCO_REAL": "Risco identificado",
        "REVISAR_MANUALMENTE": "Ponto que requer validação",
        "PREVENCAO": "Recomendação preventiva",
    }.get(c, "Ponto técnico")


def friendly_category(category: str) -> str:
    cat = (category or "GENERIC").upper()
    mapping = {
        "EXPOSURE": "Exposição de informação",
        "EXPOSED_PANEL": "Área administrativa ou painel acessível",
        "HEADER": "Proteções do navegador",
        "SURFACE_PORT": "Serviços expostos",
        "SURFACE_API": "Interfaces de aplicação",
        "SURFACE_CDN": "Infraestrutura e distribuição",
        "SURFACE_WAF": "Camadas de proteção",
        "SURFACE_AUTH": "Autenticação",
        "SURFACE_TECH": "Tecnologias identificadas",
        "PORT": "Serviços expostos",
        "TOKEN": "Tokens e identificadores",
        "API": "Interfaces de aplicação",
        "GENERIC": "Observação técnica",
    }
    return mapping.get(cat, cat.replace("_", " ").title())


def explanation_for(item: Dict[str, Any]) -> Tuple[str, str, str]:
    """
    Retorna:
    - explanation_client
    - why_it_matters
    - recommendation_client
    """
    title = str(item.get("title", "")).lower()
    category = str(item.get("category", "GENERIC")).upper()
    classification = str(item.get("client_classification", "")).upper()

    # 1) Status do servidor exposto
    if "status do servidor" in title or "server status" in title:
        return (
            "Foi localizado um endereço que aparenta expor informações operacionais do servidor.",
            "Esse tipo de informação pode facilitar o entendimento da estrutura do ambiente por terceiros e apoiar tentativas de exploração.",
            "Revisar a necessidade dessa página, restringir o acesso quando possível e garantir que dados internos não sejam exibidos publicamente.",
        )

    # 2) Painel administrativo
    if "painel administrativo" in title or category == "EXPOSED_PANEL":
        return (
            "Foi identificado um endereço que pode estar relacionado a uma área administrativa ou painel de acesso.",
            "Nem todo painel exposto representa uma falha, mas a existência de uma rota administrativa pública merece validação para evitar exposição desnecessária.",
            "Confirmar se o endereço realmente pertence a uma área administrativa, validar autenticação e revisar se a rota precisa estar acessível publicamente.",
        )

    # 3) CSP
    if "content-security-policy" in title or "csp" in title:
        return (
            "O site não apresentou uma política de segurança de conteúdo claramente configurada.",
            "Essa proteção ajuda o navegador a reduzir impactos de injeções de conteúdo e scripts maliciosos em cenários específicos.",
            "Avaliar a implementação de Content-Security-Policy compatível com o funcionamento do site.",
        )

    # 4) HSTS
    if "hsts" in title or "strict-transport-security" in title:
        return (
            "Não foi observada a proteção HSTS no cabeçalho analisado.",
            "Essa configuração reforça o uso de conexão segura e ajuda a evitar acessos indevidos por versões não criptografadas em determinados cenários.",
            "Avaliar a ativação de HSTS após confirmar que todo o site opera corretamente sob HTTPS.",
        )

    # 5) Portas
    if "porta" in title or category in {"SURFACE_PORT", "PORT"}:
        return (
            "Foi observada a presença de serviço exposto na superfície pública analisada.",
            "Serviços publicados podem ser legítimos, mas devem existir apenas quando forem necessários e estar devidamente controlados.",
            "Validar a finalidade do serviço identificado e manter exposto somente o que for realmente necessário.",
        )

    # 6) APIs
    if category in {"SURFACE_API", "API"}:
        return (
            "Foram identificados sinais de interfaces de aplicação acessíveis durante a análise.",
            "APIs públicas ou parcialmente expostas podem ampliar a superfície de atenção, especialmente quando não estão bem documentadas ou controladas.",
            "Revisar autenticação, respostas públicas, mensagens de erro e necessidade de exposição de cada interface.",
        )

    # 7) Headers genéricos
    if category == "HEADER":
        return (
            "Foi identificada uma configuração de proteção do navegador que pode ser aprimorada.",
            "Essas políticas não são, sozinhas, prova de comprometimento, mas ajudam a reduzir riscos e aumentar a robustez do ambiente.",
            "Revisar os cabeçalhos de segurança recomendados e aplicar os que forem compatíveis com o site.",
        )

    # 8) Exposição genérica
    if category == "EXPOSURE":
        return (
            "Foi identificado um indício de exposição que merece atenção técnica.",
            "A exposição de informações ou rotas pode facilitar o reconhecimento do ambiente por terceiros.",
            "Validar o recurso identificado e restringir, remover ou endurecer o acesso quando aplicável.",
        )

    # 9) Prevenção genérica
    if classification == "PREVENCAO":
        return (
            "Foi observada uma oportunidade de reforço preventivo na superfície analisada.",
            "Esse ponto não foi classificado como falha confirmada, mas pode contribuir para uma postura de segurança mais madura.",
            "Avaliar a recomendação no ciclo de melhoria contínua do ambiente.",
        )

    # 10) Revisão manual genérica
    if classification == "REVISAR_MANUALMENTE":
        return (
            "Foi identificado um sinal técnico relevante que precisa de confirmação humana.",
            "O mecanismo automático detectou um indício, mas ainda não há evidência suficiente para tratá-lo como risco confirmado.",
            "Executar validação manual controlada antes de classificar definitivamente o impacto.",
        )

    # 11) Risco real genérico
    if classification == "RISCO_REAL":
        return (
            "Foi identificado um ponto com evidência suficiente para tratamento como risco técnico relevante.",
            "Esse achado possui indícios consistentes de exposição ou fragilidade e deve ser priorizado pela equipe responsável.",
            "Planejar correção ou mitigação, registrar evidências e acompanhar a validação após o ajuste.",
        )

    return (
        "Foi registrado um achado técnico durante a análise.",
        "O item contribui para a leitura geral da superfície de segurança do ambiente.",
        "Revisar tecnicamente o achado e definir a ação adequada.",
    )


def impact_message(classification: str) -> str:
    c = (classification or "").upper()
    if c == "RISCO_REAL":
        return (
            "Este item foi tratado como risco real porque possui evidência suficiente "
            "para entrar no plano de ação do cliente."
        )
    if c == "REVISAR_MANUALMENTE":
        return (
            "Este item não foi tratado como falha confirmada. Ele requer validação "
            "técnica complementar antes de qualquer conclusão definitiva."
        )
    if c == "PREVENCAO":
        return (
            "Este item representa uma melhoria preventiva ou boa prática. "
            "Ele contribui para reduzir exposição futura, mas não foi classificado "
            "como risco confirmado."
        )
    return "Este item requer leitura técnica complementar."


def convert_finding(item: Dict[str, Any], index: int) -> Dict[str, Any]:
    classification = str(item.get("client_classification", "PREVENCAO")).upper()
    severity = str(item.get("severity", "INFO")).upper()

    explanation, why, recommendation = explanation_for(item)

    return {
        "id": item.get("id") or f"CLF-{index:04d}",
        "title": item.get("title") or "Achado técnico",
        "technical_title": item.get("title") or "Achado técnico",
        "category": item.get("category", "GENERIC"),
        "friendly_category": friendly_category(item.get("category", "GENERIC")),
        "technical_severity": severity,
        "severity_label": severity_label(severity),
        "client_classification": classification,
        "client_classification_label": public_classification_label(classification),
        "attention_label": attention_label(classification),
        "review_status": item.get("review_status", ""),
        "risk_score": item.get("risk_score"),
        "what_was_observed": explanation,
        "why_it_matters": why,
        "recommended_action": recommendation,
        "classification_context": impact_message(classification),
        "classification_reason": item.get(
            "client_classification_reason",
            item.get("classification_reason", "-"),
        ),
        "technical_evidence": item.get("evidence", ""),
        "source_type": item.get("source_type", ""),
        "raw": item,
    }


def sort_findings(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    class_priority = {
        "RISCO_REAL": 0,
        "REVISAR_MANUALMENTE": 1,
        "PREVENCAO": 2,
    }
    sev_priority = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4,
    }

    return sorted(
        items,
        key=lambda x: (
            class_priority.get(x.get("client_classification", ""), 99),
            sev_priority.get(x.get("technical_severity", ""), 99),
            str(x.get("title", "")),
        ),
    )


def group_by_classification(items: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    grouped = {
        "RISCO_REAL": [],
        "REVISAR_MANUALMENTE": [],
        "PREVENCAO": [],
    }
    for item in items:
        key = item.get("client_classification", "PREVENCAO")
        grouped.setdefault(key, []).append(item)
    return grouped


def count_by_classification(items: List[Dict[str, Any]]) -> Dict[str, int]:
    result = {
        "RISCO_REAL": 0,
        "REVISAR_MANUALMENTE": 0,
        "PREVENCAO": 0,
    }
    for item in items:
        key = item.get("client_classification", "PREVENCAO")
        result[key] = result.get(key, 0) + 1
    return result


def count_by_severity(items: List[Dict[str, Any]]) -> Dict[str, int]:
    result = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }
    for item in items:
        key = item.get("technical_severity", "INFO")
        result[key] = result.get(key, 0) + 1
    return result


def count_by_friendly_category(items: List[Dict[str, Any]]) -> Dict[str, int]:
    output: Dict[str, int] = {}
    for item in items:
        key = item.get("friendly_category", "Observação técnica")
        output[key] = output.get(key, 0) + 1
    return dict(sorted(output.items(), key=lambda pair: (-pair[1], pair[0])))


def client_executive_overview(
    counts: Dict[str, int],
    findings: List[Dict[str, Any]],
) -> List[str]:
    risk_real = counts.get("RISCO_REAL", 0)
    manual = counts.get("REVISAR_MANUALMENTE", 0)
    preventive = counts.get("PREVENCAO", 0)

    lines: List[str] = []

    if risk_real > 0:
        lines.append(
            f"Foram identificados {risk_real} ponto(s) que merecem tratamento prioritário, "
            "por apresentarem evidência suficiente para serem considerados riscos relevantes."
        )
    else:
        lines.append(
            "Não foram identificados riscos confirmados de maior impacto na consolidação automática desta etapa."
        )

    if manual > 0:
        lines.append(
            f"Há {manual} item(ns) que devem passar por validação técnica manual antes de uma conclusão definitiva."
        )

    if preventive > 0:
        lines.append(
            f"Também foram registradas {preventive} recomendação(ões) preventivas e melhorias de postura de segurança."
        )

    if findings:
        first = findings[0]
        lines.append(
            f"O ponto de maior prioridade identificado nesta camada foi: "
            f"“{first.get('title', 'Achado prioritário')}”."
        )

    return lines


def render_section(title: str, items: List[Dict[str, Any]]) -> List[str]:
    lines: List[str] = []
    lines.append(f"## {title}")
    lines.append("")

    if not items:
        lines.append("_Nenhum item nesta categoria._")
        lines.append("")
        return lines

    for idx, item in enumerate(items, start=1):
        lines.append(f"### {idx}. {md_escape(item['title'])}")
        lines.append("")
        lines.append(f"- **Classificação:** {md_escape(item['client_classification_label'])}")
        lines.append(f"- **Nível técnico:** {md_escape(item['severity_label'])}")
        lines.append(f"- **Tema:** {md_escape(item['friendly_category'])}")
        lines.append(f"- **Prioridade:** {md_escape(item['attention_label'])}")
        lines.append("")
        lines.append(f"**O que foi observado:** {md_escape(item['what_was_observed'])}")
        lines.append("")
        lines.append(f"**Por que isso importa:** {md_escape(item['why_it_matters'])}")
        lines.append("")
        lines.append(f"**Recomendação:** {md_escape(item['recommended_action'])}")
        lines.append("")
        lines.append(f"**Leitura da classificação:** {md_escape(item['classification_context'])}")
        lines.append("")
    return lines


def render_client_md(
    meta: Dict[str, Any],
    counts: Dict[str, int],
    severity_counts: Dict[str, int],
    categories: Dict[str, int],
    grouped: Dict[str, List[Dict[str, Any]]],
    overview: List[str],
) -> str:
    lines: List[str] = []

    lines.append("# CyberLab — Camada 4B")
    lines.append("")
    lines.append("## Tradução dos achados para linguagem de cliente final")
    lines.append("")
    lines.append(f"- **Cliente:** {md_escape(meta.get('client'))}")
    lines.append(f"- **Alvo analisado:** {md_escape(meta.get('target'))}")
    lines.append(f"- **Perfil:** {md_escape(meta.get('profile'))}")
    lines.append(f"- **Pasta oficial do scan:** `{md_escape(meta.get('scan_dir'))}`")
    lines.append(f"- **Gerado em:** {md_escape(meta.get('generated_at'))}")
    lines.append("")

    lines.append("## Resumo executivo")
    lines.append("")
    for item in overview:
        lines.append(f"- {md_escape(item)}")
    lines.append("")

    lines.append("## Classificação consolidada para entrega")
    lines.append("")
    lines.append(f"- **Riscos identificados:** {counts.get('RISCO_REAL', 0)}")
    lines.append(f"- **Pontos para validação técnica:** {counts.get('REVISAR_MANUALMENTE', 0)}")
    lines.append(f"- **Recomendações preventivas:** {counts.get('PREVENCAO', 0)}")
    lines.append("")

    lines.append("## Severidade técnica de referência")
    lines.append("")
    for key in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        lines.append(f"- **{key}:** {severity_counts.get(key, 0)}")
    lines.append("")

    lines.append("## Principais temas observados")
    lines.append("")
    if categories:
        for key, value in categories.items():
            lines.append(f"- **{md_escape(key)}:** {value}")
    else:
        lines.append("- Nenhum tema agregado.")
    lines.append("")

    lines.extend(render_section(
        "1. Riscos identificados que devem entrar no plano de ação",
        grouped.get("RISCO_REAL", []),
    ))
    lines.extend(render_section(
        "2. Pontos que exigem validação técnica manual",
        grouped.get("REVISAR_MANUALMENTE", []),
    ))
    lines.extend(render_section(
        "3. Melhorias preventivas e boas práticas",
        grouped.get("PREVENCAO", []),
    ))

    lines.append("## Nota metodológica")
    lines.append("")
    lines.append(
        "Esta camada transforma os achados técnicos consolidados em uma leitura mais adequada "
        "para comunicação com o cliente final. Ela preserva a rastreabilidade técnica, mas evita "
        "apresentar como falha confirmada itens que são apenas indícios ou recomendações preventivas."
    )
    lines.append("")

    return "\n".join(lines)


def render_summary_md(
    meta: Dict[str, Any],
    input_file: Path,
    output_files: Dict[str, Path],
    counts: Dict[str, int],
) -> str:
    lines = [
        "# CyberLab — Camada 4B",
        "",
        "## Tradução técnica para linguagem de cliente final",
        "",
        f"- **Cliente:** {meta.get('client', '-')}",
        f"- **Alvo:** {meta.get('target', '-')}",
        f"- **Perfil:** {meta.get('profile', '-')}",
        f"- **Scan oficial:** `{meta.get('scan_dir', '-')}`",
        f"- **Gerado em:** {meta.get('generated_at', '-')}",
        "",
        "## Entrada utilizada",
        "",
        f"- `{input_file}`",
        "",
        "## Resultado da tradução",
        "",
        f"- **Riscos identificados:** {counts.get('RISCO_REAL', 0)}",
        f"- **Revisar manualmente:** {counts.get('REVISAR_MANUALMENTE', 0)}",
        f"- **Prevenção / melhoria:** {counts.get('PREVENCAO', 0)}",
        "",
        "## Arquivos gerados",
        "",
    ]

    for name, path in output_files.items():
        lines.append(f"- **{name}:** `{path}`")

    lines.extend([
        "",
        "## Status",
        "",
        "- **Camada 4B:** concluída com sucesso.",
        "- O conteúdo está pronto para ser consumido pela próxima etapa de geração de relatórios finais em PDF.",
        "",
    ])

    return "\n".join(lines)


def update_audit_context(
    context: Dict[str, Any],
    output_files: Dict[str, Path],
    scan_dir: Path,
) -> None:
    context.setdefault("artifacts", {})
    context.setdefault("stages", {})

    registry = {
        "block17_4b_client_language_json": output_files["client_language_findings_json"],
        "block17_4b_client_report_base_md": output_files["client_language_report_base_md"],
        "block17_4b_summary_md": output_files["block_17_4b_summary_md"],
        "block17_4b_status_json": output_files["block_17_4b_status_json"],
    }

    for key, path in registry.items():
        context["artifacts"][key] = {
            "path": str(path),
            "kind": "file",
            "exists": path.exists(),
            "registered_at": now_iso(),
        }

    context["stages"]["block17_4b_client_language"] = {
        "status": "OK",
        "message": "Camada 4B executada e sincronizada.",
        "updated_at": now_iso(),
        "scan_dir": str(scan_dir),
        "stdout_log": None,
        "stderr_log": None,
    }

    context["updated_at"] = now_iso()
    write_json(AUDIT_CONTEXT, context)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CyberLab Camada 4B - Tradução técnica para linguagem de cliente."
    )
    parser.add_argument(
        "--scan-dir",
        help="Pasta oficial do scan. Se omitida, será obtida do contexto da auditoria.",
    )
    args = parser.parse_args()

    context = load_context()
    scan_dir = resolve_scan_dir(args.scan_dir, context)

    delivery_dir = scan_dir / "block_17_client_final_delivery"
    classified_path = delivery_dir / "findings_classified.json"

    if not classified_path.exists():
        raise SystemExit(
            f"[ERRO] findings_classified.json não encontrado: {classified_path}\n"
            "Execute primeiro a Camada 4A/4A.1."
        )

    classified = read_json(classified_path)
    raw_findings = classified.get("findings", [])

    converted = [
        convert_finding(item, idx)
        for idx, item in enumerate(raw_findings, start=1)
    ]
    converted = sort_findings(converted)

    counts = count_by_classification(converted)
    severity_counts = count_by_severity(converted)
    categories = count_by_friendly_category(converted)
    grouped = group_by_classification(converted)

    client = (
        classified.get("client")
        or context.get("client_name")
        or context.get("client")
        or "-"
    )
    target = (
        classified.get("target")
        or context.get("target")
        or "-"
    )
    profile = (
        classified.get("profile")
        or context.get("profile")
        or "-"
    )

    meta = {
        "schema": "cyberlab.block17.4b.client_language.v1",
        "client": client,
        "target": target,
        "profile": profile,
        "scan_dir": str(scan_dir),
        "input_findings_classified": str(classified_path),
        "generated_at": now_iso(),
    }

    overview = client_executive_overview(counts, converted)

    content_json = {
        **meta,
        "stats": {
            "total_findings": len(converted),
            "by_client_classification": counts,
            "by_severity": severity_counts,
            "by_friendly_category": categories,
        },
        "executive_overview": overview,
        "sections": {
            "risk_real": grouped.get("RISCO_REAL", []),
            "manual_review": grouped.get("REVISAR_MANUALMENTE", []),
            "prevention": grouped.get("PREVENCAO", []),
        },
        "findings": converted,
    }

    delivery_dir.mkdir(parents=True, exist_ok=True)

    client_language_json = delivery_dir / "client_language_findings.json"
    client_report_base_md = delivery_dir / "client_language_report_base.md"
    block_17_4b_summary_md = delivery_dir / "block_17_4b_summary.md"
    block_17_4b_status_json = delivery_dir / "block_17_4b_status.json"

    write_json(client_language_json, content_json)

    client_report_base_md.write_text(
        render_client_md(
            meta=meta,
            counts=counts,
            severity_counts=severity_counts,
            categories=categories,
            grouped=grouped,
            overview=overview,
        ),
        encoding="utf-8",
    )

    output_files = {
        "client_language_findings_json": client_language_json,
        "client_language_report_base_md": client_report_base_md,
        "block_17_4b_summary_md": block_17_4b_summary_md,
        "block_17_4b_status_json": block_17_4b_status_json,
    }

    block_17_4b_summary_md.write_text(
        render_summary_md(
            meta=meta,
            input_file=classified_path,
            output_files=output_files,
            counts=counts,
        ),
        encoding="utf-8",
    )

    status = {
        "schema": "cyberlab.block17.4b.status.v1",
        "block": "17_4B",
        "module": "Client Language Translator",
        "status": "completed",
        "generated_at": now_iso(),
        "client": client,
        "target": target,
        "profile": profile,
        "scan_dir": str(scan_dir),
        "input": {
            "findings_classified_json": str(classified_path),
        },
        "outputs": {
            key: str(path)
            for key, path in output_files.items()
        },
        "stats": {
            "total_findings": len(converted),
            "risk_real": counts.get("RISCO_REAL", 0),
            "manual_review": counts.get("REVISAR_MANUALMENTE", 0),
            "prevention": counts.get("PREVENCAO", 0),
        },
    }
    write_json(block_17_4b_status_json, status)

    update_audit_context(context, output_files, scan_dir)

    print("==============================================================")
    print(" CyberLab — Camada 4B")
    print(" Tradução técnica para linguagem de cliente final")
    print("==============================================================")
    print(f"[OK] Cliente: {client}")
    print(f"[OK] Alvo: {target}")
    print(f"[OK] Scan oficial: {scan_dir}")
    print(f"[OK] Achados traduzidos: {len(converted)}")
    print("")
    print("[CLASSIFICAÇÃO CLIENTE]")
    print(f" - RISCO_REAL: {counts.get('RISCO_REAL', 0)}")
    print(f" - REVISAR_MANUALMENTE: {counts.get('REVISAR_MANUALMENTE', 0)}")
    print(f" - PREVENCAO: {counts.get('PREVENCAO', 0)}")
    print("")
    print("[ARQUIVOS GERADOS]")
    print(f" - {client_language_json}")
    print(f" - {client_report_base_md}")
    print(f" - {block_17_4b_summary_md}")
    print(f" - {block_17_4b_status_json}")
    print("")
    print("[OK] Contexto oficial da auditoria atualizado com os artefatos da Camada 4B.")
    print("[OK] Camada 4B finalizada.")
    print("==============================================================")


if __name__ == "__main__":
    main()
