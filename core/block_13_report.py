#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CyberLab - Block 13 Delivery Enterprise

Gera:
- Relatorio executivo
- Relatorio tecnico
- Plano de remediacao
- PDFs
- SLA timeline
- Status JSON

Seguranca:
- Usa somente arquivos locais ja gerados pelo CyberLab.
- Nao executa scan.
- Nao explora alvo.
- Nao faz requisicoes externas.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional


DEFAULT_SLA = {
    "CRITICAL": "24 horas",
    "HIGH": "72 horas",
    "MEDIUM": "7 dias",
    "LOW": "30 dias",
    "INFO": "Revisao preventiva"
}


class Block13Report:
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)

    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        default = {
            "company_name": "CyberLab",
            "report_author": "CyberLab Security",
            "default_sla": DEFAULT_SLA
        }

        if not config_path:
            return default

        path = Path(config_path)

        if not path.exists():
            return default

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            default.update(data)
            return default
        except Exception:
            return default

    def load_block12(self, input_path: str) -> Dict[str, Any]:
        path = Path(input_path)

        if not path.exists():
            raise FileNotFoundError(f"Arquivo do Bloco 12 nao encontrado: {input_path}")

        data = json.loads(path.read_text(encoding="utf-8"))

        if "summary" not in data:
            raise ValueError("Arquivo do Bloco 12 invalido: campo summary ausente.")

        if "findings" not in data:
            raise ValueError("Arquivo do Bloco 12 invalido: campo findings ausente.")

        return data

    def _safe(self, value: Any, default: str = "-") -> str:
        if value is None:
            return default

        text = str(value)
        text = text.replace("\n", " ").replace("\r", " ")
        return text.strip() if text.strip() else default

    def _is_surface(self, item: Dict[str, Any]) -> bool:
        return str(item.get("category", "")).upper().startswith("SURFACE_")

    def _severity_rank(self, severity: str) -> int:
        order = {
            "CRITICAL": 5,
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2,
            "INFO": 1
        }
        return order.get(str(severity).upper(), 0)

    def _sorted_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return sorted(
            findings,
            key=lambda item: (
                int(item.get("risk_score", 0)),
                self._severity_rank(item.get("severity", "INFO"))
            ),
            reverse=True
        )

    def _risk_narrative(self, summary: Dict[str, Any]) -> str:
        risk_findings = int(summary.get("risk_findings", 0))
        surface_findings = int(summary.get("surface_findings", 0))
        risk_level = str(summary.get("risk_level", "INFO")).upper()

        if risk_findings == 0 and surface_findings > 0:
            return (
                "Nao foram identificadas evidencias automatizadas de vulnerabilidades criticas nesta etapa. "
                "A analise encontrou pontos de superficie publica, como portas, WAF/CDN, caminhos de autenticacao, "
                "scripts, tecnologias e headers. Esses pontos devem ser revisados preventivamente para reduzir "
                "exposicao e fortalecer a postura de seguranca."
            )

        if risk_findings == 0 and surface_findings == 0:
            return (
                "Nenhum achado relevante foi identificado nesta etapa automatizada. "
                "Recomenda-se manter revisoes periodicas e repetir a validacao apos mudancas no ambiente."
            )

        if risk_level in {"CRITICAL", "HIGH"}:
            return (
                "Foram identificados achados que exigem revisao prioritaria. "
                "A remediacao deve iniciar pelos itens de maior severidade, considerando evidencia, impacto e criticidade."
            )

        if risk_level == "MEDIUM":
            return (
                "Foram identificados pontos relevantes de melhoria. "
                "A recomendacao e revisar configuracoes, reduzir exposicao e fortalecer controles preventivos."
            )

        return (
            "Foram encontrados pontos de baixa criticidade ou informativos. "
            "A recomendacao e tratar como melhoria continua de seguranca."
        )

    def build_sla_timeline(self, report: Dict[str, Any]) -> Dict[str, Any]:
        findings = report.get("findings", [])
        sla = self.config.get("default_sla", DEFAULT_SLA)

        timeline = []

        for item in findings:
            severity = str(item.get("severity", "INFO")).upper()
            category = str(item.get("category", "UNKNOWN")).upper()
            surface = self._is_surface(item)

            if surface:
                priority = "Preventiva"
                due = "Revisao planejada"
            else:
                priority = severity
                due = sla.get(severity, DEFAULT_SLA.get(severity, "Revisao preventiva"))

            timeline.append({
                "title": item.get("title"),
                "category": category,
                "severity": severity,
                "priority": priority,
                "sla": due,
                "review_status": item.get("review_status"),
                "recommended_action": item.get("recommended_action"),
                "source_type": item.get("source_type"),
                "file": item.get("file"),
                "evidence": item.get("evidence")
            })

        timeline.sort(
            key=lambda item: (
                1 if item.get("priority") == "Preventiva" else 0,
                self._severity_rank(item.get("severity", "INFO"))
            ),
            reverse=True
        )

        return {
            "block": "13",
            "module": "CyberLab Delivery Enterprise",
            "target": report.get("target"),
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "timeline": timeline
        }

    def executive_markdown(self, report: Dict[str, Any]) -> str:
        summary = report.get("summary", {})
        target = report.get("target", "-")
        top = summary.get("top_priorities", [])

        lines = []

        lines.append("# Relatorio Executivo de Seguranca")
        lines.append("")
        lines.append(f"**Alvo analisado:** {target}")
        lines.append(f"**Gerado em:** {datetime.now().isoformat(timespec='seconds')}")
        lines.append(f"**Ferramenta:** {self.config.get('company_name', 'CyberLab')}")
        lines.append("")
        lines.append("## Sumario executivo")
        lines.append("")
        lines.append(self._risk_narrative(summary))
        lines.append("")
        lines.append("## Resultado geral")
        lines.append("")
        lines.append(f"- Nivel geral: **{summary.get('risk_level', 'INFO')}**")
        lines.append(f"- Score final calibrado: **{summary.get('overall_score', 0)}**")
        lines.append(f"- Achados de risco real: **{summary.get('risk_findings', 0)}**")
        lines.append(f"- Achados de superficie: **{summary.get('surface_findings', 0)}**")
        lines.append(f"- Total de achados: **{summary.get('total_findings', 0)}**")
        lines.append("")
        lines.append("## Leitura para decisao")
        lines.append("")

        if int(summary.get("risk_findings", 0)) == 0 and int(summary.get("surface_findings", 0)) > 0:
            lines.append(
                "O ambiente nao apresentou evidencia automatizada de falha critica nesta etapa. "
                "O principal ponto de atencao e a superficie publica mapeada, que deve ser revisada "
                "para confirmar se tudo que esta exposto e necessario e esta protegido."
            )
        elif int(summary.get("risk_findings", 0)) > 0:
            lines.append(
                "Existem achados que precisam ser avaliados tecnicamente. "
                "A prioridade deve considerar severidade, evidencia, impacto e facilidade de correcao."
            )
        else:
            lines.append("Nenhum ponto relevante foi identificado nesta execucao.")

        lines.append("")
        lines.append("## Categorias observadas")
        lines.append("")

        by_category = summary.get("by_category", {})

        if not by_category:
            lines.append("- Nenhuma categoria relevante identificada.")
        else:
            for category, count in by_category.items():
                lines.append(f"- **{category}:** {count}")

        lines.append("")
        lines.append("## Principais recomendacoes")
        lines.append("")
        lines.append("- Manter WAF/CDN ativo e revisar regras de protecao.")
        lines.append("- Validar se todas as portas identificadas precisam estar publicas.")
        lines.append("- Revisar areas de login, cadastro, pedidos e recuperacao de senha.")
        lines.append("- Aplicar rate limit, monitoramento e alertas nas rotas sensiveis.")
        lines.append("- Revisar headers, scripts publicos e exposicao de tecnologias.")
        lines.append("- Executar nova validacao apos ajustes.")
        lines.append("")
        lines.append("## Top itens para revisao")
        lines.append("")

        if not top:
            lines.append("- Nenhum item prioritario identificado.")
        else:
            for idx, item in enumerate(top[:10], start=1):
                lines.append(
                    f"{idx}. **{item.get('title')}** - "
                    f"{item.get('severity')} - {item.get('review_status')} - Origem {item.get('source_type')}"
                )

        return "\n".join(lines)

    def technical_markdown(self, report: Dict[str, Any]) -> str:
        summary = report.get("summary", {})
        findings = self._sorted_findings(report.get("findings", []))

        lines = []

        lines.append("# Relatorio Tecnico de Seguranca")
        lines.append("")
        lines.append(f"**Alvo:** {report.get('target', '-')}")
        lines.append(f"**Pasta analisada:** `{report.get('target_dir', '-')}`")
        lines.append(f"**Gerado em:** {datetime.now().isoformat(timespec='seconds')}")
        lines.append("")
        lines.append("## Fonte")
        lines.append("")
        lines.append("```text")
        lines.append("block_12_intelligence/block_12_findings.json")
        lines.append("```")
        lines.append("")
        lines.append("## Resumo tecnico")
        lines.append("")
        lines.append(f"- Total de achados: **{summary.get('total_findings', 0)}**")
        lines.append(f"- Achados de risco real: **{summary.get('risk_findings', 0)}**")
        lines.append(f"- Achados de superficie: **{summary.get('surface_findings', 0)}**")
        lines.append(f"- Score de risco real: **{summary.get('risk_score_total', 0)}**")
        lines.append(f"- Score bruto de superficie: **{summary.get('surface_score_total', 0)}**")
        lines.append(f"- Score ajustado de superficie: **{summary.get('surface_adjusted_score', 0)}**")
        lines.append(f"- Score final calibrado: **{summary.get('overall_score', 0)}**")
        lines.append(f"- Nivel geral: **{summary.get('risk_level', 'INFO')}**")
        lines.append("")
        lines.append("## Distribuicao por severidade")
        lines.append("")

        for key, value in summary.get("by_severity", {}).items():
            lines.append(f"- **{key}:** {value}")

        lines.append("")
        lines.append("## Distribuicao por categoria")
        lines.append("")

        for key, value in summary.get("by_category", {}).items():
            lines.append(f"- **{key}:** {value}")

        lines.append("")
        lines.append("## Distribuicao por origem")
        lines.append("")

        for key, value in summary.get("by_source", {}).items():
            lines.append(f"- **{key}:** {value}")

        lines.append("")
        lines.append("## Revisao de falso positivo")
        lines.append("")

        for key, value in summary.get("by_review_status", {}).items():
            lines.append(f"- **{key}:** {value}")

        lines.append("")
        lines.append("## Achados detalhados")
        lines.append("")

        if not findings:
            lines.append("Nenhum achado identificado.")
            return "\n".join(lines)

        for idx, item in enumerate(findings, start=1):
            lines.append(f"### {idx}. {self._safe(item.get('title'))}")
            lines.append("")
            lines.append(f"- **Categoria:** {self._safe(item.get('category'))}")
            lines.append(f"- **Origem:** {self._safe(item.get('source_type'))}")
            lines.append(f"- **Severidade:** {self._safe(item.get('severity'))}")
            lines.append(f"- **Score:** {self._safe(item.get('risk_score'))}")
            lines.append(f"- **Status de revisao:** {self._safe(item.get('review_status'))}")
            lines.append(f"- **Arquivo:** `{self._safe(item.get('file'))}`")
            lines.append(f"- **Evidencia:** `{self._safe(item.get('evidence'))}`")
            lines.append("")
            lines.append("**Impacto:**")
            lines.append("")
            lines.append(self._safe(item.get("impact")))
            lines.append("")
            lines.append("**Remediacao:**")
            lines.append("")
            lines.append(self._safe(item.get("remediation")))
            lines.append("")
            lines.append("**Acao recomendada:**")
            lines.append("")
            lines.append(self._safe(item.get("recommended_action")))
            lines.append("")

        return "\n".join(lines)

    def remediation_markdown(self, report: Dict[str, Any]) -> str:
        summary = report.get("summary", {})
        timeline = self.build_sla_timeline(report).get("timeline", [])

        lines = []

        lines.append("# Plano de Remediacao e SLA")
        lines.append("")
        lines.append(f"**Alvo:** {report.get('target', '-')}")
        lines.append(f"**Gerado em:** {datetime.now().isoformat(timespec='seconds')}")
        lines.append("")
        lines.append("## Visao geral")
        lines.append("")
        lines.append(f"- Achados de risco real: **{summary.get('risk_findings', 0)}**")
        lines.append(f"- Achados de superficie: **{summary.get('surface_findings', 0)}**")
        lines.append(f"- Nivel geral: **{summary.get('risk_level', 'INFO')}**")
        lines.append(f"- Score final calibrado: **{summary.get('overall_score', 0)}**")
        lines.append("")
        lines.append("## Criterio de SLA")
        lines.append("")
        lines.append("| Severidade | Prazo sugerido |")
        lines.append("|---|---|")
        lines.append("| CRITICAL | 24 horas |")
        lines.append("| HIGH | 72 horas |")
        lines.append("| MEDIUM | 7 dias |")
        lines.append("| LOW | 30 dias |")
        lines.append("| INFO | Revisao preventiva |")
        lines.append("")
        lines.append("## Plano priorizado")
        lines.append("")

        if not timeline:
            lines.append("Nenhum item para remediacao nesta etapa.")
            return "\n".join(lines)

        lines.append("| # | Item | Categoria | Severidade | SLA | Acao |")
        lines.append("|---|---|---|---|---|---|")

        for idx, item in enumerate(timeline, start=1):
            title = self._safe(item.get("title")).replace("|", "-")
            category = self._safe(item.get("category")).replace("|", "-")
            severity = self._safe(item.get("severity")).replace("|", "-")
            sla = self._safe(item.get("sla")).replace("|", "-")
            action = self._safe(item.get("recommended_action")).replace("|", "-")

            lines.append(f"| {idx} | {title} | {category} | {severity} | {sla} | {action} |")

        lines.append("")
        lines.append("## Recomendacoes praticas")
        lines.append("")
        lines.append("1. Validar se portas 8080 e 8443 precisam estar expostas.")
        lines.append("2. Revisar regras de WAF/CDN para login, cadastro e recuperacao de senha.")
        lines.append("3. Aplicar rate limit nas areas sensiveis.")
        lines.append("4. Monitorar tentativas repetidas de acesso e falhas de login.")
        lines.append("5. Revisar headers e scripts publicos carregados pelo site.")
        lines.append("6. Executar novo scan apos ajustes.")
        lines.append("")

        return "\n".join(lines)

    def save_text(self, content: str, output_path: str) -> None:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def markdown_to_pdf(self, markdown_text: str, output_path: str, title: str) -> None:
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import cm
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
            from reportlab.lib import colors
        except Exception as exc:
            raise RuntimeError(
                "ReportLab nao esta instalado. Ative a venv e rode: pip install reportlab"
            ) from exc

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        doc = SimpleDocTemplate(
            str(output),
            pagesize=A4,
            rightMargin=1.6 * cm,
            leftMargin=1.6 * cm,
            topMargin=1.6 * cm,
            bottomMargin=1.6 * cm
        )

        styles = getSampleStyleSheet()

        styles.add(ParagraphStyle(
            name="CyberTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=22,
            spaceAfter=14
        ))

        styles.add(ParagraphStyle(
            name="CyberHeading1",
            parent=styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            spaceBefore=12,
            spaceAfter=8
        ))

        styles.add(ParagraphStyle(
            name="CyberHeading2",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=15,
            spaceBefore=10,
            spaceAfter=6
        ))

        styles.add(ParagraphStyle(
            name="CyberBody",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            spaceAfter=5
        ))

        styles.add(ParagraphStyle(
            name="CyberCode",
            parent=styles["BodyText"],
            fontName="Courier",
            fontSize=7,
            leading=9,
            backColor=colors.whitesmoke,
            borderColor=colors.lightgrey,
            borderWidth=0.25,
            borderPadding=4,
            spaceAfter=6
        ))

        story = []
        story.append(Paragraph(title, styles["CyberTitle"]))
        story.append(Spacer(1, 8))

        in_code = False
        code_buffer = []

        def esc(text: str) -> str:
            return (
                text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("**", "")
            )

        def flush_code():
            nonlocal code_buffer
            if code_buffer:
                code_text = "<br/>".join(esc(line) for line in code_buffer)
                story.append(Paragraph(code_text, styles["CyberCode"]))
                code_buffer = []

        for raw_line in markdown_text.splitlines():
            line = raw_line.rstrip()

            if line.startswith("```"):
                if in_code:
                    flush_code()
                    in_code = False
                else:
                    in_code = True
                    code_buffer = []
                continue

            if in_code:
                code_buffer.append(line)
                continue

            if not line.strip():
                story.append(Spacer(1, 5))
                continue

            if line.startswith("# "):
                story.append(Paragraph(esc(line[2:].strip()), styles["CyberTitle"]))
            elif line.startswith("## "):
                story.append(Paragraph(esc(line[3:].strip()), styles["CyberHeading1"]))
            elif line.startswith("### "):
                story.append(Paragraph(esc(line[4:].strip()), styles["CyberHeading2"]))
            elif line.startswith("- "):
                story.append(Paragraph("• " + esc(line[2:].strip()), styles["CyberBody"]))
            elif line.startswith("|"):
                story.append(Paragraph(esc(line), styles["CyberBody"]))
            else:
                story.append(Paragraph(esc(line), styles["CyberBody"]))

        flush_code()
        doc.build(story)

    def write_status(self, report: Dict[str, Any], output_dir: str, outputs: Dict[str, str]) -> Dict[str, Any]:
        status = {
            "block": "13",
            "module": "CyberLab Delivery Enterprise",
            "status": "completed",
            "target": report.get("target"),
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "input": "block_12_intelligence/block_12_findings.json",
            "outputs": outputs,
            "summary": report.get("summary", {})
        }

        path = Path(output_dir) / "block_13_status.json"
        path.write_text(json.dumps(status, ensure_ascii=False, indent=2), encoding="utf-8")
        return status
