#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, PageBreak
except Exception as exc:
    raise SystemExit(
        "[ERRO] ReportLab não disponível. Ative a venv e rode: pip install reportlab\n"
        f"Detalhe: {exc}"
    )

HOME = Path.home()
CYBERLAB = HOME / "CyberLab"
CONTEXT_FILE = CYBERLAB / "state/audit/current_audit_context.json"


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def resolve_scan_dir(argv: list[str], context: dict[str, Any]) -> Path:
    if len(argv) > 1 and argv[1].strip():
        return Path(argv[1]).expanduser().resolve()

    candidates = [
        context.get("scan_dir"),
        context.get("paths", {}).get("scan_dir"),
        context.get("paths", {}).get("official_scan_dir"),
    ]

    for candidate in candidates:
        if candidate:
            return Path(candidate).expanduser().resolve()

    raise SystemExit("[ERRO] Não foi possível localizar o scan oficial pelo contexto atual.")


def artifact(path: Path, kind: str = "file") -> dict[str, Any]:
    return {
        "path": str(path),
        "kind": kind,
        "exists": path.exists(),
        "registered_at": now_iso(),
    }


def markdown_to_pdf(md_path: Path, pdf_path: Path, report_title: str, client: str, target: str) -> None:
    text = md_path.read_text(encoding="utf-8", errors="ignore")
    lines = text.splitlines()

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=18,
        leading=24,
        spaceAfter=16,
    )

    subtitle_style = ParagraphStyle(
        "CustomSubtitle",
        parent=styles["Normal"],
        alignment=TA_CENTER,
        fontSize=10,
        leading=14,
        spaceAfter=18,
    )

    h1 = ParagraphStyle(
        "H1",
        parent=styles["Heading1"],
        fontSize=15,
        leading=19,
        spaceBefore=12,
        spaceAfter=8,
    )

    h2 = ParagraphStyle(
        "H2",
        parent=styles["Heading2"],
        fontSize=13,
        leading=17,
        spaceBefore=10,
        spaceAfter=6,
    )

    h3 = ParagraphStyle(
        "H3",
        parent=styles["Heading3"],
        fontSize=11,
        leading=15,
        spaceBefore=8,
        spaceAfter=5,
    )

    body = ParagraphStyle(
        "Body",
        parent=styles["BodyText"],
        alignment=TA_LEFT,
        fontSize=9.5,
        leading=13,
        spaceAfter=6,
    )

    bullet = ParagraphStyle(
        "Bullet",
        parent=body,
        leftIndent=14,
        firstLineIndent=-8,
        bulletIndent=4,
        spaceAfter=4,
    )

    small = ParagraphStyle(
        "Small",
        parent=body,
        fontSize=8,
        leading=11,
    )

    story = [
        Paragraph(report_title, title_style),
        Paragraph(f"Cliente: {client}<br/>Alvo analisado: {target}", subtitle_style),
        Spacer(1, 0.25 * cm),
    ]

    in_code = False
    code_buffer: list[str] = []

    def flush_code() -> None:
        nonlocal code_buffer
        if not code_buffer:
            return
        safe = "<br/>".join(
            line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            for line in code_buffer
        )
        story.append(Paragraph(f"<font name='Courier'>{safe}</font>", small))
        story.append(Spacer(1, 0.15 * cm))
        code_buffer = []

    for raw in lines:
        line = raw.strip()

        if line.startswith("```"):
            if in_code:
                flush_code()
                in_code = False
            else:
                in_code = True
            continue

        if in_code:
            code_buffer.append(raw)
            continue

        if not line:
            story.append(Spacer(1, 0.08 * cm))
            continue

        escaped = (
            line.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )

        escaped = re.sub(r"\*\*(.*?)\*\*", r"<b>\1</b>", escaped)
        escaped = re.sub(r"`([^`]+)`", r"<font name='Courier'>\1</font>", escaped)

        if line.startswith("# "):
            story.append(Paragraph(escaped[2:], h1))
        elif line.startswith("## "):
            story.append(Paragraph(escaped[3:], h2))
        elif line.startswith("### "):
            story.append(Paragraph(escaped[4:], h3))
        elif re.match(r"^[-*]\s+", line):
            content = re.sub(r"^[-*]\s+", "", escaped)
            story.append(Paragraph(content, bullet, bulletText="•"))
        elif re.match(r"^\d+\.\s+", line):
            story.append(Paragraph(escaped, bullet, bulletText="•"))
        elif line == "---":
            story.append(Spacer(1, 0.2 * cm))
        else:
            story.append(Paragraph(escaped, body))

    flush_code()

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.drawString(2 * cm, 1.2 * cm, "CyberLab — Relatório de Auditoria")
        canvas.drawRightString(19 * cm, 1.2 * cm, f"Página {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=A4,
        rightMargin=1.8 * cm,
        leftMargin=1.8 * cm,
        topMargin=1.8 * cm,
        bottomMargin=1.8 * cm,
        title=report_title,
        author="CyberLab",
    )

    doc.build(story, onFirstPage=footer, onLaterPages=footer)


def main(argv: list[str]) -> int:
    if not CONTEXT_FILE.exists():
        raise SystemExit(f"[ERRO] Contexto oficial não encontrado: {CONTEXT_FILE}")

    context = read_json(CONTEXT_FILE)
    scan_dir = resolve_scan_dir(argv, context)

    if not scan_dir.exists():
        raise SystemExit(f"[ERRO] Pasta do scan não existe: {scan_dir}")

    out = scan_dir / "block_17_client_final_delivery"
    out.mkdir(parents=True, exist_ok=True)

    client = str(context.get("client_name") or context.get("client") or "Cliente")
    target = str(context.get("target") or "Alvo não informado")

    source_map = {
        "executive": (
            out / "client_final_executive_report_polished.md",
            out / "client_final_executive_report.md",
            out / "client_final_executive_report.pdf",
            "Relatório Executivo Final",
        ),
        "technical": (
            out / "client_final_technical_report_polished.md",
            out / "client_final_technical_report.md",
            out / "client_final_technical_report.pdf",
            "Relatório Técnico Final",
        ),
        "remediation": (
            out / "client_final_remediation_plan_polished.md",
            out / "client_final_remediation_plan.md",
            out / "client_final_remediation_plan.pdf",
            "Plano Final de Correção e Priorização",
        ),
    }

    sources: dict[str, str] = {}
    outputs: dict[str, str] = {}

    for key, (preferred, fallback, pdf, title) in source_map.items():
        src = preferred if preferred.exists() else fallback
        if not src.exists():
            raise SystemExit(
                f"[ERRO] Fonte Markdown não encontrada para {key}: "
                f"{preferred} ou {fallback}"
            )

        markdown_to_pdf(src, pdf, title, client, target)
        sources[key] = str(src)
        outputs[key] = str(pdf)

    status_path = out / "block_17_4d_status.json"
    summary_path = out / "block_17_4d_summary.md"

    status = {
        "block": "17",
        "layer": "4D",
        "module": "Final Client PDF Publisher",
        "status": "OK",
        "client": client,
        "target": target,
        "scan_dir": str(scan_dir),
        "generated_at": now_iso(),
        "sources": sources,
        "outputs": outputs,
    }

    summary = f"""# CyberLab — Camada 4D

## Publicação dos PDFs finais do cliente

- **Cliente:** {client}
- **Alvo:** {target}
- **Scan oficial:** `{scan_dir}`
- **Gerado em:** {status["generated_at"]}

## PDFs finais gerados

- **Executivo:** `{outputs["executive"]}`
- **Técnico:** `{outputs["technical"]}`
- **Plano de correção:** `{outputs["remediation"]}`

## Critério

Esta camada renderiza em PDF os relatórios finais já consolidados, calibrados, traduzidos e polidos pelas camadas anteriores do Bloco 17.
"""

    write_json(status_path, status)
    summary_path.write_text(summary, encoding="utf-8")

    stages = context.setdefault("stages", {})
    stages["block17_4d_final_pdf_publisher"] = {
        "status": "OK",
        "message": "PDFs finais do cliente gerados.",
        "updated_at": now_iso(),
        "scan_dir": str(scan_dir),
        "status_json": str(status_path),
        "summary_md": str(summary_path),
    }

    artifacts = context.setdefault("artifacts", {})
    artifacts["block17_4d_executive_pdf"] = artifact(Path(outputs["executive"]))
    artifacts["block17_4d_technical_pdf"] = artifact(Path(outputs["technical"]))
    artifacts["block17_4d_remediation_pdf"] = artifact(Path(outputs["remediation"]))
    artifacts["block17_4d_status_json"] = artifact(status_path)
    artifacts["block17_4d_summary_md"] = artifact(summary_path)

    write_json(CONTEXT_FILE, context)

    print("============================================================")
    print(" CyberLab — Camada 4D")
    print(" Publicação de PDFs finais do cliente")
    print("============================================================")
    print(f"[OK] Cliente: {client}")
    print(f"[OK] Alvo: {target}")
    print(f"[OK] Scan oficial: {scan_dir}")
    print("")
    print("[PDFs GERADOS]")
    print(f" - {outputs['executive']}")
    print(f" - {outputs['technical']}")
    print(f" - {outputs['remediation']}")
    print("")
    print(f"[OK] Status: {status_path}")
    print(f"[OK] Resumo: {summary_path}")
    print("[OK] Camada 4D finalizada.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
