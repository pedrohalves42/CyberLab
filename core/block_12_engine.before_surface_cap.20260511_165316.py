#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CyberLab - Block 12 Intelligence Engine

Camadas:
- 12A Findings Intelligence
- 12B Risk Scoring
- 12C False Positive Review
- 12D Surface Intelligence

Este módulo analisa somente arquivos locais já gerados pelo framework.
Não realiza exploração ativa.
"""

import os
import re
import json
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional


SEVERITY_WEIGHT = {
    "INFO": 1,
    "LOW": 2,
    "MEDIUM": 4,
    "HIGH": 7,
    "CRITICAL": 10
}


SURFACE_CATEGORIES = {
    "SURFACE_WAF",
    "SURFACE_HTTP",
    "SURFACE_PORT",
    "SURFACE_AUTH",
    "SURFACE_SCRIPT",
    "SURFACE_TECH",
    "SURFACE_HEADER",
    "SURFACE_TOKEN",
    "SURFACE_API",
    "SURFACE_CDN"
}


class Block12Engine:
    def __init__(self, rules_path: str):
        self.rules_path = Path(rules_path)
        self.rules = self._load_rules()

    def _load_rules(self) -> List[Dict[str, Any]]:
        if not self.rules_path.exists():
            raise FileNotFoundError(f"Arquivo de regras não encontrado: {self.rules_path}")

        data = json.loads(self.rules_path.read_text(encoding="utf-8"))
        return data.get("rules", [])

    def _iter_result_files(self, target_dir: str) -> List[Path]:
        allowed_extensions = {
            ".txt", ".log", ".json", ".md", ".csv", ".html", ".xml",
            ".yaml", ".yml", ".out", ".report"
        }

        ignored_dirs = {
            "block_12_intelligence",
            "block_12a_findings_intel",
            "__pycache__",
            ".git",
            ".venv",
            "venv"
        }

        base = Path(target_dir)

        if not base.exists():
            raise FileNotFoundError(f"Pasta de resultados não encontrada: {target_dir}")

        files = []

        for root, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames if d not in ignored_dirs]

            for name in filenames:
                file_path = Path(root) / name

                if file_path.suffix.lower() in allowed_extensions:
                    files.append(file_path)

        return files

    def _read_file(self, file_path: Path) -> str:
        try:
            return file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return ""

    def _source_type(self, file_path: Path) -> str:
        path = str(file_path).lower()

        if "httpx" in path or "02-alive" in path:
            return "HTTPX"

        if "naabu" in path or "03-ports" in path:
            return "NAABU"

        if "wafw00f" in path or "waf" in path:
            return "WAFW00F"

        if "whatweb" in path:
            return "WHATWEB"

        if "headers" in path or "06-headers" in path:
            return "HEADERS"

        if "urls" in path or "crawl" in path:
            return "CRAWL"

        if "dns" in path or "whois" in path:
            return "DNS"

        return "GENERIC"

    def _mask_sensitive(self, value: str) -> str:
        value = value.strip()

        if len(value) <= 12:
            return value[:3] + "***"

        return value[:8] + "***" + value[-4:]

    def _safe_evidence(self, evidence: str, category: str) -> str:
        evidence = evidence.strip()

        if category.upper() in {"SECRET", "JWT"}:
            return self._mask_sensitive(evidence)

        if len(evidence) > 280:
            return evidence[:280] + "..."

        return evidence

    def _normalize_evidence_for_fp(self, finding: Dict[str, Any]) -> str:
        category = finding.get("category", "")
        evidence = finding.get("evidence", "").strip()

        if category == "SURFACE_PORT":
            match = re.search(r":([0-9]{2,5})$", evidence)
            if match:
                return f"port:{match.group(1)}"

        if category == "SURFACE_AUTH":
            path = re.sub(r"^https?://[^/]+", "", evidence)
            return path.rstrip("/")

        if category in {"SURFACE_WAF", "SURFACE_HEADER", "SURFACE_TECH"}:
            return evidence.lower()

        return evidence

    def _fingerprint(self, finding: Dict[str, Any]) -> str:
        normalized_evidence = self._normalize_evidence_for_fp(finding)

        raw = "|".join([
            finding.get("rule_id", ""),
            finding.get("category", ""),
            finding.get("title", ""),
            normalized_evidence
        ])

        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def _calculate_risk_score(self, finding: Dict[str, Any]) -> int:
        severity = finding.get("severity", "INFO").upper()
        confidence = int(finding.get("confidence", 50))
        exposure = int(finding.get("exposure", 50))
        impact_weight = int(finding.get("impact_weight", 3))
        category = finding.get("category", "UNKNOWN").upper()

        severity_score = SEVERITY_WEIGHT.get(severity, 1) * 8
        confidence_score = confidence * 0.20
        exposure_score = exposure * 0.20
        impact_score = impact_weight * 3

        score = int(severity_score + confidence_score + exposure_score + impact_score)

        # 12D Surface Intelligence não deve inflar risco como vulnerabilidade real.
        if category in SURFACE_CATEGORIES:
            if severity == "INFO":
                score = min(score, 25)
            elif severity == "LOW":
                score = min(score, 45)
            elif severity == "MEDIUM":
                score = min(score, 60)

        if score > 100:
            return 100

        if score < 1:
            return 1

        return score

    def _false_positive_review(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        confidence = int(finding.get("confidence", 50))
        severity = finding.get("severity", "INFO").upper()
        category = finding.get("category", "UNKNOWN").upper()
        evidence = finding.get("evidence", "").lower()
        fp_weight = int(finding.get("false_positive_weight", 50))

        # Achados de superfície são inventário/revisão, não confirmação de falha.
        if category in SURFACE_CATEGORIES:
            if category == "SURFACE_PORT":
                return {
                    "false_positive_score": 65,
                    "review_status": "REVISAR_MANUALMENTE",
                    "recommended_action": "Validar se a porta identificada deve estar exposta publicamente."
                }

            if category == "SURFACE_AUTH":
                return {
                    "false_positive_score": 70,
                    "review_status": "REVISAR_MANUALMENTE",
                    "recommended_action": "Revisar controles de autenticação, rate limit e proteção contra abuso."
                }

            return {
                "false_positive_score": 80,
                "review_status": "INFORMATIVO",
                "recommended_action": "Registrar como informação de superfície para contexto do relatório."
            }

        fp_score = fp_weight

        strong_indicators = [
            ".env",
            ".git/config",
            "wp-config",
            "api_key",
            "secret",
            "bearer",
            "php version",
            "index of /",
            "server-status",
            "aws_secret_access_key"
        ]

        weak_indicators = [
            "/api/",
            "/v1/",
            "/v2/",
            "/login",
            "/admin",
            "missing",
            "ausente"
        ]

        if any(x in evidence for x in strong_indicators):
            fp_score -= 25

        if any(x in evidence for x in weak_indicators):
            fp_score += 10

        if confidence >= 80:
            fp_score -= 15

        if confidence < 65:
            fp_score += 15

        if severity in {"HIGH", "CRITICAL"}:
            fp_score -= 10

        if category in {"HEADER", "API", "PORT"}:
            fp_score += 8

        fp_score = max(0, min(100, fp_score))

        if fp_score <= 25:
            status = "CONFIRMADO_PROVAVEL"
            action = "Priorizar validação e correção."
        elif fp_score <= 50:
            status = "SUSPEITO_FORTE"
            action = "Revisar evidência e confirmar impacto."
        elif fp_score <= 75:
            status = "REVISAR_MANUALMENTE"
            action = "Pode depender do contexto do ambiente."
        else:
            status = "POSSIVEL_FALSO_POSITIVO"
            action = "Baixa confiança; revisar antes de reportar como risco real."

        return {
            "false_positive_score": fp_score,
            "review_status": status,
            "recommended_action": action
        }

    def _deduplicate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        unique = []

        for finding in findings:
            fp = finding.get("fingerprint")

            if fp not in seen:
                unique.append(finding)
                seen.add(fp)

        unique.sort(
            key=lambda item: (
                item.get("risk_score", 0),
                SEVERITY_WEIGHT.get(item.get("severity", "INFO").upper(), 0),
                item.get("confidence", 0)
            ),
            reverse=True
        )

        return unique

    def _summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        by_severity = {}
        by_category = {}
        by_review_status = {}
        by_source = {}

        risk_score_total = 0
        surface_score_total = 0

        surface_count = 0
        risk_count = 0

        for item in findings:
            severity = item.get("severity", "INFO").upper()
            category = item.get("category", "UNKNOWN").upper()
            review_status = item.get("review_status", "UNKNOWN")
            source_type = item.get("source_type", "GENERIC")
            item_score = int(item.get("risk_score", 0))

            by_severity[severity] = by_severity.get(severity, 0) + 1
            by_category[category] = by_category.get(category, 0) + 1
            by_review_status[review_status] = by_review_status.get(review_status, 0) + 1
            by_source[source_type] = by_source.get(source_type, 0) + 1

            if category in SURFACE_CATEGORIES:
                surface_count += 1
                surface_score_total += item_score
            else:
                risk_count += 1
                risk_score_total += item_score

        # Score calibrado:
        # - risco real pesa 100%
        # - superfície pesa 20%, com teto de 120
        surface_adjusted_score = min(int(surface_score_total * 0.20), 120)
        overall_score = risk_score_total + surface_adjusted_score

        if risk_count == 0 and surface_count > 0:
            if surface_count >= 20:
                risk_level = "MEDIUM"
            elif surface_count >= 5:
                risk_level = "LOW"
            else:
                risk_level = "INFO"
        else:
            if overall_score >= 300:
                risk_level = "CRITICAL"
            elif overall_score >= 180:
                risk_level = "HIGH"
            elif overall_score >= 90:
                risk_level = "MEDIUM"
            elif overall_score > 0:
                risk_level = "LOW"
            else:
                risk_level = "INFO"

        top_priorities = findings[:10]

        return {
            "total_findings": len(findings),
            "risk_findings": risk_count,
            "surface_findings": surface_count,
            "risk_score_total": risk_score_total,
            "surface_score_total": surface_score_total,
            "surface_adjusted_score": surface_adjusted_score,
            "overall_score": overall_score,
            "risk_level": risk_level,
            "by_severity": by_severity,
            "by_category": by_category,
            "by_review_status": by_review_status,
            "by_source": by_source,
            "top_priorities": [
                {
                    "title": item.get("title"),
                    "severity": item.get("severity"),
                    "category": item.get("category"),
                    "risk_score": item.get("risk_score"),
                    "review_status": item.get("review_status"),
                    "source_type": item.get("source_type")
                }
                for item in top_priorities
            ]
        }

    def analyze(self, target_dir: str, target_name: Optional[str] = None) -> Dict[str, Any]:
        files = self._iter_result_files(target_dir)
        findings = []

        for file_path in files:
            content = self._read_file(file_path)

            if not content:
                continue

            source_type = self._source_type(file_path)

            for rule in self.rules:
                category = rule.get("category", "UNKNOWN")
                patterns = rule.get("patterns", [])

                for pattern in patterns:
                    try:
                        matches = re.finditer(
                            pattern,
                            content,
                            flags=re.IGNORECASE | re.MULTILINE
                        )
                    except re.error:
                        continue

                    for match in matches:
                        raw_evidence = match.group(0)

                        finding = {
                            "rule_id": rule.get("id"),
                            "category": category,
                            "title": rule.get("title"),
                            "severity": rule.get("severity", "INFO"),
                            "confidence": int(rule.get("confidence", 50)),
                            "exposure": int(rule.get("exposure", 50)),
                            "impact_weight": int(rule.get("impact_weight", 3)),
                            "false_positive_weight": int(rule.get("false_positive_weight", 50)),
                            "source_type": source_type,
                            "file": str(file_path),
                            "evidence": self._safe_evidence(raw_evidence, category),
                            "impact": rule.get("impact", ""),
                            "remediation": rule.get("remediation", ""),
                            "detected_at": datetime.now().isoformat(timespec="seconds")
                        }

                        finding["risk_score"] = self._calculate_risk_score(finding)
                        finding.update(self._false_positive_review(finding))
                        finding["fingerprint"] = self._fingerprint(finding)

                        findings.append(finding)

        findings = self._deduplicate(findings)

        return {
            "module": "CyberLab Intelligence Engine",
            "block": "12",
            "includes": [
                "12A Findings Intelligence",
                "12B Risk Scoring",
                "12C False Positive Review",
                "12D Surface Intelligence"
            ],
            "target": target_name or Path(target_dir).name,
            "target_dir": str(target_dir),
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "summary": self._summary(findings),
            "findings": findings
        }

    def save_json(self, report: Dict[str, Any], output_path: str) -> None:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(report, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )

    def save_markdown(self, report: Dict[str, Any], output_path: str) -> None:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(self.to_markdown(report), encoding="utf-8")

    def to_markdown(self, report: Dict[str, Any]) -> str:
        summary = report.get("summary", {})
        findings = report.get("findings", [])

        lines = []

        lines.append("# CyberLab - Bloco 12 Intelligence Engine")
        lines.append("")
        lines.append(f"**Alvo:** {report.get('target', '-')}")
        lines.append(f"**Pasta analisada:** `{report.get('target_dir', '-')}`")
        lines.append(f"**Gerado em:** {report.get('generated_at', '-')}")
        lines.append("")
        lines.append("## Módulos incluídos")
        lines.append("")
        lines.append("- 12A Findings Intelligence")
        lines.append("- 12B Risk Scoring")
        lines.append("- 12C False Positive Review")
        lines.append("- 12D Surface Intelligence")
        lines.append("")
        lines.append("## Resumo geral")
        lines.append("")
        lines.append(f"- Total de achados: **{summary.get('total_findings', 0)}**")
        lines.append(f"- Achados de risco real: **{summary.get('risk_findings', 0)}**")
        lines.append(f"- Achados de superfície: **{summary.get('surface_findings', 0)}**")
        lines.append(f"- Score de risco real: **{summary.get('risk_score_total', 0)}**")
        lines.append(f"- Score bruto de superfície: **{summary.get('surface_score_total', 0)}**")
        lines.append(f"- Score ajustado de superfície: **{summary.get('surface_adjusted_score', 0)}**")
        lines.append(f"- Score final calibrado: **{summary.get('overall_score', 0)}**")
        lines.append(f"- Nível geral: **{summary.get('risk_level', 'INFO')}**")
        lines.append("")

        lines.append("### Achados por severidade")
        lines.append("")
        for key, value in summary.get("by_severity", {}).items():
            lines.append(f"- **{key}:** {value}")

        lines.append("")
        lines.append("### Achados por categoria")
        lines.append("")
        for key, value in summary.get("by_category", {}).items():
            lines.append(f"- **{key}:** {value}")

        lines.append("")
        lines.append("### Achados por origem")
        lines.append("")
        for key, value in summary.get("by_source", {}).items():
            lines.append(f"- **{key}:** {value}")

        lines.append("")
        lines.append("### Revisão de falso positivo")
        lines.append("")
        for key, value in summary.get("by_review_status", {}).items():
            lines.append(f"- **{key}:** {value}")

        lines.append("")
        lines.append("## Top prioridades")
        lines.append("")

        for idx, item in enumerate(summary.get("top_priorities", []), start=1):
            lines.append(
                f"{idx}. **{item.get('title')}** — "
                f"{item.get('severity')} / Score {item.get('risk_score')} / "
                f"{item.get('review_status')} / Origem {item.get('source_type')}"
            )

        lines.append("")
        lines.append("## Achados detalhados")
        lines.append("")

        if not findings:
            lines.append("Nenhum achado identificado pelo Bloco 12.")
            return "\n".join(lines)

        for idx, item in enumerate(findings, start=1):
            lines.append(f"### {idx}. {item.get('title')}")
            lines.append("")
            lines.append(f"- **Categoria:** {item.get('category')}")
            lines.append(f"- **Origem:** {item.get('source_type')}")
            lines.append(f"- **Severidade:** {item.get('severity')}")
            lines.append(f"- **Confiança:** {item.get('confidence')}%")
            lines.append(f"- **Exposição:** {item.get('exposure')}%")
            lines.append(f"- **Score de risco:** {item.get('risk_score')}")
            lines.append(f"- **Status revisão:** {item.get('review_status')}")
            lines.append(f"- **Score falso positivo:** {item.get('false_positive_score')}")
            lines.append(f"- **Arquivo:** `{item.get('file')}`")
            lines.append(f"- **Evidência:** `{item.get('evidence')}`")
            lines.append("")
            lines.append("**Impacto:**")
            lines.append("")
            lines.append(item.get("impact", "-"))
            lines.append("")
            lines.append("**Correção recomendada:**")
            lines.append("")
            lines.append(item.get("remediation", "-"))
            lines.append("")
            lines.append("**Ação recomendada:**")
            lines.append("")
            lines.append(item.get("recommended_action", "-"))
            lines.append("")

        return "\n".join(lines)
