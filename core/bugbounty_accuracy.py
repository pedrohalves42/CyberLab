#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CyberLab - Bug Bounty Accuracy Layer

Camada de precisão para reduzir falso positivo, deduplicar achados
e classificar findings em confirmed/candidate/informational/noise.

Este módulo NÃO explora vulnerabilidades.
Ele apenas interpreta evidências já coletadas pelo framework.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Tuple


Finding = Dict[str, Any]


NOISE_TITLES = [
    "endpoint descoberto via ffuf",
    "endpoint descoberto via gobuster",
    "nikto: assinatura informativa/candidata",
    "zap contém seção/alerta: informational",
]

CONFIRMED_KEYWORDS = [
    "exposed secret",
    "api key",
    "token exposed",
    "private key",
    "password",
    "database dump",
    "sql error",
    "stack trace",
    "directory listing",
    "backup file",
    ".env",
    "aws_access_key",
    "google api key",
    "jwt",
]

CANDIDATE_KEYWORDS = [
    "possible",
    "candidate",
    "potential",
    "manual validation",
    "requires manual validation",
    "vulnerable",
    "cve-",
    "admin",
    "login",
    "backup",
    "config",
]

INFO_KEYWORDS = [
    "header",
    "fingerprint",
    "technology",
    "status code",
    "redirect",
    "not wordpress",
    "screenshot",
]


def norm(value: Any) -> str:
    return str(value or "").strip().lower()


def normalize_url(value: str) -> str:
    value = str(value or "").strip()
    value = re.sub(r"#.*$", "", value)
    value = re.sub(r"\?.*$", "", value)
    value = value.rstrip("/")
    return value.lower()


def finding_text(item: Finding) -> str:
    parts = [
        item.get("tool"),
        item.get("title"),
        item.get("category"),
        item.get("severity"),
        item.get("confidence"),
        item.get("url"),
        item.get("endpoint"),
        item.get("target"),
        item.get("description"),
        item.get("evidence"),
    ]
    return " ".join(str(p or "") for p in parts).lower()


def evidence_strength(item: Finding) -> int:
    """
    Score simples de força de evidência.
    0 = sem evidência útil
    100 = evidência forte
    """
    text = finding_text(item)
    score = 0

    if item.get("evidence"):
        score += 20
    if item.get("url") or item.get("endpoint"):
        score += 15
    if item.get("status") or item.get("status_code"):
        score += 10

    if any(k in text for k in CONFIRMED_KEYWORDS):
        score += 35

    if any(k in text for k in CANDIDATE_KEYWORDS):
        score += 15

    if "none" in norm(item.get("evidence")):
        score -= 10

    if len(text) < 80:
        score -= 10

    return max(0, min(100, score))


def classify(item: Finding) -> Tuple[str, int, List[str]]:
    """
    Retorna:
    - accuracy_status: confirmed/candidate/informational/noise
    - confidence_score: 0-100
    - reasons: lista de motivos
    """
    text = finding_text(item)
    title = norm(item.get("title"))
    tool = norm(item.get("tool"))
    severity = norm(item.get("severity"))

    reasons: List[str] = []
    score = evidence_strength(item)

    if any(n in title for n in NOISE_TITLES):
        reasons.append("generic_scanner_output")
        if tool in {"ffuf_controlled", "gobuster_controlled"}:
            return "informational", min(score, 45), reasons
        return "noise", min(score, 30), reasons

    if tool in {"ffuf_controlled", "gobuster_controlled"}:
        status = str(item.get("status") or item.get("status_code") or "")
        if status in {"401", "403"}:
            reasons.append("protected_endpoint_discovered")
            return "candidate", max(score, 55), reasons
        if status.startswith("2"):
            reasons.append("live_endpoint_discovered")
            return "candidate", max(score, 60), reasons
        reasons.append("content_discovery")
        return "informational", max(score, 35), reasons

    if tool == "nikto_safe":
        if any(k in text for k in CONFIRMED_KEYWORDS):
            reasons.append("nikto_strong_keyword")
            return "candidate", max(score, 65), reasons
        reasons.append("nikto_signature_requires_validation")
        return "informational", min(max(score, 40), 55), reasons

    if tool == "zap_baseline":
        if severity in {"high", "critical"} and any(k in text for k in CONFIRMED_KEYWORDS):
            reasons.append("zap_high_with_strong_evidence")
            return "candidate", max(score, 70), reasons
        reasons.append("zap_baseline_alert")
        return "candidate" if severity in {"medium", "high"} else "informational", max(score, 45), reasons

    if tool == "nuclei_controlled":
        if severity in {"high", "critical"}:
            reasons.append("nuclei_high_or_critical_template")
            return "candidate", max(score, 70), reasons
        if severity == "medium":
            reasons.append("nuclei_medium_template")
            return "candidate", max(score, 60), reasons
        reasons.append("nuclei_low_or_info_template")
        return "informational", max(score, 40), reasons

    if any(k in text for k in CONFIRMED_KEYWORDS):
        reasons.append("strong_evidence_keyword")
        if severity in {"high", "critical"}:
            return "confirmed", max(score, 80), reasons
        return "candidate", max(score, 70), reasons

    if severity in {"critical", "high"}:
        reasons.append("high_severity_requires_manual_validation")
        return "candidate", max(score, 60), reasons

    if severity == "medium":
        reasons.append("medium_severity_candidate")
        return "candidate", max(score, 45), reasons

    reasons.append("low_context_or_informational")
    return "informational", max(score, 25), reasons


def dedupe_key(item: Finding) -> str:
    tool = norm(item.get("tool"))
    title = norm(item.get("title"))
    category = norm(item.get("category"))
    url = normalize_url(item.get("url") or item.get("endpoint") or item.get("target") or "")
    status = str(item.get("status") or item.get("status_code") or "")

    raw = "|".join([tool, title, category, url, status])
    return hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()



def bugbounty_priority_score(item: Finding) -> Tuple[int, List[str]]:
    """
    Prioriza achados para validação bug bounty.
    Não confirma vulnerabilidade; apenas ordena por probabilidade de impacto.
    """
    text = finding_text(item)
    tool = norm(item.get("tool"))
    severity = norm(item.get("severity"))
    category = norm(item.get("category"))
    meta = item.get("metadata", {}) or {}

    score = 0
    reasons: List[str] = []

    accuracy = meta.get("accuracy_status")

    if accuracy == "confirmed":
        score += 50
        reasons.append("accuracy_confirmed")
    elif accuracy == "candidate":
        score += 35
        reasons.append("accuracy_candidate")
    elif accuracy == "informational":
        score += 10
        reasons.append("accuracy_informational")
    elif accuracy == "noise":
        score -= 30
        reasons.append("accuracy_noise")

    severity_weight = {
        "critical": 45,
        "high": 35,
        "medium": 20,
        "low": 5,
        "info": 0,
        "informational": 0,
    }

    if severity in severity_weight:
        score += severity_weight[severity]
        reasons.append(f"severity_{severity}")

    tool_weight = {
        "nuclei_controlled": 25,
        "sqlmap_check": 22,
        "zap_baseline": 18,
        "nikto_safe": 14,
        "ffuf_controlled": 12,
        "gobuster_controlled": 10,
        "httpx_fingerprint": 8,
        "katana_crawl_light": 8,
        "wapiti_light": 8,
        "nmap_safe": 7,
        "gowitness_snapshot": 4,
        "wpscan_passive": 4,
        "masscan_webports_controlled": 3,
        "metasploit_check": 3,
    }

    if tool in tool_weight:
        score += tool_weight[tool]
        reasons.append(f"tool_weight_{tool}")

    if item.get("evidence"):
        score += 12
        reasons.append("has_evidence")

    if item.get("url") or item.get("endpoint"):
        score += 10
        reasons.append("has_url_or_endpoint")

    if item.get("status") or item.get("status_code"):
        score += 6
        reasons.append("has_http_status")

    high_value_keywords = [
        ".env", "secret", "token", "api key", "apikey", "private key",
        "credential", "password", "backup", ".bak", ".old", ".sql",
        "config.php", "debug", "stack trace", "sql error", "admin",
        "login", "auth", "jwt", "redirect", "takeover", "cve-",
        "rce", "xss", "ssrf", "idor", "sqli", "upload",
        "arquivo sensível", "configuração exposta",
    ]

    for kw in high_value_keywords:
        if kw in text:
            score += 8
            reasons.append(f"keyword_{kw}")
            break

    if "status 403" in text or "http 403" in text:
        score -= 5
        reasons.append("protected_403_lower_priority")

    if "not wordpress" in text:
        score -= 10
        reasons.append("not_wordpress_context")

    if "screenshot" in category or tool == "gowitness_snapshot":
        score -= 5
        reasons.append("visual_evidence_low_priority")

    if meta.get("duplicate"):
        score -= 50
        reasons.append("duplicate_lower_priority")

    if accuracy == "noise":
        score = min(score, 10)

    score = max(0, min(100, score))
    return score, reasons

def enrich_findings(findings: List[Finding]) -> Dict[str, Any]:
    enriched: List[Finding] = []
    seen = {}

    duplicate_count = 0

    for item in findings:
        item = dict(item)
        key = dedupe_key(item)

        accuracy_status, confidence_score, reasons = classify(item)

        item.setdefault("metadata", {})
        item["metadata"]["accuracy_status"] = accuracy_status
        item["metadata"]["confidence_score"] = confidence_score
        item["metadata"]["accuracy_reasons"] = reasons
        item["metadata"]["dedupe_key"] = key


        priority_score, priority_reasons = bugbounty_priority_score(item)
        item["metadata"]["bugbounty_priority_score"] = priority_score
        item["metadata"]["bugbounty_priority_reasons"] = priority_reasons

        if key in seen:
            duplicate_count += 1
            item["metadata"]["duplicate"] = True
            item["metadata"]["duplicate_of"] = seen[key]
        else:
            seen[key] = len(enriched)
            item["metadata"]["duplicate"] = False
            enriched.append(item)

    buckets = Counter(i["metadata"]["accuracy_status"] for i in enriched)
    tools = Counter(i.get("tool") for i in enriched)
    severities = Counter(i.get("severity") for i in enriched)

    priority = [
        i for i in enriched
        if i["metadata"]["accuracy_status"] in {"confirmed", "candidate"}
    ]

    priority.sort(
        key=lambda x: (
            {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(str(x.get("severity", "")).upper(), 0),
            x["metadata"].get("confidence_score", 0),
        ),
        reverse=True,
    )

    return {
        "schema": "cyberlab.bugbounty_accuracy.v1",
        "ok": True,
        "raw_count": len(findings),
        "deduped_count": len(enriched),
        "duplicate_count": duplicate_count,
        "accuracy_counts": dict(buckets),
        "tool_counts": dict(tools),
        "severity_counts": dict(severities),
        "findings": enriched,
        "priority": priority[:50],
    }


def load_findings(path: Path) -> List[Finding]:
    data = json.loads(path.read_text(encoding="utf-8"))

    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        for key in ("findings", "items", "results"):
            if isinstance(data.get(key), list):
                return data[key]

    return []


def write_markdown(report: Dict[str, Any], path: Path) -> None:
    lines: List[str] = []

    lines.append("# CyberLab — Bug Bounty Accuracy Report")
    lines.append("")
    lines.append("## Resumo")
    lines.append("")
    lines.append(f"- Achados brutos: **{report.get('raw_count')}**")
    lines.append(f"- Achados deduplicados: **{report.get('deduped_count')}**")
    lines.append(f"- Duplicados removidos: **{report.get('duplicate_count')}**")
    lines.append("")

    lines.append("## Classificação por precisão")
    lines.append("")
    for k, v in sorted(report.get("accuracy_counts", {}).items()):
        lines.append(f"- **{k}:** {v}")
    lines.append("")

    lines.append("## Severidade")
    lines.append("")
    for k, v in sorted(report.get("severity_counts", {}).items()):
        lines.append(f"- **{k}:** {v}")
    lines.append("")

    lines.append("## Ferramentas")
    lines.append("")
    for k, v in sorted(report.get("tool_counts", {}).items()):
        lines.append(f"- **{k}:** {v}")
    lines.append("")

    lines.append("## Top prioridades para validação manual")
    lines.append("")
    for item in report.get("priority", [])[:30]:
        meta = item.get("metadata", {})
        lines.append(
            f"- **{item.get('severity')}** | `{item.get('tool')}` | "
            f"{item.get('title')} | "
            f"accuracy=`{meta.get('accuracy_status')}` | "
            f"score=`{meta.get('confidence_score')}`"
        )
    lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--scan-dir", required=True)
    args = parser.parse_args()

    scan_dir = Path(args.scan_dir)
    out_dir = scan_dir / "11-tool-orchestrator" / "tool_output_intelligence"
    findings_path = out_dir / "tool-findings.json"

    if not findings_path.exists():
        raise SystemExit(f"[ERRO] tool-findings.json não encontrado: {findings_path}")

    findings = load_findings(findings_path)
    report = enrich_findings(findings)

    accuracy_json = out_dir / "bugbounty-accuracy.json"
    accuracy_md = out_dir / "bugbounty-accuracy-summary.md"

    accuracy_json.write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )

    write_markdown(report, accuracy_md)

    print("============================================================")
    print("CYBERLAB — BUG BOUNTY ACCURACY FINALIZADO")
    print("============================================================")
    print(f"[OK] Scan dir:       {scan_dir}")
    print(f"[OK] Output JSON:    {accuracy_json}")
    print(f"[OK] Output MD:      {accuracy_md}")
    print(f"[OK] Raw findings:   {report.get('raw_count')}")
    print(f"[OK] Deduped:        {report.get('deduped_count')}")
    print(f"[OK] Duplicates:     {report.get('duplicate_count')}")
    print(f"[OK] Accuracy:       {report.get('accuracy_counts')}")
    print("[OK] Status:         True")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
