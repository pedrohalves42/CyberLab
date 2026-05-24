#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CyberLab — Tool Output Parser

Lê os artefatos gerados pelo Tool Orchestrator e consolida:
- achados técnicos estruturados;
- índice de evidências;
- status por ferramenta;
- resumo Markdown operacional.

Entrada esperada:
  <scan_dir>/11-tool-orchestrator/

Saída:
  <scan_dir>/11-tool-orchestrator/tool_output_intelligence/
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


TOOL_DIRNAME = "11-tool-orchestrator"
OUT_DIRNAME = "tool_output_intelligence"


INTERESTING_STATUS = {200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 405}
NOISE_STATUS = {404, 400, 429}


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def read_text(path: Path, limit: int = 2_000_000) -> str:
    try:
        if not path.exists() or not path.is_file():
            return ""
        data = path.read_text(encoding="utf-8", errors="ignore")
        if len(data) > limit:
            return data[:limit] + "\n[TRUNCATED]\n"
        return data
    except Exception:
        return ""


def read_json(path: Path) -> Any:
    try:
        if not path.exists() or not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None



def detect_executed_tools_from_evidence(evidence_items):
    """
    Conta ferramentas que executaram e geraram artefatos,
    mesmo quando não produziram achados estruturados.
    """
    tools = {}
    for ev in evidence_items or []:
        tool = ev.get("tool")
        if not tool:
            continue
        tools.setdefault(tool, 0)
    return tools

def write_json(path: Path, data: Any) -> None:
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def safe_rel(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except Exception:
        return str(path)


def ensure_scan_dir(scan_dir: Path) -> Path:
    if not scan_dir.exists():
        raise SystemExit(f"[ERRO] scan_dir não existe: {scan_dir}")

    tools_dir = scan_dir / TOOL_DIRNAME
    if not tools_dir.exists():
        raise SystemExit(f"[ERRO] diretório do orchestrator não existe: {tools_dir}")

    return tools_dir


def finding(
    *,
    tool: str,
    title: str,
    severity: str = "INFO",
    category: str = "tool-output",
    description: str = "",
    evidence: Optional[str] = None,
    source_file: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "tool": tool,
        "title": title,
        "severity": severity,
        "category": category,
        "description": description,
        "evidence": evidence,
        "source_file": source_file,
        "metadata": metadata or {},
    }


def evidence_item(
    *,
    tool: str,
    kind: str,
    path: Path,
    base: Path,
    description: str = "",
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "tool": tool,
        "kind": kind,
        "path": str(path),
        "relative_path": safe_rel(path, base),
        "exists": path.exists(),
        "size": path.stat().st_size if path.exists() and path.is_file() else 0,
        "description": description,
        "metadata": metadata or {},
    }


def parse_tool_summary_json(scan_dir: Path, tools_dir: Path) -> Dict[str, Any]:
    candidates = [
        tools_dir / "tool_run_summary.json",
    ]

    audit_root = Path.home() / "CyberLab" / "state" / "audit"
    if audit_root.exists():
        for p in audit_root.rglob("tool_run_summary.json"):
            txt = read_text(p, limit=200_000)
            if str(scan_dir) in txt:
                candidates.append(p)

    for p in candidates:
        data = read_json(p)
        if isinstance(data, dict):
            return data

    return {
        "target": scan_dir.parent.name if scan_dir.parent else "",
        "scan_dir": str(scan_dir),
        "results": [],
        "summary": {},
    }


def parse_nmap(tool_dir: Path, base: Path) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    text = "\n".join(read_text(p) for p in tool_dir.rglob("*") if p.is_file())
    if not text.strip():
        return findings

    port_re = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+([^\s]+)(?:\s+(.*))?$", re.I | re.M)

    for match in port_re.finditer(text):
        port, proto, service, detail = match.groups()
        findings.append(finding(
            tool="nmap_safe",
            title=f"Porta aberta detectada: {port}/{proto}",
            severity="INFO",
            category="network-service",
            description=f"Serviço detectado: {service}.",
            evidence=match.group(0),
            source_file=str(tool_dir),
            metadata={
                "port": int(port),
                "protocol": proto,
                "service": service,
                "detail": detail or "",
            },
        ))

    return findings


def parse_ffuf_json(path: Path) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    data = read_json(path)

    results = []
    if isinstance(data, dict):
        results = data.get("results") or []
    elif isinstance(data, list):
        results = data

    for item in results:
        if not isinstance(item, dict):
            continue

        status = item.get("status")
        url = item.get("url") or item.get("input", {}).get("FUZZ")
        length = item.get("length")
        words = item.get("words")
        lines = item.get("lines")

        try:
            status_int = int(status)
        except Exception:
            status_int = 0

        if status_int in NOISE_STATUS:
            continue

        sev = "LOW"
        if status_int in {401, 403}:
            sev = "MEDIUM"
        elif status_int in {200, 301, 302}:
            sev = "LOW"

        findings.append(finding(
            tool="ffuf_controlled",
            title=f"Endpoint descoberto via FFUF: HTTP {status_int}",
            severity=sev,
            category="web-discovery",
            description="Caminho ou endpoint retornou status potencialmente relevante.",
            evidence=str(url),
            source_file=str(path),
            metadata={
                "status": status_int,
                "url": url,
                "length": length,
                "words": words,
                "lines": lines,
            },
        ))

    return findings


def parse_gobuster_text(path: Path) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    text = read_text(path)

    pattern = re.compile(
        r"(?P<path>/[^\s]+)\s+\(Status:\s*(?P<status>\d+)\)(?:\s+\[Size:\s*(?P<size>\d+)\])?",
        re.I,
    )

    for m in pattern.finditer(text):
        path_value = m.group("path")
        status = int(m.group("status"))
        size = m.group("size")

        if status in NOISE_STATUS:
            continue

        sev = "LOW"
        if status in {401, 403}:
            sev = "MEDIUM"

        findings.append(finding(
            tool="gobuster_controlled",
            title=f"Diretório/rota descoberta: {path_value}",
            severity=sev,
            category="web-discovery",
            description=f"Gobuster identificou rota com HTTP {status}.",
            evidence=m.group(0),
            source_file=str(path),
            metadata={
                "path": path_value,
                "status": status,
                "size": int(size) if size else None,
            },
        ))

    return findings


def parse_nikto_text(path: Path) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    text = read_text(path)

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        if stripped.startswith("+"):
            lowered = stripped.lower()

            severity = "LOW"
            if any(k in lowered for k in ["x-frame-options", "content-security-policy", "strict-transport-security"]):
                severity = "MEDIUM"
            if any(k in lowered for k in ["admin", "credentials", "password", "phpinfo", "vulnerable"]):
                severity = "HIGH"

            findings.append(finding(
                tool="nikto_safe",
                title="Alerta Nikto",
                severity=severity,
                category="web-hardening",
                description=stripped,
                evidence=stripped,
                source_file=str(path),
            ))

    return findings


def parse_wapiti_json(path: Path) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    data = read_json(path)

    if not isinstance(data, dict):
        return findings

    vulnerabilities = data.get("vulnerabilities") or {}
    if isinstance(vulnerabilities, dict):
        for category, items in vulnerabilities.items():
            if not isinstance(items, list):
                continue

            for item in items:
                if not isinstance(item, dict):
                    continue

                level = str(item.get("level") or item.get("severity") or "LOW").upper()
                info = item.get("info") or item.get("description") or ""
                path_url = item.get("path") or item.get("url") or ""

                findings.append(finding(
                    tool="wapiti_light",
                    title=f"Wapiti: {category}",
                    severity=level if level in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"} else "LOW",
                    category="web-vulnerability",
                    description=str(info),
                    evidence=str(path_url),
                    source_file=str(path),
                    metadata=item,
                ))

    return findings


def parse_wpscan_json(path: Path) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    data = read_json(path)

    if not isinstance(data, dict):
        return findings

    scan_aborted = str(data.get("scan_aborted") or "")

    if "does not seem to be running WordPress" in scan_aborted:
        findings.append(finding(
            tool="wpscan_passive",
            title="Alvo não aparenta usar WordPress",
            severity="INFO",
            category="cms-detection",
            description="WPScan executou e indicou que o alvo está online, mas não aparenta rodar WordPress.",
            evidence=scan_aborted,
            source_file=str(path),
            metadata={"target_url": data.get("target_url")},
        ))
        return findings

    if data.get("version"):
        findings.append(finding(
            tool="wpscan_passive",
            title="WordPress detectado",
            severity="MEDIUM",
            category="cms-detection",
            description="WPScan identificou possível instalação WordPress.",
            evidence=json.dumps(data.get("version"), ensure_ascii=False),
            source_file=str(path),
            metadata={"version": data.get("version")},
        ))

    for section in ["plugins", "themes", "timthumbs", "config_backups", "db_exports"]:
        value = data.get(section)
        if isinstance(value, dict) and value:
            findings.append(finding(
                tool="wpscan_passive",
                title=f"WPScan encontrou dados em {section}",
                severity="MEDIUM",
                category="cms-wordpress",
                description=f"Seção {section} possui entradas no resultado do WPScan.",
                evidence=section,
                source_file=str(path),
                metadata={section: value},
            ))

    return findings


def parse_masscan_text(path: Path) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    text = read_text(path)

    # Exemplos comuns:
    # open tcp 80 1.2.3.4
    # Discovered open port 443/tcp on 1.2.3.4
    patterns = [
        re.compile(r"open\s+tcp\s+(\d+)\s+([0-9.]+)", re.I),
        re.compile(r"Discovered open port\s+(\d+)/tcp\s+on\s+([0-9.]+)", re.I),
    ]

    for pat in patterns:
        for m in pat.finditer(text):
            port = int(m.group(1))
            ip = m.group(2)

            findings.append(finding(
                tool="masscan_webports_controlled",
                title=f"Porta web rápida detectada: {port}/tcp",
                severity="INFO",
                category="network-fast-discovery",
                description="Masscan identificou porta web aberta em varredura controlada.",
                evidence=m.group(0),
                source_file=str(path),
                metadata={"ip": ip, "port": port, "protocol": "tcp"},
            ))

    if "permission denied" in text.lower():
        findings.append(finding(
            tool="masscan_webports_controlled",
            title="Masscan sem permissão de rede",
            severity="LOW",
            category="tool-runtime",
            description="Masscan retornou erro de permissão. Verificar capabilities do binário.",
            evidence="permission denied",
            source_file=str(path),
        ))

    return findings


def parse_gowitness(tool_dir: Path, base: Path) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    screenshots = list(tool_dir.rglob("*.jpeg")) + list(tool_dir.rglob("*.jpg")) + list(tool_dir.rglob("*.png"))
    jsonls = list(tool_dir.rglob("*.jsonl"))

    for shot in screenshots:
        findings.append(finding(
            tool="gowitness_snapshot",
            title="Screenshot web capturado",
            severity="INFO",
            category="visual-evidence",
            description="Gowitness capturou evidência visual do alvo.",
            evidence=str(shot),
            source_file=str(shot),
            metadata={"relative_path": safe_rel(shot, base), "size": shot.stat().st_size},
        ))

    for jsonl in jsonls:
        for line in read_text(jsonl).splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except Exception:
                continue

            url = item.get("url") or item.get("target")
            status_code = item.get("status_code") or item.get("status-code")
            title = item.get("title")

            findings.append(finding(
                tool="gowitness_snapshot",
                title="Resultado visual Gowitness",
                severity="INFO",
                category="visual-evidence",
                description=f"Página renderizada com status {status_code}.",
                evidence=str(url),
                source_file=str(jsonl),
                metadata={
                    "url": url,
                    "status_code": status_code,
                    "title": title,
                },
            ))

    return findings


def parse_sqlmap(tool_dir: Path) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    text = "\n".join(read_text(p) for p in tool_dir.rglob("*") if p.is_file())

    if not text.strip():
        return findings

    lowered = text.lower()

    if "all tested parameters do not appear to be injectable" in lowered:
        findings.append(finding(
            tool="sqlmap_check",
            title="SQLMap não identificou injeção nos parâmetros testados",
            severity="INFO",
            category="injection-validation",
            description="Execução controlada do SQLMap não indicou parâmetros injetáveis no escopo testado.",
            evidence="all tested parameters do not appear to be injectable",
            source_file=str(tool_dir),
        ))
    elif "is vulnerable" in lowered or "parameter" in lowered and "injectable" in lowered:
        findings.append(finding(
            tool="sqlmap_check",
            title="Possível indício de SQL Injection",
            severity="HIGH",
            category="injection-validation",
            description="SQLMap retornou indício que precisa de validação manual controlada.",
            evidence="Possível indicação de parâmetro injetável no log.",
            source_file=str(tool_dir),
        ))

    return findings


def parse_zap(tool_dir: Path, base: Path) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    html = tool_dir / "zap_baseline.html"
    if html.exists() and html.stat().st_size > 0:
        findings.append(finding(
            tool="zap_baseline",
            title="Relatório ZAP Baseline gerado",
            severity="INFO",
            category="web-scanner-report",
            description="ZAP gerou relatório HTML de baseline.",
            evidence=str(html),
            source_file=str(html),
            metadata={
                "relative_path": safe_rel(html, base),
                "size": html.stat().st_size,
            },
        ))

    text = read_text(html, limit=500_000)
    for keyword, severity in [
        ("High", "HIGH"),
        ("Medium", "MEDIUM"),
        ("Low", "LOW"),
        ("Informational", "INFO"),
    ]:
        if keyword in text:
            findings.append(finding(
                tool="zap_baseline",
                title=f"ZAP contém seção/alerta: {keyword}",
                severity=severity,
                category="web-scanner-report",
                description=f"O relatório HTML do ZAP contém referência a {keyword}.",
                evidence=keyword,
                source_file=str(html),
            ))

    return findings



def normalize_url_for_key(value: Any) -> str:
    raw = str(value or "").strip().lower()
    raw = raw.replace("https://", "").replace("http://", "")
    raw = raw.split("#")[0]
    raw = re.sub(r"[?&](utm_[^=&]+|fbclid|gclid)=[^&]+", "", raw)
    raw = re.sub(r"/+$", "", raw)
    return raw


def normalize_finding_severity(item: Dict[str, Any]) -> Dict[str, Any]:
    tool = str(item.get("tool") or "")
    desc = str(item.get("description") or "").lower()
    evidence = str(item.get("evidence") or "").lower()
    combined = f"{desc} {evidence}"

    # Nikto é scanner de assinaturas. A maioria das linhas é candidata,
    # não confirmação de vulnerabilidade.
    if tool == "nikto_safe":
        item["title"] = classify_nikto_title(combined)
        item["category"] = classify_nikto_category(combined)

        confirmed_high = [
            # HIGH somente quando o texto indica vulnerabilidade forte e atual.
            # CVE sozinho não basta, porque o Nikto lista muitos checks históricos.
            "remote code execution",
            " rce ",
            "command execution",
            "shell upload",
            "sql injection vulnerability",
            "directory traversal vulnerability",
            "authentication bypass",
            "arbitrary file upload",
            "unauthenticated access confirmed",
            "confirmed vulnerable",
        ]

        sensitive_candidate = [
            "config.php",
            "configuration file",
            "backup",
            ".bak",
            ".old",
            ".sql",
            "database",
            "db/users",
            "passwd",
            "password",
            "credentials",
            "phpinfo",
            "admin",
            "login",
            "webadmin",
            "server-status",
        ]

        hardening = [
            "x-frame-options",
            "content-security-policy",
            "strict-transport-security",
            "x-content-type-options",
            "cookie",
            "httponly",
            "samesite",
        ]

        generic_signature_noise = [
            "sterling commerce",
            "iisamples",
            "site server",
            "coldfusion",
            "domlog.nsf",
            "catalog.nsf",
            "cfcache.map",
            "bigconf.cgi",
            "cvs",
            "admentor",
            "livehelp",
            "axis",
            "frontpage",
            "test password",
            "default file",
            "default page",
            "win2000",
            "windows 2000",
            "cve-1999",
            "cve-2000",
            "cve-2001",
            "bugtraq",
            "ms99-",
            "iis 4",
            "iis 5",
            "oracle pages",
            "owa_util",
            "exair",
            "codebrws",
            "code.asp",
            "codebrwl.asp",
            "team services vulnerable",
            "default iis script",
            "default iis scripts",
        ]

        if any(k in combined for k in confirmed_high):
            item["severity"] = "HIGH"
            item["metadata"]["confidence"] = "candidate_high_requires_manual_validation"
        elif any(k in combined for k in sensitive_candidate):
            item["severity"] = "MEDIUM"
            item["metadata"]["confidence"] = "candidate_requires_status_validation"
        elif any(k in combined for k in hardening):
            item["severity"] = "LOW"
            item["metadata"]["confidence"] = "hardening_indicator"
        elif any(k in combined for k in generic_signature_noise):
            item["severity"] = "INFO"
            item["metadata"]["confidence"] = "generic_nikto_signature"
        else:
            item["severity"] = "INFO"
            item["metadata"]["confidence"] = "informational_nikto_output"

    # Gate conservador:
    # Nikto produz muitas assinaturas históricas/candidatas.
    # No CyberLab, Nikto não confirma HIGH sozinho.
    if tool == "nikto_safe":
        if item.get("severity") == "HIGH":
            item["severity"] = "MEDIUM"
            item.setdefault("metadata", {})
            item["metadata"]["confidence"] = "nikto_candidate_manual_validation_required"
            item["metadata"]["severity_gate"] = "downgraded_from_high_by_candidate_gate"

        if item.get("category") in {"tool-signature", "vulnerability-candidate", "access-surface"}:
            item.setdefault("metadata", {})
            item["metadata"]["requires_manual_validation"] = True

    # ZAP baseline HTML pode conter a palavra High sem ser achado estruturado.
    # Sem alerta estruturado, tratar como candidato.
    if tool == "zap_baseline":
        if item.get("severity") == "HIGH":
            item["severity"] = "MEDIUM"
            item.setdefault("metadata", {})
            item["metadata"]["confidence"] = "zap_html_section_requires_manual_validation"
            item["metadata"]["severity_gate"] = "downgraded_from_high_by_candidate_gate"


    # FFUF/Gobuster são descoberta, não vulnerabilidade confirmada.
    if tool in {"ffuf_controlled", "gobuster_controlled"}:
        status = item.get("metadata", {}).get("status")
        try:
            status = int(status)
        except Exception:
            status = 0

        if status in {401, 403}:
            item["severity"] = "MEDIUM"
        elif status in {200, 201, 202, 204, 301, 302, 307, 308, 405}:
            item["severity"] = "LOW"
        else:
            item["severity"] = "INFO"

    # Guarda final: Nikto não deve gerar HIGH por assinatura antiga/genérica.
    if tool == "nikto_safe" and item.get("severity") == "HIGH":
        confidence = str(item.get("metadata", {}).get("confidence") or "")
        if confidence in {
            "generic_nikto_signature",
            "informational_nikto_output",
            "candidate_requires_status_validation",
        }:
            item["severity"] = "MEDIUM"
            item["metadata"]["confidence"] = "downgraded_high_requires_manual_validation"

    return item


def classify_nikto_title(text: str) -> str:
    if any(k in text for k in ["x-frame-options", "content-security-policy", "strict-transport-security", "x-content-type-options"]):
        return "Nikto: indicador de hardening HTTP"
    if any(k in text for k in ["admin", "login", "webadmin"]):
        return "Nikto: possível rota administrativa ou autenticação"
    if any(k in text for k in ["backup", ".bak", ".old", ".sql", "config.php", "configuration file"]):
        return "Nikto: possível arquivo sensível ou configuração exposta"
    if any(k in text for k in ["cve-", "vulnerable", "remote code", "sql injection", "directory traversal"]):
        return "Nikto: possível vulnerabilidade conhecida"
    return "Nikto: assinatura informativa/candidata"


def classify_nikto_category(text: str) -> str:
    if any(k in text for k in ["x-frame-options", "content-security-policy", "strict-transport-security", "x-content-type-options"]):
        return "web-hardening"
    if any(k in text for k in ["admin", "login", "webadmin"]):
        return "access-surface"
    if any(k in text for k in ["backup", ".bak", ".old", ".sql", "config.php", "configuration file"]):
        return "sensitive-file-candidate"
    if any(k in text for k in ["cve-", "vulnerable", "remote code", "sql injection", "directory traversal"]):
        return "vulnerability-candidate"
    return "tool-signature"


def finding_key(item: Dict[str, Any]) -> str:
    meta = item.get("metadata") or {}

    tool = str(item.get("tool") or "")
    category = str(item.get("category") or "")
    title = str(item.get("title") or "")

    url = meta.get("url") or meta.get("path") or item.get("evidence") or ""
    norm = normalize_url_for_key(url)

    status = meta.get("status", "")
    port = meta.get("port", "")

    return f"{tool}|{category}|{title}|{norm}|{status}|{port}"


def ffuf_fingerprint(item: Dict[str, Any]) -> str:
    meta = item.get("metadata") or {}
    return "|".join([
        str(meta.get("status", "")),
        str(meta.get("length", "")),
        str(meta.get("words", "")),
        str(meta.get("lines", "")),
    ])


def suppress_noisy_findings(findings: List[Dict[str, Any]]) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Reduz ruído sem apagar evidência:
    - normaliza severidade;
    - remove duplicados;
    - suprime fallback massivo do FFUF por fingerprint repetido;
    - aplica limite por ferramenta para relatório.
    """
    normalized: List[Dict[str, Any]] = []
    suppressed: List[Dict[str, Any]] = []

    for item in findings:
        normalized.append(normalize_finding_severity(item))

    # 1. Deduplicação forte.
    seen = set()
    deduped: List[Dict[str, Any]] = []

    for item in normalized:
        key = finding_key(item)
        if key in seen:
            clone = dict(item)
            clone["suppressed_reason"] = "duplicate_finding_key"
            suppressed.append(clone)
            continue
        seen.add(key)
        deduped.append(item)

    # 2. FFUF: se centenas têm mesmo status/tamanho/palavras/linhas, é fallback/ruído.
    ffuf_counts: Dict[str, int] = {}
    for item in deduped:
        if item.get("tool") == "ffuf_controlled":
            fp = ffuf_fingerprint(item)
            ffuf_counts[fp] = ffuf_counts.get(fp, 0) + 1

    filtered: List[Dict[str, Any]] = []

    for item in deduped:
        if item.get("tool") == "ffuf_controlled":
            fp = ffuf_fingerprint(item)
            count = ffuf_counts.get(fp, 0)

            # Permite amostra de fingerprints repetidos, mas não milhares.
            if count > 40:
                clone = dict(item)
                clone["suppressed_reason"] = f"ffuf_repeated_response_fingerprint_{count}"
                suppressed.append(clone)
                continue

        filtered.append(item)

    # 3. Limite por ferramenta para não poluir findings.
    tool_limits = {
        "ffuf_controlled": 150,
        "gobuster_controlled": 120,
        "nikto_safe": 120,
        "zap_baseline": 20,
        "gowitness_snapshot": 20,
        "wpscan_passive": 20,
        "masscan_webports_controlled": 50,
        "wapiti_light": 200,
        "nmap_safe": 200,
        "sqlmap_check": 50,
    }

    final: List[Dict[str, Any]] = []
    counters: Dict[str, int] = {}

    severity_rank = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4,
    }

    filtered = sorted(
        filtered,
        key=lambda x: (
            str(x.get("tool") or ""),
            severity_rank.get(str(x.get("severity") or "INFO"), 9),
            str(x.get("title") or ""),
        ),
    )

    for item in filtered:
        tool = str(item.get("tool") or "UNKNOWN")
        counters[tool] = counters.get(tool, 0) + 1

        limit = tool_limits.get(tool, 100)
        if counters[tool] > limit:
            clone = dict(item)
            clone["suppressed_reason"] = f"tool_limit_exceeded_{limit}"
            suppressed.append(clone)
            continue

        final.append(item)

    return final, suppressed



def collect_evidence(tools_dir: Path, out_dir: Path) -> List[Dict[str, Any]]:
    evidence: List[Dict[str, Any]] = []

    for tool_dir in tools_dir.iterdir():
        if not tool_dir.is_dir() or tool_dir.name == OUT_DIRNAME:
            continue

        for p in tool_dir.rglob("*"):
            if not p.is_file():
                continue

            suffix = p.suffix.lower()
            kind = "file"
            if suffix in {".json", ".jsonl"}:
                kind = "json"
            elif suffix in {".log", ".txt"}:
                kind = "log"
            elif suffix in {".html", ".htm"}:
                kind = "html-report"
            elif suffix in {".jpeg", ".jpg", ".png"}:
                kind = "screenshot"

            evidence.append(evidence_item(
                tool=tool_dir.name,
                kind=kind,
                path=p,
                base=tools_dir,
                description=f"Artefato gerado por {tool_dir.name}",
            ))

    return evidence


def parse_all(scan_dir: Path) -> Dict[str, Any]:
    tools_dir = ensure_scan_dir(scan_dir)
    out_dir = tools_dir / OUT_DIRNAME
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = parse_tool_summary_json(scan_dir, tools_dir)

    findings: List[Dict[str, Any]] = []

    # nmap
    if (tools_dir / "nmap_safe").exists():
        findings.extend(parse_nmap(tools_dir / "nmap_safe", tools_dir))

    # ffuf
    for p in (tools_dir / "ffuf_controlled").rglob("*.json") if (tools_dir / "ffuf_controlled").exists() else []:
        findings.extend(parse_ffuf_json(p))

    # gobuster
    for p in (tools_dir / "gobuster_controlled").rglob("*") if (tools_dir / "gobuster_controlled").exists() else []:
        if p.is_file() and p.suffix.lower() in {".txt", ".log"}:
            findings.extend(parse_gobuster_text(p))

    # nikto
    # Evita ler stdout/stderr genéricos, banners e help.
    # Preferência para o arquivo real gerado pelo Nikto.
    nikto_dir = tools_dir / "nikto_safe"
    if nikto_dir.exists():
        nikto_candidates = [
            p for p in nikto_dir.rglob("*")
            if p.is_file()
            and p.name not in {"stdout.log", "stderr.log"}
            and ("nikto" in p.name.lower() or p.suffix.lower() in {".txt", ".json"})
        ]
        for p in nikto_candidates:
            findings.extend(parse_nikto_text(p))

    # wapiti
    for p in (tools_dir / "wapiti_light").rglob("*.json") if (tools_dir / "wapiti_light").exists() else []:
        findings.extend(parse_wapiti_json(p))

    # zap
    if (tools_dir / "zap_baseline").exists():
        findings.extend(parse_zap(tools_dir / "zap_baseline", tools_dir))

    # sqlmap
    if (tools_dir / "sqlmap_check").exists():
        findings.extend(parse_sqlmap(tools_dir / "sqlmap_check"))

    # gowitness
    if (tools_dir / "gowitness_snapshot").exists():
        findings.extend(parse_gowitness(tools_dir / "gowitness_snapshot", tools_dir))

    # wpscan
    for p in (tools_dir / "wpscan_passive").rglob("*.json") if (tools_dir / "wpscan_passive").exists() else []:
        findings.extend(parse_wpscan_json(p))

    # masscan
    if (tools_dir / "masscan_webports_controlled").exists():
        for p in (tools_dir / "masscan_webports_controlled").rglob("*"):
            if p.is_file():
                findings.extend(parse_masscan_text(p))

    raw_findings_count = len(findings)
    findings, suppressed_findings = suppress_noisy_findings(findings)

    evidence = collect_evidence(tools_dir, out_dir)

    status = {
        "schema": "cyberlab.tool_output_intelligence.status.v1",
        "generated_at": now_iso(),
        "scan_dir": str(scan_dir),
        "tools_dir": str(tools_dir),
        "output_dir": str(out_dir),
        "target": summary.get("target"),
        "profile": summary.get("profile"),
        "orchestrator_summary": summary.get("summary", {}),
        "raw_findings_count": raw_findings_count,
        "findings_count": len(findings),
        "noise_suppressed_count": len(suppressed_findings),
        "evidence_count": len(evidence),
        "severity_counts": count_by(findings, "severity"),
        "tool_counts": count_by(findings, "tool"),
        "ok": True,
    }

    write_json(out_dir / "tool-findings.json", {
        "schema": "cyberlab.tool_findings.v1",
        "generated_at": now_iso(),
        "scan_dir": str(scan_dir),
        "findings": findings,
    })

    write_json(out_dir / "tool-evidence-index.json", {
        "schema": "cyberlab.tool_evidence_index.v1",
        "generated_at": now_iso(),
        "scan_dir": str(scan_dir),
        "evidence": evidence,
    })

    write_json(out_dir / "tool-noise-suppressed.json", {
        "schema": "cyberlab.tool_noise_suppressed.v1",
        "generated_at": now_iso(),
        "scan_dir": str(scan_dir),
        "suppressed_count": len(suppressed_findings),
        "suppressed": suppressed_findings[:2000],
        "note": "Amostra limitada a 2000 itens para evitar arquivo excessivo.",
    })

    write_json(out_dir / "tool-output-status.json", status)

    (out_dir / "tool-output-summary.md").write_text(
        build_markdown_summary(status, findings, evidence),
        encoding="utf-8",
    )

    return {
        "status": status,
        "findings": findings,
        "evidence": evidence,
        "out_dir": str(out_dir),
    }


def count_by(items: List[Dict[str, Any]], key: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for item in items:
        value = str(item.get(key) or "UNKNOWN")
        counts[value] = counts.get(value, 0) + 1
    return counts


def build_markdown_summary(
    status: Dict[str, Any],
    findings: List[Dict[str, Any]],
    evidence: List[Dict[str, Any]],
) -> str:
    lines: List[str] = []

    lines.append("# CyberLab — Tool Output Intelligence")
    lines.append("")
    lines.append(f"**Gerado em:** {status.get('generated_at')}")
    lines.append(f"**Scan dir:** `{status.get('scan_dir')}`")
    lines.append(f"**Target:** `{status.get('target')}`")
    lines.append(f"**Profile:** `{status.get('profile')}`")
    lines.append("")
    lines.append("## Resumo")
    lines.append("")
    lines.append(f"- Achados brutos antes do filtro: **{status.get('raw_findings_count', len(findings))}**")
    lines.append(f"- Achados consolidados: **{len(findings)}**")
    lines.append(f"- Ruído suprimido: **{status.get('noise_suppressed_count', 0)}**")
    lines.append(f"- Evidências indexadas: **{len(evidence)}**")
    lines.append("")
    lines.append("## Achados por severidade")
    lines.append("")
    for sev, count in sorted(status.get("severity_counts", {}).items()):
        lines.append(f"- **{sev}:** {count}")

    lines.append("")
    lines.append("## Achados por ferramenta")
    lines.append("")
    for tool, count in sorted(status.get("tool_counts", {}).items()):
        lines.append(f"- **{tool}:** {count}")

    lines.append("")
    lines.append("## Top achados")
    lines.append("")

    severity_rank = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4,
    }

    top = sorted(
        findings,
        key=lambda x: severity_rank.get(str(x.get("severity", "INFO")), 9),
    )[:30]

    if not top:
        lines.append("- Nenhum achado consolidado.")
    else:
        for item in top:
            lines.append(
                f"- **{item.get('severity')}** | `{item.get('tool')}` | {item.get('title')}"
            )

    lines.append("")
    lines.append("## Evidências principais")
    lines.append("")

    for item in evidence[:50]:
        lines.append(
            f"- `{item.get('tool')}` | {item.get('kind')} | `{item.get('relative_path')}`"
        )

    lines.append("")
    return "\n".join(lines)



# ============================================================
# CyberLab - Normalização de ferramentas sem achados
# ============================================================

def normalize_empty_tool_result(tool_name: str, output_file: Path, stdout_file: Path = None, stderr_file: Path = None):
    """
    Quando uma ferramenta executa corretamente mas gera JSON vazio,
    isso não deve ser tratado como ausência da ferramenta.
    Exemplo: Nuclei exit 0 + JSON vazio = OK_NO_FINDINGS.
    """
    result = {
        "tool": tool_name,
        "status": "OK_NO_FINDINGS",
        "title": f"{tool_name}: executado sem achados",
        "severity": "INFO",
        "category": "tool-execution",
        "confidence": "confirmed_no_findings",
        "description": f"{tool_name} executou corretamente, mas não retornou achados estruturados.",
        "evidence": str(output_file) if output_file else None,
        "metadata": {
            "empty_result": True,
            "stdout_log": str(stdout_file) if stdout_file else None,
            "stderr_log": str(stderr_file) if stderr_file else None,
        }
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="CyberLab Tool Output Parser"
    )
    parser.add_argument(
        "--scan-dir",
        required=True,
        help="Diretório oficial do scan que contém 11-tool-orchestrator",
    )
    args = parser.parse_args()

    scan_dir = Path(args.scan_dir).expanduser().resolve()
    result = parse_all(scan_dir)

    status = result["status"]

    print("============================================================")
    print(" CYBERLAB — TOOL OUTPUT PARSER FINALIZADO")
    print("============================================================")
    print(f"[OK] Scan dir:       {status['scan_dir']}")
    print(f"[OK] Output dir:     {status['output_dir']}")
    print(f"[OK] Findings:       {status['findings_count']}")
    print(f"[OK] Evidências:     {status['evidence_count']}")
    print(f"[OK] Status:         {status['ok']}")
    print("============================================================")

    return 0





def cyberlab_get_scan_dir_from_argv():
    """
    Extrai --scan-dir da linha de comando para pós-processamentos do parser.
    """
    import sys
    from pathlib import Path

    for i, arg in enumerate(sys.argv):
        if arg == "--scan-dir" and i + 1 < len(sys.argv):
            return Path(sys.argv[i + 1])
        if arg.startswith("--scan-dir="):
            return Path(arg.split("=", 1)[1])

    return None

def cyberlab_run_bugbounty_accuracy(scan_dir):
    """
    Executa a camada Bug Bounty Accuracy após o parser 05B.
    Não falha o parser principal se a camada de accuracy falhar.
    """
    import subprocess
    import sys
    from pathlib import Path

    scan_dir = Path(scan_dir)

    accuracy_script = Path(__file__).resolve().parent / "bugbounty_accuracy.py"

    if not accuracy_script.exists():
        print(f"[WARN] bugbounty_accuracy.py não encontrado: {accuracy_script}")
        return False

    cmd = [
        sys.executable,
        str(accuracy_script),
        "--scan-dir",
        str(scan_dir),
    ]

    try:
        proc = subprocess.run(
            cmd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=300,
        )

        if proc.stdout.strip():
            print(proc.stdout.strip())

        if proc.returncode != 0:
            print("[WARN] Bug Bounty Accuracy retornou erro.")
            if proc.stderr.strip():
                print(proc.stderr.strip())
            return False

        print("[OK] Bug Bounty Accuracy integrado ao 05B.")
        return True

    except subprocess.TimeoutExpired:
        print("[WARN] Bug Bounty Accuracy excedeu timeout interno.")
        return False

    except Exception as exc:
        print(f"[WARN] Bug Bounty Accuracy falhou: {exc}")
        return False

def cyberlab_postprocess_zero_finding_tools_from_evidence():
    """
    Pós-processamento defensivo do 05B:
    se uma ferramenta gerou evidência/log/artefato, mas teve 0 achados,
    ela também deve aparecer em tool_counts com valor 0.
    """
    import json
    import sys
    from pathlib import Path

    scan_dir = None

    for i, arg in enumerate(sys.argv):
        if arg == "--scan-dir" and i + 1 < len(sys.argv):
            scan_dir = sys.argv[i + 1]
            break
        if arg.startswith("--scan-dir="):
            scan_dir = arg.split("=", 1)[1]
            break

    if not scan_dir:
        return

    scan_dir = Path(scan_dir)
    out_dir = scan_dir / "11-tool-orchestrator" / "tool_output_intelligence"
    status_path = out_dir / "tool-output-status.json"
    evidence_path = out_dir / "tool-evidence-index.json"

    if not status_path.exists():
        return

    try:
        status = json.loads(status_path.read_text(encoding="utf-8"))
    except Exception:
        return

    tools = set()

    def walk(obj):
        if isinstance(obj, dict):
            tool = obj.get("tool")
            if tool and isinstance(tool, str):
                tools.add(tool)
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)

    if evidence_path.exists():
        try:
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            walk(evidence)
        except Exception:
            pass

    orch_dir = scan_dir / "11-tool-orchestrator"
    if orch_dir.exists():
        for child in orch_dir.iterdir():
            if child.is_dir() and child.name != "tool_output_intelligence":
                if any(child.iterdir()):
                    tools.add(child.name)

    status.setdefault("tool_counts", {})
    for tool in sorted(tools):
        status["tool_counts"].setdefault(tool, 0)

    status_path.write_text(
        json.dumps(status, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )

if __name__ == "__main__":
    _cyberlab_exit_code = main()

    try:
        cyberlab_postprocess_zero_finding_tools_from_evidence()
    except Exception as exc:
        print(f"[WARN] postprocess zero-finding tools falhou: {exc}")

    try:
        _scan_dir = cyberlab_get_scan_dir_from_argv()
        if _scan_dir:
            cyberlab_run_bugbounty_accuracy(_scan_dir)
        else:
            print("[WARN] --scan-dir não encontrado; Bug Bounty Accuracy não executado.")
    except Exception as exc:
        print(f"[WARN] Integração Bug Bounty Accuracy falhou: {exc}")

    raise SystemExit(_cyberlab_exit_code)

if __name__ == "__main__":
    _cyberlab_exit_code = main()

    try:
        cyberlab_postprocess_zero_finding_tools_from_evidence()
    except Exception as exc:
        print(f"[WARN] postprocess zero-finding tools falhou: {exc}")

    try:
        _scan_dir = cyberlab_get_scan_dir_from_argv()
        if _scan_dir:
            cyberlab_run_bugbounty_accuracy(_scan_dir)
        else:
            print("[WARN] --scan-dir não encontrado; Bug Bounty Accuracy não executado.")
    except Exception as exc:
        print(f"[WARN] Integração Bug Bounty Accuracy falhou: {exc}")

    raise SystemExit(_cyberlab_exit_code)

if __name__ == "__main__":
    _cyberlab_exit_code = main()

    try:
        cyberlab_postprocess_zero_finding_tools_from_evidence()
    except Exception as exc:
        print(f"[WARN] postprocess zero-finding tools falhou: {exc}")

    try:
        _scan_dir = cyberlab_get_scan_dir_from_argv()
        if _scan_dir:
            cyberlab_run_bugbounty_accuracy(_scan_dir)
        else:
            print("[WARN] --scan-dir não encontrado; Bug Bounty Accuracy não executado.")
    except Exception as exc:
        print(f"[WARN] Integração Bug Bounty Accuracy falhou: {exc}")

    raise SystemExit(_cyberlab_exit_code)

