#!/usr/bin/env python3
import json, hashlib, os
from pathlib import Path
from datetime import datetime

HOME = Path.home() / "CyberLab"
RESULTS = HOME / "results"
STATE = HOME / "state"
OUT_DIR = STATE / "findings"
OUT_DIR.mkdir(parents=True, exist_ok=True)

def load_json(path):
    try:
        return json.loads(Path(path).read_text(errors="ignore"))
    except Exception:
        return None

def severity_norm(v):
    if not v:
        return "INFO"
    v = str(v).upper()
    if v in ["CRITICAL", "CRITICO", "CRÍTICO"]:
        return "CRITICAL"
    if v in ["HIGH", "ALTO"]:
        return "HIGH"
    if v in ["MEDIUM", "MEDIO", "MÉDIO"]:
        return "MEDIUM"
    if v in ["LOW", "BAIXO"]:
        return "LOW"
    return "INFO"

def confidence_from_source(source):
    s = source.lower()
    if "nuclei" in s:
        return 85
    if "nikto" in s:
        return 65
    if "correlation" in s:
        return 75
    if "detection" in s:
        return 70
    if "threat" in s:
        return 70
    if "web" in s:
        return 60
    return 50

def finding_id(asset, title, category):
    raw = f"{asset}|{title}|{category}".lower()
    return hashlib.sha1(raw.encode()).hexdigest()[:16]

def make_finding(asset, title, severity="INFO", category="general", source="unknown", evidence=None, tags=None):
    severity = severity_norm(severity)
    fid = finding_id(asset, title, category)
    return {
        "id": fid,
        "title": title,
        "severity": severity,
        "confidence": confidence_from_source(source),
        "category": category,
        "source": source,
        "asset": asset,
        "evidence": evidence or [],
        "tags": tags or [],
        "false_positive": False,
        "created_at": datetime.now().isoformat()
    }

def extract_from_summary(path, data):
    findings = []
    asset = data.get("target") or data.get("asset") or data.get("domain") or "unknown"
    source = str(path)

    # score/level summaries
    if "score" in data or "level" in data:
        score = int(data.get("score", 0) or 0)
        level = data.get("level", "INFO")
        findings.append(make_finding(
            asset=asset,
            title=f"Resumo de risco consolidado: score {score}",
            severity=level,
            category="risk-summary",
            source=source,
            evidence=[str(path)],
            tags=["summary", "risk"]
        ))

    # generic findings array
    for key in ["findings", "issues", "vulnerabilities", "alerts"]:
        arr = data.get(key)
        if isinstance(arr, list):
            for item in arr:
                if isinstance(item, dict):
                    title = item.get("title") or item.get("name") or item.get("item") or item.get("description") or "Achado sem título"
                    sev = item.get("severity") or item.get("risk") or item.get("level") or "INFO"
                    cat = item.get("category") or item.get("type") or key
                    a = item.get("asset") or item.get("host") or item.get("target") or asset
                    findings.append(make_finding(
                        asset=a,
                        title=title,
                        severity=sev,
                        category=cat,
                        source=source,
                        evidence=[item.get("evidence", str(path))],
                        tags=item.get("tags", [])
                    ))
    return findings

def extract_from_text(path):
    findings = []
    txt = Path(path).read_text(errors="ignore")
    asset = "unknown"
    source = str(path)

    patterns = [
        ("Strict-Transport-Security", "HSTS ausente ou revisar configuração", "MEDIUM", "header"),
        ("Content-Security-Policy", "CSP ausente ou revisar configuração", "MEDIUM", "header"),
        ("X-Frame-Options", "X-Frame-Options ausente ou revisar configuração", "LOW", "header"),
        ("PHPSESSID", "Cookie de sessão observado em resposta HTTP", "LOW", "session"),
        ("x-powered-by", "Header X-Powered-By expõe tecnologia", "LOW", "fingerprint"),
        ("cloudflare", "Proteção Cloudflare/CDN detectada", "INFO", "waf"),
        ("WAF", "WAF/CDN detectado", "INFO", "waf"),
        ("Nikto", "Resultado Nikto disponível para revisão", "INFO", "scanner"),
        ("Nuclei", "Resultado Nuclei disponível para revisão", "INFO", "scanner"),
    ]
    lowtxt = txt.lower()
    for token, title, sev, cat in patterns:
        if token.lower() in lowtxt:
            findings.append(make_finding(asset, title, sev, cat, source, [str(path)], [cat]))
    return findings

def dedup(findings):
    merged = {}
    for f in findings:
        fid = f["id"]
        if fid not in merged:
            merged[fid] = f
        else:
            old = merged[fid]
            old["confidence"] = min(100, max(old["confidence"], f["confidence"]) + 5)
            old["evidence"] = list(dict.fromkeys(old.get("evidence", []) + f.get("evidence", [])))
            old["tags"] = list(dict.fromkeys(old.get("tags", []) + f.get("tags", [])))
            old["source"] = old["source"] + " | " + f["source"]
    return list(merged.values())

def main():
    findings = []

    for p in RESULTS.rglob("*.json"):
        data = load_json(p)
        if isinstance(data, dict):
            findings.extend(extract_from_summary(p, data))

    for p in RESULTS.rglob("*.md"):
        findings.extend(extract_from_text(p))

    findings = dedup(findings)

    out = OUT_DIR / "findings.json"
    out.write_text(json.dumps({
        "generated_at": datetime.now().isoformat(),
        "count": len(findings),
        "findings": findings
    }, indent=2, ensure_ascii=False))

    print(f"[OK] Findings normalizados: {out}")
    print(f"[OK] Total: {len(findings)}")

if __name__ == "__main__":
    main()
