#!/usr/bin/env python3
import json
from pathlib import Path
from datetime import datetime

HOME = Path.home() / "CyberLab"
IN = HOME / "state/intelligence/findings-scored.json"
OUT = HOME / "state/intelligence/remediation-plan.json"

RECS = {
    "header": "Revisar e aplicar headers de segurança compatíveis com a aplicação.",
    "session": "Revisar cookies de sessão, flags HttpOnly, Secure, SameSite e escopo de domínio.",
    "fingerprint": "Reduzir exposição de versão/tecnologia em headers e mensagens públicas.",
    "waf": "Validar regras do WAF/CDN e monitorar alterações na proteção.",
    "scanner": "Revisar manualmente o resultado bruto do scanner e confirmar impacto real.",
    "risk-summary": "Usar como indicador agregado; validar os achados individuais.",
    "exposure": "Confirmar necessidade de exposição pública e restringir acesso quando possível.",
    "cve": "Validar versão afetada e aplicar patch ou mitigação documentada.",
    "secret": "Revogar segredo, rotacionar credenciais e investigar uso indevido.",
    "auth": "Testar controle de acesso e aplicar correção no fluxo de autenticação/autorização.",
    "admin": "Restringir painel administrativo por VPN, allowlist, MFA ou camada adicional."
}

def sla(priority):
    return {
        "P1": "24-48h",
        "P2": "3-7 dias",
        "P3": "15-30 dias",
        "P4": "Próximo ciclo de hardening"
    }.get(priority, "Próximo ciclo")

def main():
    data = json.loads(IN.read_text(errors="ignore"))
    items = []

    for f in data.get("findings", []):
        cat = str(f.get("category", "general")).lower()
        pri = f.get("priority", "P4")
        items.append({
            "finding_id": f.get("id"),
            "title": f.get("title"),
            "asset": f.get("asset"),
            "severity": f.get("severity"),
            "priority": pri,
            "risk_score": f.get("risk_score", 0),
            "confidence": f.get("confidence", 0),
            "recommendation": RECS.get(cat, "Validar tecnicamente o achado, confirmar impacto e aplicar mitigação proporcional."),
            "suggested_sla": sla(pri),
            "category": cat
        })

    OUT.write_text(json.dumps({
        "generated_at": datetime.now().isoformat(),
        "count": len(items),
        "remediation": items
    }, indent=2, ensure_ascii=False))

    print(f"[OK] Plano de remediação: {OUT}")

if __name__ == "__main__":
    main()
