#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CyberLab - Bloco 14 Validation Intelligence

Objetivo:
- Validar achados do Bloco 12 sem exploração destrutiva.
- Separar risco real, revisão manual, superfície informativa e falso positivo provável.
- Contextualizar plataformas como Shopify, Cloudflare, CDN e APIs públicas.
- Gerar insights úteis para cliente e relatório técnico.

Controle:
- Leitura local de evidências.
- Decodificação local de tokens.
- Sem brute force.
- Sem bypass.
- Sem exploração destrutiva.
- Sem alteração de dados.
"""

from __future__ import annotations

import base64
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


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
    "SURFACE_CDN",
}

SENSITIVE_KEYS = {
    "email",
    "e-mail",
    "mail",
    "phone",
    "telefone",
    "tel",
    "cpf",
    "cnpj",
    "document",
    "documento",
    "address",
    "endereco",
    "endereço",
    "street",
    "cep",
    "postal",
    "customer",
    "customer_id",
    "cliente",
    "user",
    "user_id",
    "name",
    "nome",
    "first_name",
    "last_name",
    "birth",
    "birthday",
    "nascimento",
    "payment",
    "card",
    "cartao",
    "cartão",
}


@dataclass
class ValidationResult:
    validation_status: str
    validation_severity: str
    confidence: int
    reason: str
    action: str
    evidence_safe: str
    promoted_to_real_risk: bool = False


class Block14ValidationEngine:
    def __init__(self, scan_dir: Path, target: str):
        self.scan_dir = scan_dir
        self.target = target
        self.block12_dir = self.scan_dir / "block_12_intelligence"
        self.output_dir = self.scan_dir / "block_14_validation"
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.block12_json = self.block12_dir / "block_12_findings.json"

    def run(self) -> Dict[str, Path]:
        if not self.block12_json.exists():
            raise FileNotFoundError(f"Bloco 12 não encontrado: {self.block12_json}")

        data = json.loads(self.block12_json.read_text(encoding="utf-8"))
        findings = data.get("findings") or data.get("items") or []

        validated = []
        insights = []

        for item in findings:
            result = self.validate_item(item)
            enriched = dict(item)
            enriched["block14"] = {
                "validation_status": result.validation_status,
                "validation_severity": result.validation_severity,
                "confidence": result.confidence,
                "reason": result.reason,
                "recommended_action": result.action,
                "evidence_safe": result.evidence_safe,
                "promoted_to_real_risk": result.promoted_to_real_risk,
            }
            validated.append(enriched)

        insights = self.build_insights(validated)
        summary = self.build_summary(validated, insights)

        validated_payload = {
            "block": "14",
            "module": "Validation Intelligence",
            "target": self.target,
            "scan_dir": str(self.scan_dir),
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "source": str(self.block12_json),
            "summary": summary,
            "findings": validated,
        }

        insights_payload = {
            "block": "14",
            "module": "Validation Insights",
            "target": self.target,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "summary": summary,
            "insights": insights,
        }

        status_payload = {
            "block": "14",
            "module": "Validation Intelligence",
            "target": self.target,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "status": "OK",
            "input": str(self.block12_json),
            "output_dir": str(self.output_dir),
            "summary": summary,
            "files": {
                "validated_findings": str(self.output_dir / "block_14_validated_findings.json"),
                "insights": str(self.output_dir / "block_14_insights.json"),
                "technical_report": str(self.output_dir / "block_14_validation_report.md"),
                "client_summary": str(self.output_dir / "block_14_client_summary.md"),
                "pdf": str(self.output_dir / "block_14_validation_report.pdf"),
                "status": str(self.output_dir / "block_14_status.json"),
            },
        }

        paths = {
            "validated_findings": self.output_dir / "block_14_validated_findings.json",
            "insights": self.output_dir / "block_14_insights.json",
            "technical_report": self.output_dir / "block_14_validation_report.md",
            "client_summary": self.output_dir / "block_14_client_summary.md",
            "pdf": self.output_dir / "block_14_validation_report.pdf",
            "status": self.output_dir / "block_14_status.json",
        }

        paths["validated_findings"].write_text(
            json.dumps(validated_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        paths["insights"].write_text(
            json.dumps(insights_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        paths["technical_report"].write_text(
            self.render_technical_report(summary, insights, validated),
            encoding="utf-8",
        )

        paths["client_summary"].write_text(
            self.render_client_summary(summary, insights),
            encoding="utf-8",
        )

        paths["status"].write_text(
            json.dumps(status_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        self.render_pdf(paths["pdf"], summary, insights)

        return paths

    def validate_item(self, item: Dict[str, Any]) -> ValidationResult:
        category = str(item.get("category", "")).upper()
        title = str(item.get("title", ""))
        evidence = str(item.get("evidence", ""))
        source = str(item.get("source_type", item.get("origin", ""))).upper()

        evidence_safe = self.mask_evidence(evidence)

        if category in {"JWT", "TOKEN", "SECRET"}:
            return self.validate_token(item, force_real_context=True)

        if category == "SURFACE_TOKEN":
            return self.validate_token(item, force_real_context=False)

        if category in {"API", "SURFACE_API"}:
            return self.validate_api(item)

        if category in {"PORT", "SURFACE_PORT"}:
            return self.validate_port(item)

        if category in {"SURFACE_AUTH"}:
            return ValidationResult(
                validation_status="REVISAR_MANUALMENTE",
                validation_severity="LOW",
                confidence=70,
                reason="Área de autenticação ou conta identificada. Não é falha isolada, mas é ponto sensível de abuso, enumeração e tentativas repetidas.",
                action="Revisar rate limit, bloqueios progressivos, mensagens de erro genéricas, MFA quando aplicável e monitoramento de tentativas.",
                evidence_safe=evidence_safe,
            )

        if category in {"SURFACE_WAF"}:
            return ValidationResult(
                validation_status="INFORMATIVO",
                validation_severity="INFO",
                confidence=80,
                reason="WAF/CDN identificado. Isso normalmente reduz exposição direta, mas exige revisão de regras, rate limit e proteção de rotas sensíveis.",
                action="Manter WAF/CDN ativo, revisar regras de segurança e proteger login, cadastro, checkout e recuperação de senha.",
                evidence_safe=evidence_safe,
            )

        if category in {"SURFACE_CDN"}:
            return ValidationResult(
                validation_status="INFORMATIVO",
                validation_severity="INFO",
                confidence=80,
                reason="Asset público em CDN/storage identificado. Em e-commerce e Shopify isso geralmente é esperado e não representa falha isoladamente.",
                action="Confirmar que apenas arquivos públicos estão expostos e que não existem backups, dumps, exports ou dados privados no storage.",
                evidence_safe=evidence_safe,
            )

        if category in {"SURFACE_HEADER"}:
            return ValidationResult(
                validation_status="INFORMATIVO",
                validation_severity="INFO",
                confidence=75,
                reason="Header ou metadado público observado. Normalmente é informação operacional, mas pode ajudar a revisar cache, CDN e políticas de segurança.",
                action="Revisar HSTS, CSP, X-Frame-Options, cache, CORS e headers gerenciados pelo CDN/plataforma.",
                evidence_safe=evidence_safe,
            )

        if category in {"SURFACE_SCRIPT"}:
            return ValidationResult(
                validation_status="INFORMATIVO",
                validation_severity="INFO",
                confidence=75,
                reason="Script público ou rastreador identificado. Isso é comum, mas scripts de terceiros influenciam privacidade, performance e superfície de supply chain.",
                action="Revisar origem dos scripts, necessidade, permissões, política de privacidade e impacto em segurança.",
                evidence_safe=evidence_safe,
            )

        if category in {"SURFACE_HTTP", "HTTP"}:
            return ValidationResult(
                validation_status="INFORMATIVO",
                validation_severity="INFO",
                confidence=70,
                reason="Resposta HTTP observada. Pode indicar bloqueio, regra de WAF/CDN ou comportamento esperado.",
                action="Validar se respostas 403/401/404 são esperadas e se áreas sensíveis estão corretamente protegidas.",
                evidence_safe=evidence_safe,
            )

        if category in SURFACE_CATEGORIES:
            return ValidationResult(
                validation_status="INFORMATIVO",
                validation_severity="INFO",
                confidence=65,
                reason="Achado classificado como superfície pública. Não há evidência suficiente para tratar como vulnerabilidade real.",
                action="Registrar como contexto técnico e revisar necessidade de exposição.",
                evidence_safe=evidence_safe,
            )

        return ValidationResult(
            validation_status="REVISAR_MANUALMENTE",
            validation_severity=str(item.get("severity", "LOW")),
            confidence=55,
            reason="Achado fora das categorias conhecidas. Precisa de revisão humana antes de entrar em relatório final como risco.",
            action="Validar evidência, impacto, contexto e possibilidade de falso positivo.",
            evidence_safe=evidence_safe,
        )

    def validate_token(self, item: Dict[str, Any], force_real_context: bool = False) -> ValidationResult:
        evidence = str(item.get("evidence", ""))
        title = str(item.get("title", ""))
        evidence_safe = self.mask_evidence(evidence)

        jwt = self.extract_jwt(evidence)

        if not jwt:
            return ValidationResult(
                validation_status="INFORMATIVO",
                validation_severity="INFO",
                confidence=70,
                reason="Token ou estado codificado observado, mas sem estrutura JWT completa confirmada.",
                action="Validar se o parâmetro contém apenas estado de aplicação e evitar dados sensíveis em URL.",
                evidence_safe=evidence_safe,
            )

        header, payload = self.decode_jwt(jwt)
        sensitive_hits = self.find_sensitive_keys(payload)
        issuer = str(payload.get("iss", "")).lower() if isinstance(payload, dict) else ""

        strong_auth_context = bool(
            re.search(r"(authorization|bearer|access[_-]?token|id[_-]?token|refresh[_-]?token)", evidence, re.I)
        )

        if sensitive_hits:
            return ValidationResult(
                validation_status="REVISAR_MANUALMENTE",
                validation_severity="MEDIUM",
                confidence=80,
                reason=f"JWT-like decodificado localmente contém possíveis campos sensíveis: {', '.join(sorted(sensitive_hits))}.",
                action="Validar se o conteúdo pode ser exposto em URL/logs. Remover dados sensíveis e usar armazenamento seguro quando aplicável.",
                evidence_safe=evidence_safe,
                promoted_to_real_risk=True,
            )

        if strong_auth_context or force_real_context:
            return ValidationResult(
                validation_status="SUSPEITO_FORTE",
                validation_severity="HIGH",
                confidence=75,
                reason="JWT completo observado em contexto de autenticação ou categoria de risco. Não foi reutilizado nem testado; requer validação controlada.",
                action="Confirmar validade, escopo, expiração e exposição em logs. Rotacionar se for token sensível.",
                evidence_safe=evidence_safe,
                promoted_to_real_risk=True,
            )

        if "shopify" in issuer or "myshopify" in evidence.lower() or "buyer_flags" in evidence.lower():
            return ValidationResult(
                validation_status="INFORMATIVO",
                validation_severity="INFO",
                confidence=85,
                reason="Token JWT-like parece representar estado de plataforma/Shopify, sem dados sensíveis observados na decodificação local.",
                action="Registrar como superfície. Confirmar que não há PII no token e evitar logs desnecessários de URL.",
                evidence_safe=evidence_safe,
            )

        return ValidationResult(
            validation_status="REVISAR_MANUALMENTE",
            validation_severity="LOW",
            confidence=70,
            reason="JWT-like completo observado fora de contexto forte. Sem dados sensíveis aparentes, mas deve ser revisado.",
            action="Validar conteúdo, expiração, emissor e necessidade de exposição em URL.",
            evidence_safe=evidence_safe,
        )

    def validate_api(self, item: Dict[str, Any]) -> ValidationResult:
        evidence = str(item.get("evidence", ""))
        ev_lower = evidence.lower()
        evidence_safe = self.mask_evidence(evidence)

        if any(x in ev_lower for x in ["shopify", "myshopify", "cdn.shopify.com", "shopifycloud"]):
            return ValidationResult(
                validation_status="INFORMATIVO",
                validation_severity="INFO",
                confidence=85,
                reason="API ou referência associada à plataforma Shopify. Geralmente é esperado em e-commerce e não representa falha isoladamente.",
                action="Validar permissões, CORS, rate limit e se APIs públicas não retornam dados sensíveis.",
                evidence_safe=evidence_safe,
            )

        if "/graphql" in ev_lower:
            return ValidationResult(
                validation_status="REVISAR_MANUALMENTE",
                validation_severity="LOW",
                confidence=75,
                reason="Endpoint GraphQL identificado. A existência do endpoint não é falha, mas introspection pública, CORS indevido ou dados sem autenticação podem ser relevantes.",
                action="Validar autenticação, introspection, CORS, rate limit e exposição de dados usando escopo autorizado.",
                evidence_safe=evidence_safe,
            )

        if "/api/" in ev_lower:
            return ValidationResult(
                validation_status="REVISAR_MANUALMENTE",
                validation_severity="LOW",
                confidence=70,
                reason="Endpoint de API identificado. Precisa validar se exige autenticação, se possui rate limit e se não retorna dados sensíveis.",
                action="Testar com requisições seguras e autorizadas: status, autenticação, CORS, resposta e dados retornados.",
                evidence_safe=evidence_safe,
            )

        return ValidationResult(
            validation_status="INFORMATIVO",
            validation_severity="INFO",
            confidence=65,
            reason="Referência de API genérica observada sem evidência de exposição indevida.",
            action="Registrar como superfície e revisar somente se houver resposta pública com dados.",
            evidence_safe=evidence_safe,
        )

    def validate_port(self, item: Dict[str, Any]) -> ValidationResult:
        evidence = str(item.get("evidence", ""))
        evidence_safe = self.mask_evidence(evidence)

        ports = re.findall(r"\b([0-9]{2,5})/tcp\s+open\b|\b:([0-9]{2,5})\b", evidence)
        flat_ports = []
        for a, b in ports:
            if a:
                flat_ports.append(a)
            if b:
                flat_ports.append(b)

        if not flat_ports and "tcp open" in evidence.lower():
            return ValidationResult(
                validation_status="REVISAR_MANUALMENTE",
                validation_severity="LOW",
                confidence=60,
                reason="Porta aberta identificada, mas a evidência está genérica. Precisa revisar o arquivo de origem para saber a porta exata.",
                action="Verificar nmap/naabu completo e confirmar serviço, origem e necessidade de exposição.",
                evidence_safe=evidence_safe,
            )

        expected = {"80", "443"}
        review = {"8080", "8443", "8000", "8888", "3000", "5000", "9000"}

        if flat_ports and all(p in expected for p in flat_ports):
            return ValidationResult(
                validation_status="INFORMATIVO",
                validation_severity="INFO",
                confidence=85,
                reason="Portas web padrão identificadas. Para site público, 80/443 geralmente são esperadas.",
                action="Manter redirecionamento HTTP→HTTPS, TLS atualizado e WAF/CDN ativo.",
                evidence_safe=evidence_safe,
            )

        if any(p in review for p in flat_ports):
            return ValidationResult(
                validation_status="REVISAR_MANUALMENTE",
                validation_severity="LOW",
                confidence=75,
                reason=f"Portas alternativas identificadas: {', '.join(flat_ports)}. Podem ser esperadas por CDN/plataforma, mas merecem validação.",
                action="Confirmar se pertencem ao provedor/CDN ou à origem real. Restringir portas administrativas quando aplicável.",
                evidence_safe=evidence_safe,
            )

        return ValidationResult(
            validation_status="REVISAR_MANUALMENTE",
            validation_severity="LOW",
            confidence=65,
            reason=f"Portas identificadas: {', '.join(flat_ports) if flat_ports else 'não extraídas'}. Necessário confirmar serviço e exposição.",
            action="Validar necessidade de exposição pública e aplicar firewall/allowlist se necessário.",
            evidence_safe=evidence_safe,
        )

    def build_summary(self, validated: List[Dict[str, Any]], insights: List[Dict[str, Any]]) -> Dict[str, Any]:
        total = len(validated)

        by_status = Counter()
        by_severity = Counter()
        by_category = Counter()
        by_action = Counter()

        promoted = 0
        manual_review = 0
        informational = 0

        for item in validated:
            b14 = item.get("block14", {})
            status = b14.get("validation_status", "UNKNOWN")
            severity = b14.get("validation_severity", "UNKNOWN")
            category = str(item.get("category", "UNKNOWN")).upper()

            by_status[status] += 1
            by_severity[severity] += 1
            by_category[category] += 1

            if b14.get("promoted_to_real_risk"):
                promoted += 1

            if status == "REVISAR_MANUALMENTE":
                manual_review += 1

            if status == "INFORMATIVO":
                informational += 1

        if promoted > 0:
            validation_level = "HIGH"
        elif manual_review >= 10:
            validation_level = "MEDIUM"
        elif manual_review > 0:
            validation_level = "LOW"
        else:
            validation_level = "INFO"

        return {
            "total_validated": total,
            "promoted_real_risk": promoted,
            "manual_review": manual_review,
            "informational": informational,
            "validation_level": validation_level,
            "by_validation_status": dict(by_status),
            "by_validation_severity": dict(by_severity),
            "by_category": dict(by_category),
            "insight_count": len(insights),
        }

    def build_insights(self, validated: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        groups = defaultdict(list)

        for item in validated:
            category = str(item.get("category", "UNKNOWN")).upper()
            groups[category].append(item)

        insights = []

        if groups.get("SURFACE_TOKEN"):
            count = len(groups["SURFACE_TOKEN"])
            manual = sum(1 for x in groups["SURFACE_TOKEN"] if x.get("block14", {}).get("validation_status") == "REVISAR_MANUALMENTE")
            insights.append({
                "id": "token_url_state",
                "title": "Tokens ou estados codificados em URLs",
                "severity": "LOW" if manual else "INFO",
                "count": count,
                "finding": f"Foram observadas {count} ocorrências de tokens/estados codificados em URLs. A validação local não confirma vulnerabilidade isolada.",
                "impact": "Podem gerar exposição em logs, analytics, histórico do navegador ou ferramentas de terceiros se carregarem dados sensíveis.",
                "recommendation": "Confirmar que os tokens não carregam PII, evitar dados sensíveis em URL e preferir cookies seguros quando aplicável.",
            })

        if groups.get("SURFACE_API"):
            count = len(groups["SURFACE_API"])
            insights.append({
                "id": "api_surface",
                "title": "Superfície de APIs e GraphQL",
                "severity": "LOW",
                "count": count,
                "finding": f"Foram identificadas {count} referências a APIs, GraphQL ou endpoints de plataforma.",
                "impact": "A existência de APIs é esperada, mas autenticação, autorização, CORS e rate limit devem ser validados.",
                "recommendation": "Validar se endpoints públicos não retornam dados sensíveis, se GraphQL não expõe introspection indevida e se há rate limit.",
            })

        if groups.get("SURFACE_PORT"):
            count = len(groups["SURFACE_PORT"])
            insights.append({
                "id": "port_surface",
                "title": "Portas e serviços públicos",
                "severity": "LOW",
                "count": count,
                "finding": f"Foram identificadas {count} evidências relacionadas a portas abertas ou serviços expostos.",
                "impact": "Portas web padrão podem ser esperadas; portas alternativas exigem confirmação de origem e necessidade.",
                "recommendation": "Validar 8080/8443 e outras portas não padrão, confirmar se pertencem ao provedor/CDN e restringir serviços administrativos.",
            })

        if groups.get("SURFACE_WAF"):
            count = len(groups["SURFACE_WAF"])
            insights.append({
                "id": "waf_cdn",
                "title": "WAF/CDN detectado",
                "severity": "INFO",
                "count": count,
                "finding": "Foi identificado uso de WAF/CDN, incluindo indicadores de Cloudflare.",
                "impact": "Ajuda a reduzir exposição direta, mas regras precisam cobrir rotas sensíveis.",
                "recommendation": "Manter WAF/CDN ativo e revisar regras para login, cadastro, checkout e recuperação de senha.",
            })

        if groups.get("SURFACE_CDN"):
            count = len(groups["SURFACE_CDN"])
            insights.append({
                "id": "cdn_assets",
                "title": "Assets públicos e scripts de plataforma",
                "severity": "INFO",
                "count": count,
                "finding": f"Foram observados {count} assets públicos em CDN/storage.",
                "impact": "Normal em e-commerce, mas pode indicar dependência de apps de terceiros e superfície de supply chain.",
                "recommendation": "Revisar apps/extensões carregadas, remover integrações desnecessárias e confirmar ausência de arquivos sensíveis no storage.",
            })

        if groups.get("SURFACE_AUTH"):
            count = len(groups["SURFACE_AUTH"])
            insights.append({
                "id": "auth_surface",
                "title": "Áreas de autenticação e conta",
                "severity": "LOW",
                "count": count,
                "finding": f"Foram identificadas {count} referências a login, conta ou área de cliente.",
                "impact": "Áreas de autenticação são alvos comuns para abuso, enumeração e tentativas repetidas.",
                "recommendation": "Aplicar rate limit, mensagens genéricas, monitoramento, bloqueio progressivo e MFA quando aplicável.",
            })

        if groups.get("SURFACE_HEADER"):
            count = len(groups["SURFACE_HEADER"])
            insights.append({
                "id": "headers_metadata",
                "title": "Headers e metadados públicos",
                "severity": "INFO",
                "count": count,
                "finding": f"Foram observadas {count} evidências de headers/metadados públicos.",
                "impact": "Podem revelar comportamento de cache/CDN ou políticas incompletas.",
                "recommendation": "Revisar HSTS, CSP, X-Frame-Options, CORS, cache e headers gerenciados pelo provedor.",
            })

        return insights

    def render_technical_report(
        self,
        summary: Dict[str, Any],
        insights: List[Dict[str, Any]],
        validated: List[Dict[str, Any]],
    ) -> str:
        lines = []
        lines.append("# CyberLab - Bloco 14 Validation Intelligence")
        lines.append("")
        lines.append(f"**Alvo:** {self.target}")
        lines.append(f"**Pasta analisada:** `{self.scan_dir}`")
        lines.append(f"**Gerado em:** {datetime.now().isoformat(timespec='seconds')}")
        lines.append("")
        lines.append("## Objetivo")
        lines.append("")
        lines.append("Validar os achados do Bloco 12, reduzir ruído, separar superfície de risco real e gerar interpretação útil para decisão.")
        lines.append("")
        lines.append("## Resumo de validação")
        lines.append("")
        lines.append(f"- Total validado: **{summary.get('total_validated')}**")
        lines.append(f"- Promovidos a risco real: **{summary.get('promoted_real_risk')}**")
        lines.append(f"- Revisão manual: **{summary.get('manual_review')}**")
        lines.append(f"- Informativos: **{summary.get('informational')}**")
        lines.append(f"- Nível de validação: **{summary.get('validation_level')}**")
        lines.append("")
        lines.append("### Por status")
        lines.append("")
        for key, value in summary.get("by_validation_status", {}).items():
            lines.append(f"- **{key}:** {value}")
        lines.append("")
        lines.append("### Por categoria")
        lines.append("")
        for key, value in summary.get("by_category", {}).items():
            lines.append(f"- **{key}:** {value}")

        lines.append("")
        lines.append("## Insights consolidados")
        lines.append("")
        for idx, insight in enumerate(insights, start=1):
            lines.append(f"### {idx}. {insight.get('title')}")
            lines.append("")
            lines.append(f"- **Severidade:** {insight.get('severity')}")
            lines.append(f"- **Ocorrências:** {insight.get('count')}")
            lines.append(f"- **Leitura:** {insight.get('finding')}")
            lines.append(f"- **Impacto:** {insight.get('impact')}")
            lines.append(f"- **Recomendação:** {insight.get('recommendation')}")
            lines.append("")

        lines.append("## Amostras validadas")
        lines.append("")
        for idx, item in enumerate(validated[:80], start=1):
            b14 = item.get("block14", {})
            lines.append(f"### {idx}. {item.get('title', '-')}")
            lines.append("")
            lines.append(f"- **Categoria original:** {item.get('category', '-')}")
            lines.append(f"- **Severidade original:** {item.get('severity', '-')}")
            lines.append(f"- **Origem:** {item.get('source_type', item.get('origin', '-'))}")
            lines.append(f"- **Validação:** {b14.get('validation_status')}")
            lines.append(f"- **Severidade validada:** {b14.get('validation_severity')}")
            lines.append(f"- **Confiança:** {b14.get('confidence')}")
            lines.append(f"- **Evidência segura:** `{b14.get('evidence_safe')}`")
            lines.append("")
            lines.append("**Razão:**")
            lines.append("")
            lines.append(b14.get("reason", "-"))
            lines.append("")
            lines.append("**Ação recomendada:**")
            lines.append("")
            lines.append(b14.get("recommended_action", "-"))
            lines.append("")

        return "\n".join(lines)

    def render_client_summary(self, summary: Dict[str, Any], insights: List[Dict[str, Any]]) -> str:
        promoted = summary.get("promoted_real_risk", 0)
        manual = summary.get("manual_review", 0)
        level = summary.get("validation_level", "INFO")

        lines = []
        lines.append("# Resumo de Validação - CyberLab Bloco 14")
        lines.append("")
        lines.append(f"**Alvo:** {self.target}")
        lines.append(f"**Gerado em:** {datetime.now().isoformat(timespec='seconds')}")
        lines.append("")
        lines.append("## Leitura executiva")
        lines.append("")

        if promoted == 0:
            lines.append("Não foram promovidos achados automatizados para risco real confirmado nesta etapa de validação.")
        else:
            lines.append(f"Foram identificados {promoted} achado(s) que exigem tratativa prioritária por possível impacto real.")

        lines.append("")
        lines.append(f"Foram identificados **{manual}** pontos para revisão manual e **{summary.get('informational')}** itens informativos.")
        lines.append(f"O nível de validação ficou como **{level}**.")
        lines.append("")
        lines.append("## Principais pontos")
        lines.append("")

        for insight in insights:
            lines.append(f"- **{insight.get('title')}**: {insight.get('finding')}")

        lines.append("")
        lines.append("## Recomendações principais")
        lines.append("")
        for insight in insights:
            lines.append(f"- {insight.get('recommendation')}")

        lines.append("")
        lines.append("## Conclusão")
        lines.append("")
        lines.append("A análise indica que o ambiente possui superfície pública típica de e-commerce, com dependência de plataforma, CDN, APIs, scripts e rotas sensíveis. A prioridade é revisar controles preventivos, reduzir exposição desnecessária e validar manualmente pontos sensíveis como APIs, autenticação e portas alternativas.")
        return "\n".join(lines)

    def render_pdf(self, pdf_path: Path, summary: Dict[str, Any], insights: List[Dict[str, Any]]) -> None:
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        except Exception:
            pdf_path.write_text(
                "PDF não gerado: reportlab não disponível no ambiente.\n",
                encoding="utf-8",
            )
            return

        doc = SimpleDocTemplate(str(pdf_path), pagesize=A4)
        styles = getSampleStyleSheet()
        story = []

        story.append(Paragraph("CyberLab - Bloco 14 Validation Intelligence", styles["Title"]))
        story.append(Spacer(1, 12))
        story.append(Paragraph(f"<b>Alvo:</b> {self.target}", styles["Normal"]))
        story.append(Paragraph(f"<b>Gerado em:</b> {datetime.now().isoformat(timespec='seconds')}", styles["Normal"]))
        story.append(Spacer(1, 12))

        story.append(Paragraph("Resumo de validação", styles["Heading2"]))
        story.append(Paragraph(f"Total validado: {summary.get('total_validated')}", styles["Normal"]))
        story.append(Paragraph(f"Promovidos a risco real: {summary.get('promoted_real_risk')}", styles["Normal"]))
        story.append(Paragraph(f"Revisão manual: {summary.get('manual_review')}", styles["Normal"]))
        story.append(Paragraph(f"Informativos: {summary.get('informational')}", styles["Normal"]))
        story.append(Paragraph(f"Nível de validação: {summary.get('validation_level')}", styles["Normal"]))
        story.append(Spacer(1, 12))

        story.append(Paragraph("Insights consolidados", styles["Heading2"]))

        for insight in insights:
            story.append(Paragraph(str(insight.get("title")), styles["Heading3"]))
            story.append(Paragraph(f"<b>Severidade:</b> {insight.get('severity')}", styles["Normal"]))
            story.append(Paragraph(f"<b>Ocorrências:</b> {insight.get('count')}", styles["Normal"]))
            story.append(Paragraph(f"<b>Leitura:</b> {insight.get('finding')}", styles["Normal"]))
            story.append(Paragraph(f"<b>Impacto:</b> {insight.get('impact')}", styles["Normal"]))
            story.append(Paragraph(f"<b>Recomendação:</b> {insight.get('recommendation')}", styles["Normal"]))
            story.append(Spacer(1, 10))

        doc.build(story)

    def extract_jwt(self, text: str) -> Optional[str]:
        match = re.search(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", text)
        if match:
            return match.group(0)
        return None

    def decode_jwt(self, jwt: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        try:
            parts = jwt.split(".")
            if len(parts) != 3:
                return {}, {}

            header = json.loads(self.b64url_decode(parts[0]))
            payload = json.loads(self.b64url_decode(parts[1]))

            if not isinstance(header, dict):
                header = {}
            if not isinstance(payload, dict):
                payload = {}

            return header, payload
        except Exception:
            return {}, {}

    def b64url_decode(self, value: str) -> str:
        value = value.strip()
        padding = "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode((value + padding).encode()).decode("utf-8", errors="replace")

    def find_sensitive_keys(self, obj: Any) -> set:
        hits = set()

        def walk(value: Any, prefix: str = ""):
            if isinstance(value, dict):
                for k, v in value.items():
                    key = str(k).lower()
                    if key in SENSITIVE_KEYS:
                        hits.add(key)
                    walk(v, key)
            elif isinstance(value, list):
                for item in value:
                    walk(item, prefix)

        walk(obj)
        return hits

    def mask_evidence(self, evidence: str) -> str:
        if not evidence:
            return "-"

        masked = evidence.strip()

        masked = re.sub(
            r"(eyJ[A-Za-z0-9_-]{8,})\.([A-Za-z0-9_-]{8,})\.([A-Za-z0-9_-]{8,})",
            lambda m: f"{m.group(1)[:10]}...{m.group(3)[-6:]}",
            masked,
        )

        masked = re.sub(
            r"([?&](?:token|access_token|id_token|refresh_token|session|state|buyer_flags)=)[^&\s]+",
            r"\1[MASKED]",
            masked,
            flags=re.I,
        )

        if len(masked) > 220:
            masked = masked[:220] + "...[truncated]"

        return masked


def find_latest_scan(target: str, base: Optional[Path] = None) -> Path:
    base = base or Path.home() / "CyberLab" / "results" / "web" / target

    if not base.exists():
        raise FileNotFoundError(f"Pasta do alvo não encontrada: {base}")

    scans = sorted([p for p in base.iterdir() if p.is_dir()], key=lambda p: p.stat().st_mtime, reverse=True)

    if not scans:
        raise FileNotFoundError(f"Nenhum scan encontrado em: {base}")

    return scans[0]
