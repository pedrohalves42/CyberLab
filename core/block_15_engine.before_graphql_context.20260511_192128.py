#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CyberLab - Bloco 15 Controlled Offensive Validation

Objetivo:
- Validar impacto real de forma segura e controlada.
- Fazer checks ativos leves em APIs, GraphQL, CORS, headers, storage/CDN e tokens.
- Não executar brute force, bypass, exploração destrutiva, alteração de dados ou fuzzing agressivo.
- Promover somente evidências com impacto técnico claro.

Modo:
- Leitura local de Bloco 12 e Bloco 14.
- Requisições HTTP controladas: GET/HEAD/OPTIONS/POST benigno para GraphQL.
- Timeout curto.
- Rate básico.
- Máximo de alvos por categoria.
- Sem payload destrutivo.
"""

from __future__ import annotations

import base64
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


SAFE_USER_AGENT = "CyberLab-Controlled-Validation/15.0"
DEFAULT_TIMEOUT = 8
MAX_API_CHECKS = 25
MAX_STORAGE_CHECKS = 25
MAX_TOKEN_CHECKS = 30
MAX_AUTH_CHECKS = 20
MAX_TOTAL_REQUESTS = 80
REQUEST_DELAY = 0.35

SENSITIVE_KEYS = {
    "email",
    "mail",
    "e-mail",
    "phone",
    "telefone",
    "cpf",
    "cnpj",
    "document",
    "documento",
    "address",
    "endereco",
    "endereço",
    "customer",
    "customer_id",
    "cliente",
    "user",
    "user_id",
    "name",
    "nome",
    "first_name",
    "last_name",
    "payment",
    "card",
    "cartao",
    "cartão",
    "order",
    "pedido",
    "orders",
    "birth",
    "birthday",
    "nascimento",
    "cep",
    "postal",
}

SURFACE_CATEGORIES = {
    "SURFACE_TOKEN",
    "SURFACE_API",
    "SURFACE_CDN",
    "SURFACE_PORT",
    "SURFACE_WAF",
    "SURFACE_HTTP",
    "SURFACE_HEADER",
    "SURFACE_SCRIPT",
    "SURFACE_AUTH",
    "SURFACE_TECH",
}


@dataclass
class SafeHttpResult:
    url: str
    method: str
    status: Optional[int]
    content_type: str
    content_length: Optional[int]
    headers: Dict[str, str]
    body_sample: str
    error: str
    elapsed_ms: int


@dataclass
class ValidationOutcome:
    validator: str
    target: str
    status: str
    severity: str
    confidence: int
    impact: str
    evidence: str
    recommendation: str
    request_count: int = 0
    promoted: bool = False


class ControlledHttpClient:
    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        self.timeout = timeout
        self.request_count = 0

    def request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
    ) -> SafeHttpResult:
        self.request_count += 1
        start = time.time()

        base_headers = {
            "User-Agent": SAFE_USER_AGENT,
            "Accept": "text/html,application/json,text/plain,*/*",
        }

        if headers:
            base_headers.update(headers)

        req = urllib.request.Request(
            url=url,
            data=body,
            headers=base_headers,
            method=method,
        )

        ctx = ssl.create_default_context()

        status = None
        resp_headers: Dict[str, str] = {}
        content_type = ""
        content_length: Optional[int] = None
        body_sample = ""
        error = ""

        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                status = resp.getcode()
                resp_headers = {str(k).lower(): str(v) for k, v in resp.headers.items()}
                content_type = resp_headers.get("content-type", "")
                raw_len = resp_headers.get("content-length", "")
                if raw_len.isdigit():
                    content_length = int(raw_len)

                if method.upper() != "HEAD":
                    raw = resp.read(4096)
                    body_sample = raw.decode("utf-8", errors="replace")[:2000]

        except urllib.error.HTTPError as e:
            status = e.code
            resp_headers = {str(k).lower(): str(v) for k, v in e.headers.items()} if e.headers else {}
            content_type = resp_headers.get("content-type", "")
            raw_len = resp_headers.get("content-length", "")
            if raw_len.isdigit():
                content_length = int(raw_len)

            try:
                raw = e.read(4096)
                body_sample = raw.decode("utf-8", errors="replace")[:2000]
            except Exception:
                body_sample = ""

        except Exception as e:
            error = str(e)

        elapsed_ms = int((time.time() - start) * 1000)

        time.sleep(REQUEST_DELAY)

        return SafeHttpResult(
            url=url,
            method=method,
            status=status,
            content_type=content_type,
            content_length=content_length,
            headers=resp_headers,
            body_sample=body_sample,
            error=error,
            elapsed_ms=elapsed_ms,
        )


class Block15ControlledValidationEngine:
    def __init__(self, scan_dir: Path, target: str, mode: str = "controlled"):
        self.scan_dir = scan_dir
        self.target = target
        self.mode = mode
        self.output_dir = self.scan_dir / "block_15_controlled_validation"
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.block12_path = self.scan_dir / "block_12_intelligence" / "block_12_findings.json"
        self.block14_path = self.scan_dir / "block_14_validation" / "block_14_validated_findings.json"
        self.block14_insights_path = self.scan_dir / "block_14_validation" / "block_14_insights.json"

        self.http = ControlledHttpClient()
        self.total_requests = 0

    def run(self) -> Dict[str, Path]:
        findings = self.load_findings()

        candidates = self.extract_candidates(findings)

        outcomes: List[Dict[str, Any]] = []

        outcomes.extend(self.validate_tokens(candidates.get("tokens", [])))
        outcomes.extend(self.validate_apis(candidates.get("apis", [])))
        outcomes.extend(self.validate_graphql(candidates.get("graphql", [])))
        outcomes.extend(self.validate_cors_headers(candidates.get("urls", [])))
        outcomes.extend(self.validate_storage(candidates.get("storage", [])))
        outcomes.extend(self.validate_auth_surface(candidates.get("auth", [])))
        outcomes.extend(self.validate_ports(candidates.get("ports", [])))

        outcomes = self.dedup_outcomes(outcomes)

        confirmed = [x for x in outcomes if x.get("promoted") is True]
        manual = [x for x in outcomes if x.get("status") == "REVISAR_MANUALMENTE"]
        info = [x for x in outcomes if x.get("status") == "INFORMATIVO"]

        summary = self.build_summary(outcomes, confirmed, manual, info, candidates)

        paths = {
            "validations": self.output_dir / "block_15_validations.json",
            "confirmed_findings": self.output_dir / "block_15_confirmed_findings.json",
            "impact_report": self.output_dir / "block_15_impact_report.md",
            "client_summary": self.output_dir / "block_15_client_summary.md",
            "manual_tests": self.output_dir / "block_15_manual_tests.md",
            "pdf": self.output_dir / "block_15_impact_report.pdf",
            "status": self.output_dir / "block_15_status.json",
        }

        payload = {
            "block": "15",
            "module": "Controlled Offensive Validation",
            "target": self.target,
            "scan_dir": str(self.scan_dir),
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "mode": self.mode,
            "policy": self.policy(),
            "summary": summary,
            "candidates": {k: len(v) for k, v in candidates.items()},
            "validations": outcomes,
        }

        confirmed_payload = {
            "block": "15",
            "module": "Confirmed Findings",
            "target": self.target,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "summary": {
                "confirmed_count": len(confirmed),
                "manual_review_count": len(manual),
                "informational_count": len(info),
            },
            "confirmed_findings": confirmed,
            "manual_review": manual,
        }

        status_payload = {
            "block": "15",
            "module": "Controlled Offensive Validation",
            "target": self.target,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "status": "OK",
            "input": {
                "block12": str(self.block12_path),
                "block14": str(self.block14_path),
            },
            "output_dir": str(self.output_dir),
            "summary": summary,
            "files": {k: str(v) for k, v in paths.items()},
        }

        paths["validations"].write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        paths["confirmed_findings"].write_text(json.dumps(confirmed_payload, ensure_ascii=False, indent=2), encoding="utf-8")
        paths["impact_report"].write_text(self.render_impact_report(summary, outcomes), encoding="utf-8")
        paths["client_summary"].write_text(self.render_client_summary(summary, outcomes), encoding="utf-8")
        paths["manual_tests"].write_text(self.render_manual_tests(summary, outcomes), encoding="utf-8")
        paths["status"].write_text(json.dumps(status_payload, ensure_ascii=False, indent=2), encoding="utf-8")

        self.render_pdf(paths["pdf"], summary, outcomes)

        return paths

    def policy(self) -> Dict[str, Any]:
        return {
            "destructive_payloads": False,
            "bruteforce": False,
            "credential_stuffing": False,
            "auth_bypass": False,
            "data_modification": False,
            "mass_download": False,
            "dos_or_stress": False,
            "max_total_requests": MAX_TOTAL_REQUESTS,
            "timeout_seconds": DEFAULT_TIMEOUT,
            "request_delay_seconds": REQUEST_DELAY,
            "allowed_methods": ["GET", "HEAD", "OPTIONS", "POST_GRAPHQL_BENIGN"],
        }

    def load_findings(self) -> List[Dict[str, Any]]:
        source = None

        if self.block14_path.exists():
            data = json.loads(self.block14_path.read_text(encoding="utf-8"))
            source = data.get("findings", [])
            return source

        if self.block12_path.exists():
            data = json.loads(self.block12_path.read_text(encoding="utf-8"))
            source = data.get("findings") or data.get("items") or []
            return source

        raise FileNotFoundError("Nem Bloco 14 nem Bloco 12 encontrados para validação.")

    def extract_candidates(self, findings: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        candidates = {
            "tokens": [],
            "apis": [],
            "graphql": [],
            "urls": [],
            "storage": [],
            "auth": [],
            "ports": [],
        }

        for item in findings:
            category = str(item.get("category", "")).upper()
            evidence = str(item.get("evidence", ""))
            file_path = str(item.get("file", ""))
            title = str(item.get("title", ""))

            merged = " ".join([evidence, file_path, title])

            for url in self.extract_urls_from_text(merged):
                candidates["urls"].append(url)

                if self.is_api_url(url):
                    candidates["apis"].append(url)

                if "graphql" in url.lower():
                    candidates["graphql"].append(url)

                if self.is_storage_url(url):
                    candidates["storage"].append(url)

                if self.is_auth_url(url):
                    candidates["auth"].append(url)

            if category in {"SURFACE_TOKEN", "JWT", "TOKEN", "SECRET"}:
                candidates["tokens"].append(evidence)

            if category in {"SURFACE_API", "API"}:
                for url in self.extract_urls_from_file_or_evidence(item):
                    candidates["apis"].append(url)
                    if "graphql" in url.lower():
                        candidates["graphql"].append(url)

            if category in {"SURFACE_CDN", "BUCKET"}:
                for url in self.extract_urls_from_file_or_evidence(item):
                    if self.is_storage_url(url):
                        candidates["storage"].append(url)

            if category in {"SURFACE_AUTH"}:
                for url in self.extract_urls_from_file_or_evidence(item):
                    candidates["auth"].append(url)

            if category in {"SURFACE_PORT", "PORT"}:
                candidates["ports"].append(evidence)

        # Dedup com preservação de ordem
        for key in candidates:
            candidates[key] = self.dedup(candidates[key])

        candidates["apis"] = candidates["apis"][:MAX_API_CHECKS]
        candidates["graphql"] = candidates["graphql"][:MAX_API_CHECKS]
        candidates["storage"] = candidates["storage"][:MAX_STORAGE_CHECKS]
        candidates["tokens"] = candidates["tokens"][:MAX_TOKEN_CHECKS]
        candidates["auth"] = candidates["auth"][:MAX_AUTH_CHECKS]
        candidates["urls"] = candidates["urls"][:25]
        candidates["ports"] = candidates["ports"][:25]

        return candidates

    def extract_urls_from_file_or_evidence(self, item: Dict[str, Any]) -> List[str]:
        urls = []

        evidence = str(item.get("evidence", ""))
        urls.extend(self.extract_urls_from_text(evidence))

        file_path = item.get("file")
        if file_path:
            p = Path(str(file_path))
            try:
                if p.exists() and p.is_file() and p.stat().st_size < 3_000_000:
                    content = p.read_text(encoding="utf-8", errors="replace")
                    urls.extend(self.extract_urls_from_text(content))
            except Exception:
                pass

        return self.dedup(urls)

    def extract_urls_from_text(self, text: str) -> List[str]:
        if not text:
            return []
        urls = re.findall(r"https?://[^\s\"'<>]+", text)
        clean = []
        for url in urls:
            url = url.rstrip(").,;]}")
            if self.target in url or "shopify" in url.lower() or "amazonaws.com" in url.lower() or "cloudfront.net" in url.lower():
                clean.append(url)
        return clean

    def validate_tokens(self, tokens: List[str]) -> List[Dict[str, Any]]:
        outcomes = []

        for raw in tokens:
            jwt = self.extract_jwt(raw)

            if not jwt:
                outcomes.append(self.outcome(
                    validator="15D Token Deep Validation",
                    target=self.mask(raw),
                    status="INFORMATIVO",
                    severity="INFO",
                    confidence=70,
                    impact="Token ou estado codificado observado, mas sem estrutura JWT completa confirmada.",
                    evidence=self.mask(raw),
                    recommendation="Confirmar que parâmetros de URL não carregam PII e evitar dados sensíveis em links/logs.",
                ))
                continue

            header, payload = self.decode_jwt(jwt)
            sensitive = self.find_sensitive_keys(payload)
            issuer = str(payload.get("iss", "")).lower() if isinstance(payload, dict) else ""
            has_exp = "exp" in payload if isinstance(payload, dict) else False

            if sensitive:
                outcomes.append(self.outcome(
                    validator="15D Token Deep Validation",
                    target="JWT-like token",
                    status="CONFIRMADO_POTENCIAL",
                    severity="MEDIUM",
                    confidence=85,
                    impact=f"Token decodificado localmente contém possíveis campos sensíveis: {', '.join(sorted(sensitive))}.",
                    evidence=self.safe_json_sample(payload),
                    recommendation="Remover PII de URLs/tokens expostos e usar cookies seguros ou armazenamento server-side.",
                    promoted=True,
                ))
                continue

            if "shopify" in issuer or "buyer_flags" in raw.lower():
                outcomes.append(self.outcome(
                    validator="15D Token Deep Validation",
                    target="Shopify/platform token",
                    status="INFORMATIVO",
                    severity="INFO",
                    confidence=88,
                    impact="Token parece representar estado de plataforma/Shopify. Não foram observados campos sensíveis na decodificação local.",
                    evidence=self.safe_json_sample(payload),
                    recommendation="Registrar como superfície e evitar logs desnecessários de URL.",
                ))
                continue

            outcomes.append(self.outcome(
                validator="15D Token Deep Validation",
                target="JWT-like token",
                status="REVISAR_MANUALMENTE",
                severity="LOW",
                confidence=72,
                impact=f"JWT-like decodificado sem PII evidente. Expiração presente: {has_exp}.",
                evidence=self.safe_json_sample(payload),
                recommendation="Validar emissor, expiração, escopo e necessidade de exposição em URL.",
            ))

        return outcomes

    def validate_apis(self, apis: List[str]) -> List[Dict[str, Any]]:
        outcomes = []

        for url in apis:
            if not self.can_request():
                break

            result = self.http.request(url, method="GET")
            self.total_requests += 1

            body_lower = result.body_sample.lower()
            headers = result.headers

            sensitive_hits = self.find_sensitive_strings(result.body_sample)
            cors = headers.get("access-control-allow-origin", "")
            content_type = result.content_type.lower()

            if result.status in {401, 403}:
                outcomes.append(self.outcome(
                    validator="15A API Exposure Validation",
                    target=url,
                    status="INFORMATIVO",
                    severity="INFO",
                    confidence=82,
                    impact=f"Endpoint respondeu {result.status}, indicando controle de acesso ou bloqueio.",
                    evidence=self.http_evidence(result),
                    recommendation="Manter autenticação/bloqueio e revisar rate limit e logs.",
                    request_count=1,
                ))
                continue

            if result.status == 200 and "application/json" in content_type and sensitive_hits:
                outcomes.append(self.outcome(
                    validator="15A API Exposure Validation",
                    target=url,
                    status="CONFIRMADO_POTENCIAL",
                    severity="MEDIUM",
                    confidence=78,
                    impact=f"Endpoint API retornou JSON público com possíveis indicadores sensíveis: {', '.join(sorted(sensitive_hits))}.",
                    evidence=self.http_evidence(result),
                    recommendation="Validar se os dados retornados devem ser públicos. Aplicar autenticação/autorização se necessário.",
                    request_count=1,
                    promoted=True,
                ))
                continue

            if result.status == 200 and "application/json" in content_type:
                outcomes.append(self.outcome(
                    validator="15A API Exposure Validation",
                    target=url,
                    status="REVISAR_MANUALMENTE",
                    severity="LOW",
                    confidence=75,
                    impact="Endpoint API respondeu JSON publicamente, mas sem dados sensíveis detectados na amostra.",
                    evidence=self.http_evidence(result),
                    recommendation="Revisar autenticação, autorização, CORS e rate limit.",
                    request_count=1,
                ))
                continue

            if result.status in {200, 204, 301, 302, 404}:
                outcomes.append(self.outcome(
                    validator="15A API Exposure Validation",
                    target=url,
                    status="INFORMATIVO",
                    severity="INFO",
                    confidence=70,
                    impact=f"Endpoint observado respondeu status {result.status}. Não houve evidência de exposição sensível na amostra.",
                    evidence=self.http_evidence(result),
                    recommendation="Registrar como superfície e validar manualmente se for rota crítica.",
                    request_count=1,
                ))
                continue

            outcomes.append(self.outcome(
                validator="15A API Exposure Validation",
                target=url,
                status="REVISAR_MANUALMENTE",
                severity="LOW",
                confidence=60,
                impact=f"Endpoint retornou status {result.status or 'sem resposta'} ou erro. Precisa interpretação manual.",
                evidence=self.http_evidence(result),
                recommendation="Confirmar comportamento esperado e se há controles de acesso adequados.",
                request_count=1,
            ))

        return outcomes

    def validate_graphql(self, graphql_urls: List[str]) -> List[Dict[str, Any]]:
        outcomes = []

        benign_query = json.dumps({"query": "{ __typename }"}).encode("utf-8")
        introspection_probe = json.dumps({"query": "{ __schema { queryType { name } } }"}).encode("utf-8")

        for url in graphql_urls:
            if not self.can_request(2):
                break

            # Query benigna
            result_basic = self.http.request(
                url,
                method="POST",
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                body=benign_query,
            )
            self.total_requests += 1

            # Introspection simples
            result_intro = self.http.request(
                url,
                method="POST",
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                body=introspection_probe,
            )
            self.total_requests += 1

            basic_body = result_basic.body_sample.lower()
            intro_body = result_intro.body_sample.lower()

            if result_intro.status == 200 and "__schema" in intro_body and "querytype" in intro_body:
                is_shopify_graphql = (
                    "shopify" in url.lower()
                    or "/api/" in url.lower() and "graphql" in url.lower()
                    or "queryroot" in intro_body
                )

                if is_shopify_graphql:
                    outcomes.append(self.outcome(
                        validator="15B GraphQL Validation",
                        target=url,
                        status="CONFIRMADO_POTENCIAL",
                        severity="MEDIUM",
                        confidence=82,
                        impact="GraphQL público respondeu à introspection. Em plataformas como Shopify isso pode ser parte da Storefront API, mas ainda deve ser validado para garantir que não exponha dados sensíveis, operações indevidas ou schema desnecessário.",
                        evidence=self.http_evidence(result_intro),
                        recommendation="Confirmar se o endpoint é Storefront API esperado, revisar permissões, limitar escopo de tokens públicos, validar CORS/rate limit e bloquear introspection quando não for necessária.",
                        request_count=2,
                        promoted=True,
                    ))
                else:
                    outcomes.append(self.outcome(
                        validator="15B GraphQL Validation",
                        target=url,
                        status="CONFIRMADO_POTENCIAL",
                        severity="MEDIUM",
                        confidence=85,
                        impact="GraphQL respondeu à probe de introspection. Isso pode expor schema público e facilitar enumeração de operações.",
                        evidence=self.http_evidence(result_intro),
                        recommendation="Desabilitar introspection pública em produção quando não necessária, ou restringir por autenticação.",
                        request_count=2,
                        promoted=True,
                    ))

                continue

            if result_basic.status in {401, 403} or result_intro.status in {401, 403}:
                outcomes.append(self.outcome(
                    validator="15B GraphQL Validation",
                    target=url,
                    status="INFORMATIVO",
                    severity="INFO",
                    confidence=82,
                    impact="GraphQL parece protegido ou bloqueado para requisições não autenticadas.",
                    evidence=f"basic={self.http_evidence(result_basic)} | introspection={self.http_evidence(result_intro)}",
                    recommendation="Manter autenticação e rate limit.",
                    request_count=2,
                ))
                continue

            if result_basic.status == 200 or result_intro.status == 200:
                outcomes.append(self.outcome(
                    validator="15B GraphQL Validation",
                    target=url,
                    status="REVISAR_MANUALMENTE",
                    severity="LOW",
                    confidence=75,
                    impact="GraphQL respondeu a requisição pública, mas introspection não foi confirmada como aberta.",
                    evidence=f"basic={self.http_evidence(result_basic)} | introspection={self.http_evidence(result_intro)}",
                    recommendation="Revisar autenticação, introspection, CORS, rate limit e permissões de queries.",
                    request_count=2,
                ))
                continue

            outcomes.append(self.outcome(
                validator="15B GraphQL Validation",
                target=url,
                status="INFORMATIVO",
                severity="INFO",
                confidence=65,
                impact="GraphQL não respondeu de forma útil à validação segura.",
                evidence=f"basic={self.http_evidence(result_basic)} | introspection={self.http_evidence(result_intro)}",
                recommendation="Registrar como superfície e validar manualmente se fizer parte do escopo.",
                request_count=2,
            ))

        return outcomes

    def validate_cors_headers(self, urls: List[str]) -> List[Dict[str, Any]]:
        outcomes = []

        # Testa só o domínio base e alguns endpoints
        targets = []
        targets.append(f"https://{self.target}/")
        for url in urls:
            if self.target in url and url not in targets:
                targets.append(url)
            if len(targets) >= 10:
                break

        for url in targets:
            if not self.can_request():
                break

            result = self.http.request(
                url,
                method="OPTIONS",
                headers={
                    "Origin": "https://example.com",
                    "Access-Control-Request-Method": "GET",
                },
            )
            self.total_requests += 1

            h = result.headers
            acao = h.get("access-control-allow-origin", "")
            acac = h.get("access-control-allow-credentials", "")
            csp = h.get("content-security-policy", "")
            hsts = h.get("strict-transport-security", "")
            xfo = h.get("x-frame-options", "")

            if acao == "https://example.com" and acac.lower() == "true":
                outcomes.append(self.outcome(
                    validator="15E Header/CORS Validation",
                    target=url,
                    status="CONFIRMADO_POTENCIAL",
                    severity="HIGH",
                    confidence=85,
                    impact="CORS refletiu origem externa com credentials=true. Isso pode permitir leitura cross-origin em cenários autenticados.",
                    evidence=self.header_evidence(result, ["access-control-allow-origin", "access-control-allow-credentials"]),
                    recommendation="Não refletir origens arbitrárias com credenciais. Usar allowlist estrita de origens confiáveis.",
                    request_count=1,
                    promoted=True,
                ))
                continue

            checks = []
            if not hsts and url.startswith("https://"):
                checks.append("HSTS ausente")
            if not csp:
                checks.append("CSP ausente")
            if not xfo:
                checks.append("X-Frame-Options ausente")

            if checks:
                outcomes.append(self.outcome(
                    validator="15E Header/CORS Validation",
                    target=url,
                    status="REVISAR_MANUALMENTE",
                    severity="LOW",
                    confidence=72,
                    impact=f"Políticas de header para revisão: {', '.join(checks)}.",
                    evidence=self.header_evidence(result, ["strict-transport-security", "content-security-policy", "x-frame-options", "access-control-allow-origin"]),
                    recommendation="Revisar headers de segurança conforme compatibilidade da plataforma/CDN.",
                    request_count=1,
                ))
            else:
                outcomes.append(self.outcome(
                    validator="15E Header/CORS Validation",
                    target=url,
                    status="INFORMATIVO",
                    severity="INFO",
                    confidence=78,
                    impact="Não foi observada configuração CORS perigosa na validação segura.",
                    evidence=self.header_evidence(result, ["strict-transport-security", "content-security-policy", "x-frame-options", "access-control-allow-origin"]),
                    recommendation="Manter revisão periódica de headers e políticas de CDN.",
                    request_count=1,
                ))

        return outcomes

    def validate_storage(self, storage_urls: List[str]) -> List[Dict[str, Any]]:
        outcomes = []

        for url in storage_urls:
            if not self.can_request():
                break

            result = self.http.request(url, method="HEAD")
            self.total_requests += 1

            low = url.lower()
            sensitive_name = any(x in low for x in ["backup", "dump", "database", "db.sql", ".env", "secret", "private", "export", "config"])

            if result.status == 200 and sensitive_name:
                outcomes.append(self.outcome(
                    validator="15C Storage/CDN Validation",
                    target=url,
                    status="CONFIRMADO_POTENCIAL",
                    severity="HIGH",
                    confidence=82,
                    impact="Arquivo em storage/CDN com nome sensível respondeu publicamente.",
                    evidence=self.http_evidence(result),
                    recommendation="Remover arquivo público, revisar permissões do storage e rotacionar segredos caso aplicável.",
                    request_count=1,
                    promoted=True,
                ))
                continue

            if result.status == 200:
                outcomes.append(self.outcome(
                    validator="15C Storage/CDN Validation",
                    target=url,
                    status="INFORMATIVO",
                    severity="INFO",
                    confidence=82,
                    impact="Asset público em storage/CDN respondeu normalmente. Pelo nome/tipo, aparenta ser recurso público esperado.",
                    evidence=self.http_evidence(result),
                    recommendation="Confirmar que apenas assets públicos estão expostos e remover arquivos sensíveis de storage público.",
                    request_count=1,
                ))
                continue

            if result.status in {403, 401}:
                outcomes.append(self.outcome(
                    validator="15C Storage/CDN Validation",
                    target=url,
                    status="INFORMATIVO",
                    severity="INFO",
                    confidence=75,
                    impact=f"Storage/CDN retornou {result.status}, indicando bloqueio ou acesso restrito.",
                    evidence=self.http_evidence(result),
                    recommendation="Manter política restritiva para arquivos não públicos.",
                    request_count=1,
                ))
                continue

            outcomes.append(self.outcome(
                validator="15C Storage/CDN Validation",
                target=url,
                status="REVISAR_MANUALMENTE",
                severity="LOW",
                confidence=60,
                impact=f"Storage/CDN retornou status {result.status or 'sem resposta'}. Precisa revisão conforme contexto.",
                evidence=self.http_evidence(result),
                recommendation="Confirmar se o recurso deve existir publicamente.",
                request_count=1,
            ))

        return outcomes

    def validate_auth_surface(self, auth_urls: List[str]) -> List[Dict[str, Any]]:
        outcomes = []

        for url in auth_urls:
            if not self.can_request():
                break

            result = self.http.request(url, method="GET")
            self.total_requests += 1

            headers = result.headers
            set_cookie = headers.get("set-cookie", "")
            cookie_issues = []

            if set_cookie:
                low_cookie = set_cookie.lower()
                if "secure" not in low_cookie:
                    cookie_issues.append("cookie sem Secure")
                if "httponly" not in low_cookie:
                    cookie_issues.append("cookie sem HttpOnly")
                if "samesite" not in low_cookie:
                    cookie_issues.append("cookie sem SameSite")

            body_lower = result.body_sample.lower()
            login_indicators = ["login", "senha", "password", "account", "entrar", "recuperar"]

            if result.status == 200 and any(x in body_lower for x in login_indicators):
                if cookie_issues:
                    outcomes.append(self.outcome(
                        validator="15F Auth Surface Safe Checks",
                        target=url,
                        status="REVISAR_MANUALMENTE",
                        severity="LOW",
                        confidence=76,
                        impact=f"Área de autenticação acessível. Cookies observados com pontos para revisão: {', '.join(cookie_issues)}.",
                        evidence=self.header_evidence(result, ["set-cookie"]),
                        recommendation="Revisar flags Secure, HttpOnly e SameSite. Validar rate limit e mensagens genéricas.",
                        request_count=1,
                    ))
                else:
                    outcomes.append(self.outcome(
                        validator="15F Auth Surface Safe Checks",
                        target=url,
                        status="REVISAR_MANUALMENTE",
                        severity="LOW",
                        confidence=72,
                        impact="Área de autenticação acessível. Não é falha isolada, mas deve ter proteção contra abuso.",
                        evidence=self.http_evidence(result),
                        recommendation="Validar rate limit, bloqueio progressivo, MFA quando aplicável e mensagens de erro genéricas.",
                        request_count=1,
                    ))
                continue

            outcomes.append(self.outcome(
                validator="15F Auth Surface Safe Checks",
                target=url,
                status="INFORMATIVO",
                severity="INFO",
                confidence=65,
                impact="Rota de autenticação/conta observada, sem evidência automatizada de falha nesta validação segura.",
                evidence=self.http_evidence(result),
                recommendation="Manter monitoramento e controles preventivos.",
                request_count=1,
            ))

        return outcomes

    def validate_ports(self, ports: List[str]) -> List[Dict[str, Any]]:
        outcomes = []

        for evidence in ports:
            found = self.extract_ports(evidence)

            if not found:
                outcomes.append(self.outcome(
                    validator="15G Port Exposure Validation",
                    target=self.mask(evidence),
                    status="REVISAR_MANUALMENTE",
                    severity="LOW",
                    confidence=60,
                    impact="Evidência de porta aberta genérica. Precisa revisar saída completa de nmap/naabu.",
                    evidence=self.mask(evidence),
                    recommendation="Confirmar porta, serviço, origem e necessidade de exposição pública.",
                ))
                continue

            expected = {"80", "443"}
            alternative = {"8080", "8443", "8000", "8888", "3000", "5000", "9000"}

            if all(p in expected for p in found):
                outcomes.append(self.outcome(
                    validator="15G Port Exposure Validation",
                    target=", ".join(found),
                    status="INFORMATIVO",
                    severity="INFO",
                    confidence=85,
                    impact="Portas web padrão identificadas. Para site público, 80/443 são esperadas.",
                    evidence=self.mask(evidence),
                    recommendation="Manter TLS atualizado, redirecionamento HTTP para HTTPS e WAF/CDN ativo.",
                ))
            elif any(p in alternative for p in found):
                outcomes.append(self.outcome(
                    validator="15G Port Exposure Validation",
                    target=", ".join(found),
                    status="REVISAR_MANUALMENTE",
                    severity="LOW",
                    confidence=75,
                    impact=f"Portas alternativas identificadas: {', '.join(found)}. Podem pertencer ao provedor/CDN ou origem.",
                    evidence=self.mask(evidence),
                    recommendation="Confirmar origem das portas e restringir serviços não públicos.",
                ))
            else:
                outcomes.append(self.outcome(
                    validator="15G Port Exposure Validation",
                    target=", ".join(found),
                    status="REVISAR_MANUALMENTE",
                    severity="LOW",
                    confidence=65,
                    impact=f"Portas identificadas: {', '.join(found)}. Necessário confirmar serviço.",
                    evidence=self.mask(evidence),
                    recommendation="Revisar necessidade de exposição e aplicar firewall/allowlist quando aplicável.",
                ))

        return outcomes


    def dedup_outcomes(self, outcomes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Remove duplicidades por validador + alvo + impacto.
        Mantém o item mais forte quando houver repetição.
        """
        severity_weight = {
            "CRITICAL": 5,
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2,
            "INFO": 1,
        }

        best = {}

        for item in outcomes:
            validator = str(item.get("validator", "")).strip()
            target = str(item.get("target", "")).strip()
            impact = str(item.get("impact", "")).strip()

            key = (
                validator.lower(),
                target.lower(),
                impact[:120].lower(),
            )

            current = best.get(key)

            if not current:
                best[key] = item
                continue

            old_weight = severity_weight.get(str(current.get("severity", "INFO")).upper(), 0)
            new_weight = severity_weight.get(str(item.get("severity", "INFO")).upper(), 0)

            if new_weight > old_weight:
                best[key] = item

        return list(best.values())


    def build_summary(
        self,
        outcomes: List[Dict[str, Any]],
        confirmed: List[Dict[str, Any]],
        manual: List[Dict[str, Any]],
        info: List[Dict[str, Any]],
        candidates: Dict[str, List[str]],
    ) -> Dict[str, Any]:
        by_status = Counter(x.get("status") for x in outcomes)
        by_severity = Counter(x.get("severity") for x in outcomes)
        by_validator = Counter(x.get("validator") for x in outcomes)

        if confirmed:
            level = "HIGH" if any(x.get("severity") == "HIGH" for x in confirmed) else "MEDIUM"
        elif len(manual) >= 10:
            level = "MEDIUM"
        elif manual:
            level = "LOW"
        else:
            level = "INFO"

        return {
            "total_validations": len(outcomes),
            "confirmed_or_potential": len(confirmed),
            "manual_review": len(manual),
            "informational": len(info),
            "validation_level": level,
            "requests_made": self.total_requests,
            "max_total_requests": MAX_TOTAL_REQUESTS,
            "by_status": dict(by_status),
            "by_severity": dict(by_severity),
            "by_validator": dict(by_validator),
            "candidates": {k: len(v) for k, v in candidates.items()},
        }

    def render_impact_report(self, summary: Dict[str, Any], outcomes: List[Dict[str, Any]]) -> str:
        lines = []

        lines.append("# CyberLab - Bloco 15 Controlled Offensive Validation")
        lines.append("")
        lines.append(f"**Alvo:** {self.target}")
        lines.append(f"**Pasta analisada:** `{self.scan_dir}`")
        lines.append(f"**Gerado em:** {datetime.now().isoformat(timespec='seconds')}")
        lines.append(f"**Modo:** {self.mode}")
        lines.append("")
        lines.append("## Política de controle")
        lines.append("")
        lines.append("- Sem brute force")
        lines.append("- Sem credential stuffing")
        lines.append("- Sem bypass de autenticação")
        lines.append("- Sem exploração destrutiva")
        lines.append("- Sem alteração de dados")
        lines.append("- Sem download em massa")
        lines.append("- Requisições com timeout, limite e intervalo")
        lines.append("")
        lines.append("## Resumo")
        lines.append("")
        lines.append(f"- Total de validações: **{summary.get('total_validations')}**")
        lines.append(f"- Confirmados ou potenciais: **{summary.get('confirmed_or_potential')}**")
        lines.append(f"- Revisão manual: **{summary.get('manual_review')}**")
        lines.append(f"- Informativos: **{summary.get('informational')}**")
        lines.append(f"- Requisições realizadas: **{summary.get('requests_made')} / {summary.get('max_total_requests')}**")
        lines.append(f"- Nível de validação: **{summary.get('validation_level')}**")
        lines.append("")
        lines.append("### Por validador")
        lines.append("")
        for k, v in summary.get("by_validator", {}).items():
            lines.append(f"- **{k}:** {v}")
        lines.append("")
        lines.append("## Achados promovidos ou potenciais")
        lines.append("")

        promoted = [x for x in outcomes if x.get("promoted")]
        if not promoted:
            lines.append("Nenhum achado foi promovido para risco real/potencial nesta etapa.")
        else:
            for i, item in enumerate(promoted, start=1):
                lines.extend(self.render_outcome_item(i, item))

        lines.append("")
        lines.append("## Itens para revisão manual")
        lines.append("")

        manual = [x for x in outcomes if x.get("status") == "REVISAR_MANUALMENTE"]
        if not manual:
            lines.append("Nenhum item pendente de revisão manual.")
        else:
            for i, item in enumerate(manual[:60], start=1):
                lines.extend(self.render_outcome_item(i, item))

        lines.append("")
        lines.append("## Itens informativos amostrados")
        lines.append("")

        info = [x for x in outcomes if x.get("status") == "INFORMATIVO"]
        for i, item in enumerate(info[:40], start=1):
            lines.extend(self.render_outcome_item(i, item))

        return "\n".join(lines)

    def render_outcome_item(self, idx: int, item: Dict[str, Any]) -> List[str]:
        return [
            f"### {idx}. {item.get('validator')}",
            "",
            f"- **Alvo validado:** `{item.get('target')}`",
            f"- **Status:** {item.get('status')}",
            f"- **Severidade:** {item.get('severity')}",
            f"- **Confiança:** {item.get('confidence')}",
            f"- **Requisições:** {item.get('request_count', 0)}",
            "",
            "**Impacto:**",
            "",
            str(item.get("impact", "-")),
            "",
            "**Evidência segura:**",
            "",
            f"`{item.get('evidence', '-')}`",
            "",
            "**Recomendação:**",
            "",
            str(item.get("recommendation", "-")),
            "",
        ]

    def render_client_summary(self, summary: Dict[str, Any], outcomes: List[Dict[str, Any]]) -> str:
        promoted = [x for x in outcomes if x.get("promoted")]
        manual = [x for x in outcomes if x.get("status") == "REVISAR_MANUALMENTE"]

        lines = []
        lines.append("# Resumo Executivo - Bloco 15 Controlled Offensive Validation")
        lines.append("")
        lines.append(f"**Alvo:** {self.target}")
        lines.append(f"**Gerado em:** {datetime.now().isoformat(timespec='seconds')}")
        lines.append("")
        lines.append("## Leitura executiva")
        lines.append("")

        if not promoted:
            lines.append("A validação ofensiva controlada não confirmou vulnerabilidades exploráveis de alto impacto nesta etapa.")
        else:
            lines.append(f"A validação encontrou **{len(promoted)}** ponto(s) com potencial de impacto que exigem prioridade técnica.")

        lines.append("")
        lines.append(f"Foram executadas **{summary.get('total_validations')}** validações seguras, com **{summary.get('requests_made')}** requisições controladas.")
        lines.append(f"O nível consolidado do Bloco 15 ficou como **{summary.get('validation_level')}**.")
        lines.append("")
        lines.append("## Principais pontos de atenção")
        lines.append("")

        if promoted:
            for item in promoted:
                lines.append(f"- **{item.get('severity')}** — {item.get('impact')}")
        else:
            lines.append("- Nenhum item foi promovido para risco real confirmado automaticamente.")
            lines.append("- Os pontos relevantes permanecem como revisão manual ou melhoria preventiva.")

        if manual:
            lines.append("")
            lines.append("## Revisões recomendadas")
            lines.append("")
            grouped = defaultdict(int)
            for item in manual:
                grouped[item.get("validator")] += 1
            for validator, count in grouped.items():
                lines.append(f"- **{validator}:** {count} item(ns) para revisão.")

        lines.append("")
        lines.append("## Recomendação prática")
        lines.append("")
        lines.append("Priorizar validações manuais em APIs/GraphQL, autenticação, portas alternativas e políticas de headers/CORS. Caso o cliente disponibilize conta de teste, executar validação autenticada de área do cliente, pedidos, endereços, recuperação de senha e fluxo de checkout.")
        return "\n".join(lines)

    def render_manual_tests(self, summary: Dict[str, Any], outcomes: List[Dict[str, Any]]) -> str:
        lines = []
        lines.append("# CyberLab - Plano de Testes Manuais Controlados")
        lines.append("")
        lines.append(f"**Alvo:** {self.target}")
        lines.append("")
        lines.append("## Objetivo")
        lines.append("")
        lines.append("Complementar a validação automatizada com testes autorizados de lógica, autenticação e autorização, sem ações destrutivas.")
        lines.append("")
        lines.append("## Testes recomendados")
        lines.append("")
        lines.append("### 1. Conta de teste / área do cliente")
        lines.append("")
        lines.append("- Criar conta de teste autorizada.")
        lines.append("- Verificar se dados de conta, pedidos e endereços são acessíveis apenas pelo usuário correto.")
        lines.append("- Validar logout, expiração de sessão e troca de senha.")
        lines.append("")
        lines.append("### 2. Recuperação de senha")
        lines.append("")
        lines.append("- Confirmar se a mensagem é igual para e-mail existente e inexistente.")
        lines.append("- Validar rate limit.")
        lines.append("- Confirmar expiração do link/token.")
        lines.append("")
        lines.append("### 3. APIs e GraphQL")
        lines.append("")
        lines.append("- Confirmar autenticação e autorização.")
        lines.append("- Validar CORS.")
        lines.append("- Confirmar se introspection GraphQL está desabilitada ou restrita.")
        lines.append("- Verificar se endpoints públicos não retornam PII.")
        lines.append("")
        lines.append("### 4. Carrinho e checkout")
        lines.append("")
        lines.append("- Confirmar que preço e desconto são calculados server-side.")
        lines.append("- Validar cupons, quantidade e alteração de parâmetros.")
        lines.append("- Não realizar compra real sem autorização explícita.")
        lines.append("")
        lines.append("### 5. Storage/CDN")
        lines.append("")
        lines.append("- Confirmar ausência de backups, dumps, exports ou arquivos de configuração públicos.")
        lines.append("- Revisar apps/extensões de terceiros.")
        lines.append("")
        lines.append("## Restrições")
        lines.append("")
        lines.append("- Não executar brute force.")
        lines.append("- Não acessar dados de terceiros.")
        lines.append("- Não modificar dados reais.")
        lines.append("- Não realizar DoS ou stress.")
        lines.append("- Não explorar RCE/SQLi destrutivo em produção.")
        return "\n".join(lines)

    def render_pdf(self, pdf_path: Path, summary: Dict[str, Any], outcomes: List[Dict[str, Any]]) -> None:
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        except Exception:
            pdf_path.write_text("PDF não gerado: reportlab indisponível.\n", encoding="utf-8")
            return

        doc = SimpleDocTemplate(str(pdf_path), pagesize=A4)
        styles = getSampleStyleSheet()
        story = []

        story.append(Paragraph("CyberLab - Bloco 15 Controlled Offensive Validation", styles["Title"]))
        story.append(Spacer(1, 12))
        story.append(Paragraph(f"<b>Alvo:</b> {self.target}", styles["Normal"]))
        story.append(Paragraph(f"<b>Gerado em:</b> {datetime.now().isoformat(timespec='seconds')}", styles["Normal"]))
        story.append(Spacer(1, 12))

        story.append(Paragraph("Resumo", styles["Heading2"]))
        story.append(Paragraph(f"Total de validações: {summary.get('total_validations')}", styles["Normal"]))
        story.append(Paragraph(f"Confirmados ou potenciais: {summary.get('confirmed_or_potential')}", styles["Normal"]))
        story.append(Paragraph(f"Revisão manual: {summary.get('manual_review')}", styles["Normal"]))
        story.append(Paragraph(f"Informativos: {summary.get('informational')}", styles["Normal"]))
        story.append(Paragraph(f"Requisições realizadas: {summary.get('requests_made')}", styles["Normal"]))
        story.append(Paragraph(f"Nível de validação: {summary.get('validation_level')}", styles["Normal"]))
        story.append(Spacer(1, 12))

        promoted = [x for x in outcomes if x.get("promoted")]
        manual = [x for x in outcomes if x.get("status") == "REVISAR_MANUALMENTE"]

        story.append(Paragraph("Achados promovidos ou potenciais", styles["Heading2"]))
        if not promoted:
            story.append(Paragraph("Nenhum achado promovido para risco real/potencial nesta etapa.", styles["Normal"]))
        else:
            for item in promoted[:20]:
                story.append(Paragraph(str(item.get("validator")), styles["Heading3"]))
                story.append(Paragraph(f"<b>Alvo:</b> {self.escape(item.get('target'))}", styles["Normal"]))
                story.append(Paragraph(f"<b>Impacto:</b> {self.escape(item.get('impact'))}", styles["Normal"]))
                story.append(Paragraph(f"<b>Recomendação:</b> {self.escape(item.get('recommendation'))}", styles["Normal"]))
                story.append(Spacer(1, 8))

        story.append(Spacer(1, 12))
        story.append(Paragraph("Revisões manuais principais", styles["Heading2"]))
        for item in manual[:25]:
            story.append(Paragraph(str(item.get("validator")), styles["Heading3"]))
            story.append(Paragraph(f"<b>Alvo:</b> {self.escape(item.get('target'))}", styles["Normal"]))
            story.append(Paragraph(f"<b>Impacto:</b> {self.escape(item.get('impact'))}", styles["Normal"]))
            story.append(Paragraph(f"<b>Recomendação:</b> {self.escape(item.get('recommendation'))}", styles["Normal"]))
            story.append(Spacer(1, 8))

        doc.build(story)

    def outcome(
        self,
        validator: str,
        target: str,
        status: str,
        severity: str,
        confidence: int,
        impact: str,
        evidence: str,
        recommendation: str,
        request_count: int = 0,
        promoted: bool = False,
    ) -> Dict[str, Any]:
        return {
            "validator": validator,
            "target": target,
            "status": status,
            "severity": severity,
            "confidence": confidence,
            "impact": impact,
            "evidence": evidence,
            "recommendation": recommendation,
            "request_count": request_count,
            "promoted": promoted,
        }

    def can_request(self, needed: int = 1) -> bool:
        return self.total_requests + needed <= MAX_TOTAL_REQUESTS

    def dedup(self, items: List[str]) -> List[str]:
        seen = set()
        out = []
        for item in items:
            if not item:
                continue
            if item in seen:
                continue
            seen.add(item)
            out.append(item)
        return out

    def is_api_url(self, url: str) -> bool:
        low = url.lower()
        return "/api/" in low or "/graphql" in low or "graphql" in low or "/collect" in low

    def is_storage_url(self, url: str) -> bool:
        low = url.lower()
        return "amazonaws.com" in low or "cloudfront.net" in low or "cdn.shopify.com" in low or "/cdn/shop/" in low

    def is_auth_url(self, url: str) -> bool:
        low = url.lower()
        keys = ["/login", "/account", "/conta", "/minha-conta", "/recuperar", "/senha", "/password", "/cadastro", "/checkout"]
        return any(k in low for k in keys)

    def extract_jwt(self, text: str) -> Optional[str]:
        m = re.search(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", text or "")
        return m.group(0) if m else None

    def decode_jwt(self, jwt: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        try:
            parts = jwt.split(".")
            if len(parts) != 3:
                return {}, {}
            header = json.loads(self.b64url_decode(parts[0]))
            payload = json.loads(self.b64url_decode(parts[1]))
            return header if isinstance(header, dict) else {}, payload if isinstance(payload, dict) else {}
        except Exception:
            return {}, {}

    def b64url_decode(self, value: str) -> str:
        value = value.strip()
        padding = "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode((value + padding).encode()).decode("utf-8", errors="replace")

    def find_sensitive_keys(self, obj: Any) -> set:
        hits = set()

        def walk(v: Any):
            if isinstance(v, dict):
                for k, val in v.items():
                    key = str(k).lower()
                    if key in SENSITIVE_KEYS:
                        hits.add(key)
                    walk(val)
            elif isinstance(v, list):
                for x in v:
                    walk(x)

        walk(obj)
        return hits

    def find_sensitive_strings(self, text: str) -> set:
        low = (text or "").lower()
        hits = set()
        patterns = {
            "email": r"[a-z0-9_.+-]+@[a-z0-9-]+\.[a-z0-9-.]+",
            "cpf_like": r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b",
            "phone_like": r"\b(?:\+?55)?\s?\(?\d{2}\)?\s?\d{4,5}-?\d{4}\b",
            "customer": r"\bcustomer(_id)?\b",
            "order": r"\border(_id)?\b",
        }
        for name, pat in patterns.items():
            if re.search(pat, low, re.I):
                hits.add(name)
        return hits

    def extract_ports(self, text: str) -> List[str]:
        found = []
        for m in re.finditer(r"\b([0-9]{2,5})/tcp\s+open\b", text or "", re.I):
            found.append(m.group(1))
        for m in re.finditer(r":([0-9]{2,5})\b", text or ""):
            found.append(m.group(1))
        return self.dedup(found)

    def http_evidence(self, r: SafeHttpResult) -> str:
        parts = [
            f"method={r.method}",
            f"status={r.status}",
            f"content_type={r.content_type or '-'}",
            f"content_length={r.content_length if r.content_length is not None else '-'}",
            f"elapsed_ms={r.elapsed_ms}",
        ]
        if r.error:
            parts.append(f"error={self.mask(r.error)}")
        sample = self.mask(r.body_sample)
        if sample and sample != "-":
            parts.append(f"sample={sample[:300]}")
        return " | ".join(parts)

    def header_evidence(self, r: SafeHttpResult, keys: List[str]) -> str:
        out = [f"status={r.status}", f"elapsed_ms={r.elapsed_ms}"]
        for k in keys:
            v = r.headers.get(k.lower(), "")
            if v:
                out.append(f"{k}={self.mask(v)}")
            else:
                out.append(f"{k}=<ausente>")
        return " | ".join(out)

    def safe_json_sample(self, obj: Any) -> str:
        try:
            text = json.dumps(obj, ensure_ascii=False, indent=2)
        except Exception:
            text = str(obj)
        return self.mask(text[:1000])

    def mask(self, value: Any) -> str:
        text = str(value or "").strip()
        if not text:
            return "-"

        text = re.sub(r"([?&](?:token|access_token|id_token|refresh_token|session|state|buyer_flags)=)[^&\s]+", r"\1[MASKED]", text, flags=re.I)
        text = re.sub(r"(eyJ[A-Za-z0-9_-]{8,})\.([A-Za-z0-9_-]{8,})\.([A-Za-z0-9_-]{8,})", lambda m: f"{m.group(1)[:10]}...{m.group(3)[-6:]}", text)
        text = re.sub(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", "[email-masked]", text)

        if len(text) > 500:
            text = text[:500] + "...[truncated]"
        return text

    def escape(self, value: Any) -> str:
        text = str(value or "")
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def find_latest_scan(target: str, base: Optional[Path] = None) -> Path:
    base = base or Path.home() / "CyberLab" / "results" / "web" / target

    if not base.exists():
        raise FileNotFoundError(f"Pasta do alvo não encontrada: {base}")

    scans = sorted([p for p in base.iterdir() if p.is_dir()], key=lambda p: p.stat().st_mtime, reverse=True)

    if not scans:
        raise FileNotFoundError(f"Nenhum scan encontrado em: {base}")

    return scans[0]
