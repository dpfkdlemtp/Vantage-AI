from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from scanner.models import Finding

_SECURITY_HEADERS: dict[str, dict[str, Any]] = {
    "strict-transport-security": {
        "label": "Strict-Transport-Security (HSTS)",
        "summary": "Missing Strict-Transport-Security header — HTTPS not enforced by policy",
        "tags": ["security-header", "hsts", "misconfiguration"],
        "https_only": True,
    },
    "content-security-policy": {
        "label": "Content-Security-Policy",
        "summary": "Missing Content-Security-Policy header — XSS mitigation absent",
        "tags": ["security-header", "csp", "misconfiguration"],
        "https_only": False,
    },
    "x-frame-options": {
        "label": "X-Frame-Options",
        "summary": "Missing X-Frame-Options header — clickjacking risk",
        "tags": ["security-header", "clickjacking", "misconfiguration"],
        "https_only": False,
    },
    "x-content-type-options": {
        "label": "X-Content-Type-Options",
        "summary": "Missing X-Content-Type-Options header — MIME sniffing risk",
        "tags": ["security-header", "misconfiguration"],
        "https_only": False,
    },
    "referrer-policy": {
        "label": "Referrer-Policy",
        "summary": "Missing Referrer-Policy header",
        "tags": ["security-header", "misconfiguration"],
        "https_only": False,
    },
    "permissions-policy": {
        "label": "Permissions-Policy",
        "summary": "Missing Permissions-Policy header",
        "tags": ["security-header", "misconfiguration"],
        "https_only": False,
    },
}

_VERSION_RE = re.compile(
    r"(?:apache|nginx|iis|lighttpd|tomcat|jetty|caddy|openresty|microsoft-iis|php)/[\d.]+",
    re.IGNORECASE,
)


def analyze_security_headers(
    url: str,
    response_headers: dict[str, str],
    *,
    run_id: str,
    task_id: str | None,
) -> list[Finding]:
    """Return security findings for missing or disclosing headers."""
    findings: list[Finding] = []
    now = datetime.now(UTC)
    lower = {k.lower(): v for k, v in response_headers.items()}
    is_https = url.lower().startswith("https://")

    for header_name, meta in _SECURITY_HEADERS.items():
        if meta.get("https_only") and not is_https:
            continue
        if header_name not in lower:
            findings.append(Finding(
                finding_id=f"hdr-{uuid4().hex[:12]}",
                run_id=run_id,
                task_id=task_id,
                module="http_probe",
                target=url,
                status="observed",
                summary=meta["summary"],
                evidence_json={
                    "type": "security_header",
                    "missing_header": header_name,
                    "header_label": meta["label"],
                    "url": url,
                },
                tags=list(meta["tags"]),
                created_at=now,
            ))

    # Server/framework version disclosure
    for disclosure_header in ("server", "x-powered-by"):
        val = lower.get(disclosure_header, "")
        if val and _VERSION_RE.search(val):
            findings.append(Finding(
                finding_id=f"hdr-disc-{uuid4().hex[:12]}",
                run_id=run_id,
                task_id=task_id,
                module="http_probe",
                target=url,
                status="observed",
                summary=f"Server version disclosure via {disclosure_header}: {val[:120]}",
                evidence_json={
                    "type": "server_disclosure",
                    "header": disclosure_header,
                    "value": val,
                    "url": url,
                },
                tags=["server-disclosure", "information-disclosure"],
                created_at=now,
            ))
            break
    return findings
