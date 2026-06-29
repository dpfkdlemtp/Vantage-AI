"""The ai_triage analyst: turn accumulated findings into a risk-scored TriageResult.

Two paths, same output shape:
- when an API key is configured, ask the LLM to score targets and suggest deeper scans;
- otherwise (or on any LLM error) fall back to a deterministic keyword/port heuristic.

The heuristic keeps the whole feature working offline and gives tests a stable,
network-free baseline.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any
from urllib.parse import urlsplit

import httpx

from scanner.ai.client import LLMUnavailable, complete_json, resolve_api_key, resolve_model
from scanner.ai.models import TargetRisk, TriageResult
from scanner.models import Finding, ScanConfig

MAX_ITEMS_PER_GROUP = 60
MAX_TARGETS = 40

# Substrings that suggest a sensitive / high-value surface worth deeper scanning.
RISKY_KEYWORDS: tuple[str, ...] = (
    "admin", "login", "signin", "sign-in", "auth", "sso", "oauth", "vpn",
    "jenkins", "gitlab", "github", "git", "grafana", "kibana", "jira",
    "confluence", "phpmyadmin", "adminer", "dev", "develop", "staging",
    "stage", "test", "uat", "qa", "internal", "intranet", "backup", "api",
    "portal", "dashboard", "console", "manage", "mgmt", "citrix", "owa",
    "exchange", "rdp", "debug", "env", "config", "jboss", "tomcat", "weblogic",
)
# Open ports that, if exposed, raise the risk of a host.
HIGH_RISK_PORTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 135: "msrpc", 139: "netbios",
    445: "smb", 1433: "mssql", 1521: "oracle", 2375: "docker", 3306: "mysql",
    3389: "rdp", 5432: "postgres", 5601: "kibana", 5900: "vnc", 6379: "redis",
    9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}
WEB_PORTS: frozenset[int] = frozenset({80, 443, 8080, 8443, 8000, 8888, 9000, 3000})


def build_evidence(findings: Sequence[Finding]) -> dict[str, Any]:
    """Compact, redacted view of findings for prompting and heuristic scoring."""

    subdomains: list[str] = []
    live_hosts: list[dict[str, Any]] = []
    open_ports: list[dict[str, Any]] = []
    dir_findings: list[dict[str, Any]] = []
    candidate_cves: list[dict[str, Any]] = []
    seen_sub: set[str] = set()

    for finding in findings:
        ev = finding.evidence_json or {}
        if finding.module == "subdomain_enum":
            host = _first_str(ev, "host", "hostname", "subdomain") or finding.target
            key = host.lower()
            if host and key not in seen_sub:
                seen_sub.add(key)
                subdomains.append(host)
        elif finding.module == "http_probe":
            live_hosts.append(
                {
                    "url": _first_str(ev, "url", "input") or finding.target,
                    "status": ev.get("status_code") or ev.get("status"),
                    "title": _first_str(ev, "title"),
                    "tech": ev.get("technologies") or ev.get("tech") or _first_str(ev, "webserver"),
                }
            )
        elif finding.module == "port_scan":
            open_ports.append(
                {
                    "host": _first_str(ev, "host", "ip") or finding.target,
                    "port": ev.get("port"),
                    "service": _first_str(ev, "service", "name"),
                    "product": _first_str(ev, "product"),
                }
            )
        elif finding.module == "dir_enum":
            dir_findings.append(
                {"url": _first_str(ev, "url") or finding.target, "status": ev.get("status_code")}
            )
        elif finding.module == "cve_match":
            candidate_cves.append(
                {"target": finding.target, "cve": _first_str(ev, "cve_id", "cve") or finding.summary}
            )

    return {
        "subdomains": subdomains[:MAX_ITEMS_PER_GROUP],
        "live_hosts": live_hosts[:MAX_ITEMS_PER_GROUP],
        "open_ports": open_ports[:MAX_ITEMS_PER_GROUP],
        "dir_findings": dir_findings[:MAX_ITEMS_PER_GROUP],
        "candidate_cves": candidate_cves[:MAX_ITEMS_PER_GROUP],
    }


def analyze(
    evidence: dict[str, Any],
    config: ScanConfig,
    *,
    transport: httpx.BaseTransport | None = None,
) -> TriageResult:
    """Score targets via the LLM when configured, else via the offline heuristic."""

    api_key = resolve_api_key(config.ai_api_key_env)
    if api_key and config.ai_provider in ("anthropic", "openai"):
        try:
            return _llm_triage(evidence, config, api_key, transport=transport)
        except LLMUnavailable:
            # Best-effort: degrade to the deterministic path rather than failing the phase.
            pass
    return heuristic_triage(evidence)


def _llm_triage(
    evidence: dict[str, Any],
    config: ScanConfig,
    api_key: str,
    *,
    transport: httpx.BaseTransport | None,
) -> TriageResult:
    system = (
        "You are a defensive reconnaissance analyst for an AUTHORIZED security assessment. "
        "You only triage already-collected evidence; you never request exploitation, credential "
        "attacks, or out-of-scope actions. Given recon findings, rank hosts/subdomains/URLs by how "
        "much they warrant deeper but still safe enumeration (http probing, directory discovery, "
        "port scanning). Pay special attention to open ports on non-standard / high port numbers "
        "(e.g. 10002): these often host hidden web admin panels or internal services, so prioritize "
        "http probing and directory discovery on them. Respond with ONLY a JSON object of the form: "
        '{"summary": str, "targets": [{"target": str, "risk_score": 0.0-1.0, "rationale": str, '
        '"signals": [str], "suggested_modules": ["http_probe"|"dir_enum"|"port_scan"]}]}. '
        "Only reference targets that appear in the evidence."
    )
    user = "Recon evidence (JSON):\n" + json.dumps(evidence, ensure_ascii=False, sort_keys=True)
    raw = complete_json(
        provider=config.ai_provider,
        model=config.ai_model,
        api_key=api_key,
        system=system,
        user=user,
        timeout_seconds=config.ai_request_timeout_seconds,
        transport=transport,
    )
    result = TriageResult.model_validate(raw)
    result.source = "llm"
    result.model = resolve_model(config.ai_provider, config.ai_model)
    # Defensive trim: never let the model balloon the action set.
    result.targets = result.targets[:MAX_TARGETS]
    return result


def heuristic_triage(evidence: dict[str, Any]) -> TriageResult:
    """Deterministic risk scoring used offline and as the LLM fallback."""

    cve_targets = {
        str(item.get("target", "")).lower() for item in evidence.get("candidate_cves", [])
    }
    risks: dict[str, TargetRisk] = {}

    def bump(target: str, score: float, signal: str, module: str | None) -> None:
        target = (target or "").strip()
        if not target:
            return
        key = target.lower()
        existing = risks.get(key)
        if existing is None:
            existing = TargetRisk(target=target, risk_score=0.0)
            risks[key] = existing
        existing.risk_score = round(min(1.0, max(existing.risk_score, score)), 3)
        if signal and signal not in existing.signals:
            existing.signals.append(signal)
        if module and module not in existing.suggested_modules:
            existing.suggested_modules.append(module)  # type: ignore[arg-type]

    for host in evidence.get("subdomains", []):
        score, hits = _keyword_score(str(host))
        bump(str(host), max(0.2, score), hits or "subdomain", "http_probe")

    for item in evidence.get("live_hosts", []):
        url = str(item.get("url", ""))
        blob = f"{url} {item.get('title') or ''} {item.get('tech') or ''}"
        score, hits = _keyword_score(blob)
        status = _as_int(item.get("status"))
        if status in (401, 403):
            score = max(score, 0.55)
            hits = (hits + ",auth_gate").lstrip(",")
        bump(url or _host_of(url), max(0.35, score), hits or "live_host", "dir_enum")

    for item in evidence.get("open_ports", []):
        host = str(item.get("host", ""))
        port = _as_int(item.get("port"))
        if port in HIGH_RISK_PORTS:
            bump(host, 0.7, f"port:{port}/{HIGH_RISK_PORTS[port]}", None)
        elif port in WEB_PORTS:
            bump(host, 0.4, f"web_port:{port}", "http_probe")
        elif port is not None and port > 1024:
            # Hidden services tend to live on non-standard high ports (e.g. :10002).
            # Surface them for HTTP probing + directory discovery.
            bump(host, 0.6, f"non_standard_port:{port}", "http_probe")

    for key, risk in risks.items():
        if key in cve_targets or any(key in cve for cve in cve_targets):
            risk.risk_score = 0.9
            if "candidate_cve" not in risk.signals:
                risk.signals.append("candidate_cve")

    ordered = sorted(risks.values(), key=lambda r: r.risk_score, reverse=True)[:MAX_TARGETS]
    for risk in ordered:
        if not risk.rationale:
            risk.rationale = "; ".join(risk.signals) or "observed surface"
    summary = (
        f"Heuristic triage scored {len(ordered)} target(s); "
        f"{sum(1 for r in ordered if r.risk_score >= 0.6)} at/above the act threshold."
    )
    return TriageResult(summary=summary, targets=ordered, source="heuristic", model="")


def _keyword_score(value: str) -> tuple[float, str]:
    lowered = (value or "").lower()
    hits = [kw for kw in RISKY_KEYWORDS if kw in lowered]
    if not hits:
        return 0.0, ""
    score = min(0.85, 0.45 + 0.1 * len(hits))
    return score, ",".join(hits[:5])


def _first_str(evidence: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = evidence.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _host_of(url: str) -> str:
    try:
        return urlsplit(url).hostname or url
    except ValueError:
        return url
