from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256

from scanner.adapters.httpx_runner import HttpxProbeResult, HttpxRunResult
from scanner.adapters.securitytrails_runner import SecurityTrailsSubdomainsResult
from scanner.models import Finding


def normalize_securitytrails_subdomains(
    result: SecurityTrailsSubdomainsResult,
    *,
    run_id: str,
    task_id: str,
    observed_at: datetime | None = None,
) -> list[Finding]:
    created_at = observed_at or datetime.now(UTC)
    findings: list[Finding] = []
    seen_targets: set[str] = set()

    for raw_subdomain in result.subdomains:
        target = _to_fqdn(raw_subdomain, result.root_domain)
        if not target or target == result.root_domain or target in seen_targets:
            continue
        seen_targets.add(target)
        findings.append(
            Finding(
                finding_id=_build_finding_id(run_id, task_id, "subdomain_enum", target),
                run_id=run_id,
                task_id=task_id,
                module="subdomain_enum",
                target=target,
                status="observed",
                summary=f"Discovered subdomain {target} from SecurityTrails",
                evidence_json={
                    "source_tool": "securitytrails",
                    "root_domain": result.root_domain,
                    "subdomain": raw_subdomain,
                    "hostname": target,
                    "record_count": result.record_count,
                    "api_endpoint": result.endpoint,
                },
                tags=["subdomain", "passive", "securitytrails"],
                created_at=created_at,
            )
        )

    return findings


def normalize_httpx_probe_results(
    result: HttpxRunResult,
    *,
    run_id: str,
    task_id: str,
    observed_at: datetime | None = None,
) -> list[Finding]:
    created_at = observed_at or datetime.now(UTC)
    findings: list[Finding] = []
    seen_targets: set[str] = set()

    for entry in result.entries:
        target, tags = _classify_httpx_target(entry)
        if not target or target in seen_targets:
            continue
        seen_targets.add(target)
        findings.append(
            Finding(
                finding_id=_build_finding_id(run_id, task_id, "http_probe", target),
                run_id=run_id,
                task_id=task_id,
                module="http_probe",
                target=target,
                status="observed",
                summary=_httpx_summary(target, tags, entry.status_code),
                evidence_json=_compact_evidence(
                    {
                        "source_tool": "httpx",
                        "input": entry.input_target,
                        "url": entry.url,
                        "host": entry.host,
                        "path": entry.path,
                        "scheme": entry.scheme,
                        "port": entry.port,
                        "status_code": entry.status_code,
                        "title": entry.title,
                        "technologies": entry.technologies,
                        "content_type": entry.content_type,
                        "webserver": entry.webserver,
                        "ip": entry.ip,
                        "cname": entry.cname,
                        "probe_status": entry.probe_status,
                    }
                ),
                tags=tags,
                created_at=created_at,
            )
        )

    return findings


def _build_finding_id(run_id: str, task_id: str, module: str, target: str) -> str:
    digest = sha256(f"{run_id}:{task_id}:{module}:{target}".encode("utf-8")).hexdigest()
    return f"finding-{digest[:24]}"


def _to_fqdn(raw_subdomain: str, root_domain: str) -> str:
    normalized = raw_subdomain.strip().lower().rstrip(".")
    if not normalized:
        return ""
    if normalized == root_domain or normalized.endswith(f".{root_domain}"):
        return normalized
    return f"{normalized}.{root_domain}"


def _classify_httpx_target(entry: HttpxProbeResult) -> tuple[str, list[str]]:
    is_path_like = entry.path not in ("", "/")
    status_code = entry.status_code if isinstance(entry.status_code, int) else None
    is_alive = bool(entry.url) and (
        (status_code is not None and status_code > 0)
        or str(entry.probe_status or "").lower() == "success"
    )
    target_kind = "path" if is_path_like and entry.url else "host"
    if target_kind == "path":
        target = entry.url
    elif is_alive:
        target = _httpx_host_target(entry)
    else:
        target = entry.input_target or _httpx_host_target(entry) or entry.url
    state_tag = "alive" if is_alive else "unreachable"
    return target, ["httpx", state_tag, target_kind]


def _httpx_host_target(entry: HttpxProbeResult) -> str:
    host = (entry.host or "").strip()
    if not host:
        return (entry.input_target or entry.url or "").strip()
    scheme = (entry.scheme or "").strip().lower()
    port = entry.port if isinstance(entry.port, int) else None
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    if port is not None and not default_port:
        return f"{host}:{port}"
    return host


def _httpx_summary(target: str, tags: list[str], status_code: int | None) -> str:
    label = "path" if "path" in tags else "host"
    suffix = f" [{status_code}]" if status_code is not None else ""
    state = "live" if "alive" in tags else "unreachable"
    return f"Observed {state} {label} {target}{suffix}"


def _compact_evidence(evidence: dict[str, object]) -> dict[str, object]:
    compact: dict[str, object] = {}
    for key, value in evidence.items():
        if value is None:
            continue
        if isinstance(value, list) and not value:
            continue
        compact[key] = value
    return compact
