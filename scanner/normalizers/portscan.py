from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256

from scanner.adapters.nmap_runner import NmapRunResult
from scanner.models import Finding


def normalize_nmap_results(
    result: NmapRunResult,
    *,
    run_id: str,
    task_id: str,
    observed_at: datetime | None = None,
) -> list[Finding]:
    created_at = observed_at or datetime.now(UTC)
    findings: list[Finding] = []
    seen_targets: set[str] = set()

    for host_result in result.hosts:
        for port_result in host_result.ports:
            target = _target(host_result.host, host_result.ip, port_result.protocol, port_result.port)
            if target in seen_targets:
                continue
            seen_targets.add(target)
            findings.append(
                Finding(
                    finding_id=_build_finding_id(run_id, task_id, "port_scan", target),
                    run_id=run_id,
                    task_id=task_id,
                    module="port_scan",
                    target=target,
                    status="observed",
                    summary=_summary(host_result.host, host_result.ip, port_result.protocol, port_result.port, port_result.state, port_result.service),
                    evidence_json=_compact_evidence(
                        {
                            "source_tool": "nmap",
                            "host": host_result.host,
                            "ip": host_result.ip,
                            "protocol": port_result.protocol,
                            "port": port_result.port,
                            "state": port_result.state,
                            "service": port_result.service,
                            "product": port_result.product,
                            "version": port_result.version,
                            "extrainfo": port_result.extrainfo,
                        }
                    ),
                    tags=_tags(port_result.protocol, port_result.state, port_result.service),
                    created_at=created_at,
                )
            )

    return findings


def _build_finding_id(run_id: str, task_id: str, module: str, target: str) -> str:
    digest = sha256(f"{run_id}:{task_id}:{module}:{target}".encode("utf-8")).hexdigest()
    return f"finding-{digest[:24]}"


def _target(host: str, ip: str | None, protocol: str, port: int) -> str:
    base = (host or ip or "unknown-host").strip().lower()
    return f"{base}:{protocol}/{port}"


def _summary(
    host: str,
    ip: str | None,
    protocol: str,
    port: int,
    state: str | None,
    service: str | None,
) -> str:
    location = host or ip or "unknown-host"
    state_label = state or "unknown"
    service_label = f" [{service}]" if service else ""
    return f"Observed {protocol}/{port} {state_label} on {location}{service_label}"


def _tags(protocol: str, state: str | None, service: str | None) -> list[str]:
    tags = ["portscan", "nmap", protocol]
    if state:
        tags.append(state)
    if service:
        tags.append("service")
    return tags


def _compact_evidence(evidence: dict[str, object]) -> dict[str, object]:
    compact: dict[str, object] = {}
    for key, value in evidence.items():
        if value is None:
            continue
        compact[key] = value
    return compact
