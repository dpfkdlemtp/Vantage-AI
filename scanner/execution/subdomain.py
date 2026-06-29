from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from scanner import runner as runner_core
from scanner.adapters.assetfinder_runner import run_assetfinder_discovery
from scanner.adapters.assetfinder_runner import run_assetfinder_discovery as native_run_assetfinder_discovery
from scanner.adapters.crtsh_runner import fetch_crtsh_subdomains
from scanner.adapters.crtsh_runner import fetch_crtsh_subdomains as native_fetch_crtsh_subdomains
from scanner.adapters.securitytrails_runner import fetch_subdomains as native_fetch_subdomains
from scanner.adapters.subfinder_runner import run_subfinder_discovery
from scanner.adapters.subfinder_runner import run_subfinder_discovery as native_run_subfinder_discovery
from scanner.config import parse_scope_entries, resolve_scope_controls_path
from scanner.models import ArtifactRef, Finding
from scanner.state import (
    get_incomplete_tasks,
    mark_run_finished,
    mark_run_running,
    mark_task_completed,
    mark_task_failed,
    mark_task_running,
)
from scanner.storage import insert_artifact, insert_finding

@dataclass(frozen=True)
class PassiveSourceResult:
    source: str
    hosts: list[str]
    raw_output: str
    command: list[str] | None = None
    artifact_type: Literal["stdout", "raw_json"] = "stdout"
    content_type: str = "text/plain"
    file_extension: str = "txt"
    metadata: dict[str, Any] | None = None


@dataclass(frozen=True)
class RunScopeControls:
    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()


def execute_subdomain_enum_tasks(run_id: str, *, workspace: Path | None = None) -> dict[str, Any]:
    connection = runner_core._open_run_connection(run_id, workspace=workspace)
    try:
        run = runner_core._require_run(connection, run_id)
        scope_controls = load_run_scope_controls(run_id, workspace=workspace)
        tasks = [
            task
            for task in get_incomplete_tasks(connection, run_id)
            if task.module == "subdomain_enum"
        ]
        if not tasks:
            return {
                "run_id": run_id,
                "processed_task_count": 0,
                "completed_task_count": 0,
                "failed_task_count": 0,
                "finding_count": 0,
                "artifact_count": 0,
                "tasks": [],
            }

        mark_run_running(connection, run_id)
        completed_task_count = 0
        failed_task_count = 0
        finding_count = 0
        artifact_count = 0
        task_summaries: list[dict[str, Any]] = []

        for task in tasks:
            try:
                runner_core._clear_task_outputs(connection, task)
                root_domain = task.scope.strip().lower().rstrip(".")
                mark_task_running(
                    connection,
                    task.task_id,
                    cursor_json={"stage": "subdomain_discovery", "target": root_domain},
                )
                source_results, source_errors = _collect_source_results(run, root_domain)
                if not source_results:
                    raise RuntimeError(_failure_message(source_errors))

                artifacts = _write_source_artifacts(run, task, source_results)
                for artifact in artifacts:
                    insert_artifact(connection, artifact)
                findings = _normalize_merged_findings(
                    source_results,
                    root_domain=root_domain,
                    run_id=run.run_id,
                    task_id=task.task_id,
                    scope_controls=scope_controls,
                )
                scope_cursor_json = build_scope_cursor_json(
                    scope_controls,
                    input_count=findings["discovered_count"],
                    allowed_count=len(findings["items"]),
                    skipped_targets=findings["skipped_targets"],
                )
                for finding in findings["items"]:
                    insert_finding(connection, finding)
                hostnames_for_takeover = sorted({
                    str(item.target).strip().lower()
                    for item in findings["items"]
                    if str(item.target).strip()
                })
                takeover_findings = run_subzy_takeover_check(
                    hostnames_for_takeover,
                    config=run.config,
                    run_id=run.run_id,
                    task_id=task.task_id,
                )
                for tf in takeover_findings:
                    insert_finding(connection, tf)
                artifact_paths = [str(artifact.path) for artifact in artifacts]
                mark_task_completed(
                    connection,
                    task.task_id,
                    cursor_json={
                        "artifact_count": len(artifacts),
                        "artifact_paths": artifact_paths,
                        "finding_count": len(findings["items"]) + len(takeover_findings),
                        "takeover_finding_count": len(takeover_findings),
                        "record_count": len(findings["items"]),
                        "source_count": len(source_results),
                        "sources": [result.source for result in source_results],
                        "source_errors": source_errors,
                        **scope_cursor_json,
                    },
                )
                completed_task_count += 1
                finding_count += len(findings["items"]) + len(takeover_findings)
                artifact_count += len(artifacts)
                task_summary: dict[str, Any] = {
                    "task_id": task.task_id,
                    "module": task.module,
                    "tool": task.tool,
                    "scope": task.scope,
                    "state": "completed",
                    "finding_count": len(findings["items"]),
                    "artifact_paths": artifact_paths,
                    "sources": [result.source for result in source_results],
                    "scope_skipped_count": len(findings["skipped_targets"]),
                    "scope_skipped_targets": findings["skipped_targets"],
                }
                if len(artifact_paths) == 1:
                    task_summary["artifact_path"] = artifact_paths[0]
                if source_errors:
                    task_summary["source_errors"] = source_errors
                task_summaries.append(task_summary)
            except Exception as exc:
                mark_task_failed(
                    connection,
                    task.task_id,
                    str(exc),
                    cursor_json={"stage": "subdomain_discovery_failed", "target": task.scope},
                )
                failed_task_count += 1
                task_summaries.append(
                    {
                        "task_id": task.task_id,
                        "module": task.module,
                        "tool": task.tool,
                        "scope": task.scope,
                        "state": "failed",
                        "last_error": str(exc),
                    }
                )

        if not get_incomplete_tasks(connection, run_id):
            mark_run_finished(connection, run_id, "completed")

        return {
            "run_id": run_id,
            "processed_task_count": len(tasks),
            "completed_task_count": completed_task_count,
            "failed_task_count": failed_task_count,
            "finding_count": finding_count,
            "artifact_count": artifact_count,
            "tasks": task_summaries,
        }
    finally:
        connection.close()


def _collect_source_results(
    run: Any,
    root_domain: str,
) -> tuple[list[PassiveSourceResult], list[str]]:
    source_results: list[PassiveSourceResult] = []
    source_errors: list[str] = []

    if _legacy_source_enabled():
        try:
            source_results.append(_run_legacy_source(run, root_domain))
        except Exception as exc:
            source_errors.append(f"legacy_fetch: {exc}")
        return source_results, source_errors

    source_loaders = [
        ("subfinder", _run_subfinder_source),
        ("assetfinder", _run_assetfinder_source),
    ]
    if _crtsh_enabled():
        source_loaders.append(("crtsh", _run_crtsh_source))

    for source_name, loader in source_loaders:
        try:
            source_results.append(loader(root_domain, run.config))
        except Exception as exc:
            source_errors.append(f"{source_name}: {exc}")

    if getattr(run.config, "subdomain_bruteforce_enabled", False):
        try:
            source_results.append(_run_dnsx_source(root_domain, run.config))
        except Exception as exc:
            source_errors.append(f"dnsx: {exc}")

    return source_results, source_errors


def _run_subfinder_source(root_domain: str, config: Any) -> PassiveSourceResult:
    try:
        result = run_subfinder_discovery(root_domain, subfinder_bin=config.subfinder_bin)
    except TypeError:
        result = run_subfinder_discovery(root_domain)
    return PassiveSourceResult(
        source="subfinder",
        hosts=result.hosts,
        raw_output=result.raw_output,
        command=result.command,
        metadata={"command": result.command, "record_count": len(result.hosts), "source": "subfinder"},
    )


def _run_assetfinder_source(root_domain: str, config: Any) -> PassiveSourceResult:
    try:
        result = run_assetfinder_discovery(root_domain, assetfinder_bin=config.assetfinder_bin)
    except TypeError:
        result = run_assetfinder_discovery(root_domain)
    return PassiveSourceResult(
        source="assetfinder",
        hosts=result.hosts,
        raw_output=result.raw_output,
        command=result.command,
        metadata={"command": result.command, "record_count": len(result.hosts), "source": "assetfinder"},
    )


def _run_dnsx_source(root_domain: str, config: Any) -> PassiveSourceResult:
    from scanner.adapters.dnsx_runner import (
        BUILTIN_SUBDOMAIN_WORDS,
        is_dnsx_available,
        run_dnsx_bruteforce_detailed,
    )

    dnsx_bin = str(getattr(config, "dnsx_bin", "dnsx") or "dnsx")
    if not is_dnsx_available(dnsx_bin):
        raise RuntimeError(f"dnsx not found at '{dnsx_bin}'")

    result = run_dnsx_bruteforce_detailed(root_domain, dnsx_bin=dnsx_bin)
    resolved = result.hosts
    raw = "\n".join(resolved)
    return PassiveSourceResult(
        source="dnsx",
        hosts=resolved,
        raw_output=raw,
        metadata={
            "record_count": len(resolved),
            "source": "dnsx",
            "wordlist_size": len(BUILTIN_SUBDOMAIN_WORDS),
            "wildcard_dns": bool(result.wildcard_ips),
            "wildcard_ips": result.wildcard_ips,
            "wildcard_filtered_count": len(result.filtered_hosts),
        },
    )


def run_subzy_takeover_check(
    hostnames: list[str],
    *,
    config: Any,
    run_id: str,
    task_id: str,
) -> list[Finding]:
    """Probe discovered subdomains for takeover via subzy. Returns Finding list."""
    from datetime import UTC, datetime
    from uuid import uuid4

    from scanner.adapters.subzy_runner import SubzyError, is_subzy_available, run_subzy

    subzy_bin = str(getattr(config, "subzy_bin", "subzy") or "subzy")
    enabled = bool(getattr(config, "subzy_enabled", False))
    if not enabled or not hostnames:
        return []
    if not is_subzy_available(subzy_bin):
        return []
    try:
        result = run_subzy(hostnames, subzy_bin=subzy_bin)
    except SubzyError:
        return []
    now = datetime.now(UTC)
    findings: list[Finding] = []
    for match in result.matches:
        if not match.vulnerable or not match.host:
            continue
        findings.append(Finding(
            finding_id=f"takeover-{uuid4().hex[:12]}",
            run_id=run_id,
            task_id=task_id,
            module="subdomain_enum",
            target=match.host,
            status="candidate",
            summary=f"Subdomain takeover candidate ({match.service or 'unknown service'}): {match.host}",
            evidence_json={
                "type": "subdomain_takeover",
                "host": match.host,
                "service": match.service,
                "raw": match.raw,
            },
            tags=["subdomain-takeover", "critical", "subzy"],
            created_at=now,
        ))
    return findings


def _run_crtsh_source(root_domain: str, config: Any) -> PassiveSourceResult:
    result = fetch_crtsh_subdomains(root_domain)
    return PassiveSourceResult(
        source="crtsh",
        hosts=result.hosts,
        raw_output=result.raw_output,
        artifact_type="raw_json",
        content_type="application/json",
        file_extension="json",
        metadata={
            "query_url": result.query_url,
            "record_count": len(result.hosts),
            "entry_count": result.entry_count,
            "source": "crtsh",
        },
    )


def _run_legacy_source(run: Any, root_domain: str) -> PassiveSourceResult:
    result = runner_core.fetch_subdomains(
        root_domain,
        api_key_env_var=run.config.securitytrails_api_key_env or "SECURITYTRAILS_API_KEY",
    )
    raw_response = getattr(result, "raw_response", None)
    subdomains = getattr(result, "subdomains", [])
    record_count = getattr(result, "record_count", len(subdomains))
    payload = raw_response if isinstance(raw_response, dict) else {
        "subdomains": subdomains,
        "record_count": record_count,
    }
    return PassiveSourceResult(
        source="legacy_fetch",
        hosts=list(subdomains),
        raw_output=json.dumps(payload, indent=2, sort_keys=True),
        artifact_type="raw_json",
        content_type="application/json",
        file_extension="json",
        metadata={"record_count": record_count, "source": "legacy_fetch"},
    )


def _legacy_source_enabled() -> bool:
    return runner_core.fetch_subdomains is not native_fetch_subdomains


def _crtsh_enabled() -> bool:
    if fetch_crtsh_subdomains is not native_fetch_crtsh_subdomains:
        return True
    return (
        run_subfinder_discovery is native_run_subfinder_discovery
        and run_assetfinder_discovery is native_run_assetfinder_discovery
    )


def _failure_message(source_errors: list[str]) -> str:
    if source_errors:
        return "no subdomain discovery sources succeeded: " + "; ".join(source_errors)
    return "no subdomain discovery sources were available"


def _write_source_artifacts(
    run: Any,
    task: Any,
    source_results: list[PassiveSourceResult],
) -> list[ArtifactRef]:
    artifacts: list[ArtifactRef] = []
    for result in source_results:
        artifact_dir = run.config.artifacts_dir / result.source
        artifact_dir.mkdir(parents=True, exist_ok=True)
        artifact_path = artifact_dir / f"{task.task_id}.{result.file_extension}"
        raw_bytes = result.raw_output.encode("utf-8")
        artifact_path.write_text(result.raw_output, encoding="utf-8")
        digest = sha256(raw_bytes).hexdigest()
        artifacts.append(
            ArtifactRef(
                artifact_id=f"artifact-{task.task_id}-{result.source}-raw",
                run_id=run.run_id,
                task_id=task.task_id,
                phase_name="subdomain_enum",
                source_tool="orchestrator",
                artifact_type=result.artifact_type,
                path=artifact_path,
                sha256=digest,
                size_bytes=len(raw_bytes),
                content_type=result.content_type,
                created_at=runner_core._now(),
                metadata=result.metadata or {},
            )
        )
    return artifacts


def _normalize_merged_findings(
    source_results: list[PassiveSourceResult],
    *,
    root_domain: str,
    run_id: str,
    task_id: str,
    scope_controls: RunScopeControls,
) -> dict[str, Any]:
    merged_targets: set[str] = set()
    source_map: dict[str, set[str]] = {}
    for result in source_results:
        for raw_host in result.hosts:
            target = _normalize_subdomain_target(raw_host, root_domain)
            if target is None or target == root_domain:
                continue
            merged_targets.add(target)
            source_map.setdefault(target, set()).add(result.source)

    allowed_targets, skipped_targets = filter_scope_hosts(sorted(merged_targets), scope_controls)
    merged_findings: list[Finding] = []
    created_at = runner_core._now()
    record_count = len(allowed_targets)
    for target in allowed_targets:
        sources = sorted(source_map.get(target, set()))
        merged_findings.append(
            Finding(
                finding_id=_build_finding_id(run_id, task_id, target),
                run_id=run_id,
                task_id=task_id,
                module="subdomain_enum",
                target=target,
                status="observed",
                summary=_merged_summary(target, sources),
                evidence_json={
                    "source_tool": sources[0] if len(sources) == 1 else "multiple",
                    "source_tools": sources,
                    "root_domain": root_domain,
                    "subdomain": _subdomain_label(target, root_domain),
                    "hostname": target,
                    "record_count": record_count,
                },
                tags=["subdomain", "passive", *sources],
                created_at=created_at,
            )
        )
    return {
        "items": merged_findings,
        "discovered_count": len(merged_targets),
        "skipped_targets": skipped_targets,
    }


def _build_finding_id(run_id: str, task_id: str, target: str) -> str:
    digest = sha256(f"{run_id}:{task_id}:subdomain_enum:{target}".encode("utf-8")).hexdigest()
    return f"finding-{digest[:24]}"


def _normalize_subdomain_target(value: str, root_domain: str) -> str | None:
    normalized = value.strip().lower().rstrip(".")
    if not normalized:
        return None
    if normalized == root_domain or normalized.endswith(f".{root_domain}"):
        return normalized
    if "." not in normalized:
        return f"{normalized}.{root_domain}"
    return None


def _subdomain_label(target: str, root_domain: str) -> str:
    suffix = f".{root_domain}"
    if target.endswith(suffix):
        return target[: -len(suffix)]
    return target


def _merged_summary(target: str, sources: list[str]) -> str:
    if not sources:
        return f"Discovered subdomain {target}"
    return f"Discovered subdomain {target} from {', '.join(sources)}"


def load_run_scope_controls(run_id: str, *, workspace: Path | None = None) -> RunScopeControls:
    path = resolve_scope_controls_path(run_id, workspace=workspace)
    if not path.exists():
        return RunScopeControls()
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return RunScopeControls()
    if not isinstance(loaded, dict):
        return RunScopeControls()
    return RunScopeControls(
        include=tuple(parse_scope_entries(loaded.get("include"))),
        exclude=tuple(parse_scope_entries(loaded.get("exclude"))),
    )


def build_scope_cursor_json(
    scope_controls: RunScopeControls,
    *,
    input_count: int,
    allowed_count: int,
    skipped_targets: list[str],
) -> dict[str, Any]:
    return {
        "input_count": input_count,
        "total_targets": allowed_count,
        "scope_include": list(scope_controls.include),
        "scope_exclude": list(scope_controls.exclude),
        "scope_input_count": input_count,
        "scope_allowed_count": allowed_count,
        "scope_skipped_count": len(skipped_targets),
        "scope_skipped_targets": skipped_targets,
    }


def filter_scope_hosts(hosts: list[str], scope_controls: RunScopeControls) -> tuple[list[str], list[str]]:
    allowed_hosts: list[str] = []
    skipped_hosts: list[str] = []
    seen_allowed: set[str] = set()
    seen_skipped: set[str] = set()
    for host in hosts:
        normalized_value = _normalize_scope_host_value(host)
        if not normalized_value:
            continue
        normalized_host = _normalize_scope_host(normalized_value)
        if not normalized_host:
            continue
        if _scope_allows_host(normalized_host, scope_controls):
            if normalized_value in seen_allowed:
                continue
            seen_allowed.add(normalized_value)
            allowed_hosts.append(normalized_value)
            continue
        if normalized_value in seen_skipped:
            continue
        seen_skipped.add(normalized_value)
        skipped_hosts.append(normalized_value)
    return allowed_hosts, skipped_hosts


def filter_scope_urls(urls: list[str], scope_controls: RunScopeControls) -> tuple[list[str], list[str]]:
    allowed_urls: list[str] = []
    skipped_urls: list[str] = []
    seen_allowed: set[str] = set()
    seen_skipped: set[str] = set()
    for url in urls:
        normalized_url = _normalize_scope_url(url)
        if not normalized_url:
            continue
        if _scope_allows_url(normalized_url, scope_controls):
            if normalized_url in seen_allowed:
                continue
            seen_allowed.add(normalized_url)
            allowed_urls.append(normalized_url)
            continue
        if normalized_url in seen_skipped:
            continue
        seen_skipped.add(normalized_url)
        skipped_urls.append(normalized_url)
    return allowed_urls, skipped_urls


def normalize_port_scan_execution_targets(targets: list[str]) -> list[str]:
    normalized_targets: list[str] = []
    seen_targets: set[str] = set()
    for target in targets:
        normalized_target = _normalize_port_scan_target(target)
        if not normalized_target or normalized_target in seen_targets:
            continue
        seen_targets.add(normalized_target)
        normalized_targets.append(normalized_target)
    return normalized_targets


def _scope_allows_host(host: str, scope_controls: RunScopeControls) -> bool:
    if any(_scope_rule_matches_host(rule, host) for rule in scope_controls.exclude):
        return False
    if not scope_controls.include:
        return True
    return any(_scope_rule_matches_host(rule, host) for rule in scope_controls.include)


def _scope_allows_url(url: str, scope_controls: RunScopeControls) -> bool:
    if any(_scope_rule_matches_url(rule, url) for rule in scope_controls.exclude):
        return False
    if not scope_controls.include:
        return True
    return any(_scope_rule_matches_url(rule, url) for rule in scope_controls.include)


def _scope_rule_matches_host(rule: str, host: str) -> bool:
    normalized_rule = _normalize_scope_host(rule)
    if not normalized_rule:
        return False
    return host == normalized_rule or host.endswith(f".{normalized_rule}")


def _scope_rule_matches_url(rule: str, url: str) -> bool:
    normalized_rule_url = _normalize_scope_url(rule)
    if normalized_rule_url and (
        url == normalized_rule_url or url.startswith(f"{normalized_rule_url.rstrip('/')}/")
    ):
        return True

    normalized_url_host_port = _normalize_scope_host_port(url)
    normalized_rule_host_port = _normalize_scope_host_port(rule)
    if (
        normalized_url_host_port
        and normalized_rule_host_port
        and ":" in normalized_rule_host_port
        and normalized_url_host_port == normalized_rule_host_port
    ):
        return True

    normalized_url_host = _normalize_scope_host(url)
    return bool(normalized_url_host) and _scope_rule_matches_host(rule, normalized_url_host)


def _normalize_scope_url(value: str) -> str | None:
    text = value.strip().lower()
    if not text or "://" not in text:
        return None
    parsed = urlsplit(text)
    if not parsed.scheme or not parsed.netloc:
        return None
    path = parsed.path.rstrip("/") or "/"
    netloc = parsed.hostname.lower().rstrip(".") if parsed.hostname else ""
    if not netloc:
        return None
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"
    return f"{parsed.scheme}://{netloc}{path}"


def _normalize_scope_host_value(value: str) -> str:
    return value.strip().lower().rstrip(".")


def _normalize_scope_host(value: str) -> str:
    text = _normalize_scope_host_value(value)
    if not text:
        return ""
    parsed = urlsplit(text) if "://" in text else None
    if parsed is not None and parsed.hostname:
        return parsed.hostname.lower().rstrip(".")
    head = text.split("/", 1)[0]
    if head.startswith("[") and "]" in head:
        return head[1 : head.index("]")]
    host, separator, port = head.rpartition(":")
    if separator and host and port.isdigit():
        return host.rstrip(".")
    return head.rstrip(".")


def _normalize_scope_host_port(value: str) -> str | None:
    text = value.strip().lower()
    if not text:
        return None
    parsed = urlsplit(text) if "://" in text else None
    if parsed is not None and parsed.hostname:
        host = parsed.hostname.lower().rstrip(".")
        return f"{host}:{parsed.port}" if parsed.port is not None else host
    head = text.split("/", 1)[0].rstrip(".")
    return head or None


def _normalize_port_scan_target(value: str) -> str:
    text = _normalize_scope_host_value(value)
    if not text:
        return ""
    if _is_ipv4_cidr_target(text):
        return text
    return _normalize_scope_host(text)


def _is_ipv4_cidr_target(value: str) -> bool:
    try:
        parsed = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return isinstance(parsed, ipaddress.IPv4Network)
