from __future__ import annotations

import json
import re
from pathlib import Path
from threading import Lock
from typing import Any, cast

from scanner.adapters import httpx_runner as httpx_adapter
from scanner.adapters.wappalyzer_runner import detect_technologies
from scanner import runner as runner_core
from scanner.config import build_web_headers, detect_auth_from_probe, summarize_web_headers
from scanner.execution.subdomain import build_scope_cursor_json, filter_scope_hosts, load_run_scope_controls
from scanner.normalizers.subdomain import normalize_httpx_probe_results
from scanner.state import (
    get_incomplete_tasks,
    get_task,
    mark_run_finished,
    mark_run_running,
    mark_task_completed,
    mark_task_failed,
    mark_task_running,
)
from scanner.models import Finding
from scanner.normalizers.headers import analyze_security_headers
from scanner.execution.waf_signatures import detect_waf
from scanner.storage import insert_artifact, insert_finding

HTTPX_RATIO_RE = re.compile(r"(?P<processed>\d+)\s*/\s*(?P<total>\d+)")
HTTPX_PERCENT_RE = re.compile(r"(?P<percent>\d+(?:\.\d+)?)%")


def execute_http_probe_tasks(run_id: str, *, workspace: Path | None = None) -> dict[str, Any]:
    connection = runner_core._open_run_connection(run_id, workspace=workspace)
    try:
        run = runner_core._require_run(connection, run_id)
        scope_controls = load_run_scope_controls(run_id, workspace=workspace)
        tasks = [
            task
            for task in get_incomplete_tasks(connection, run_id)
            if task.module == "http_probe" and task.tool == "httpx"
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
                run = runner_core._require_run(connection, run_id)
                runner_core._clear_task_outputs(connection, task)
                raw_probe_targets = runner_core._load_http_probe_targets(connection, run_id, task)
                probe_targets, skipped_targets = filter_scope_hosts(raw_probe_targets, scope_controls)
                scope_cursor_json = build_scope_cursor_json(
                    scope_controls,
                    input_count=len(raw_probe_targets),
                    allowed_count=len(probe_targets),
                    skipped_targets=skipped_targets,
                )
                prior_cursor = dict(get_task(connection, task.task_id).cursor_json or {})
                mark_task_running(
                    connection,
                    task.task_id,
                    cursor_json={**prior_cursor, "stage": "httpx_probe", **scope_cursor_json},
                )
                if not probe_targets:
                    empty_meta = runner_core.incremental_http_probe_cursor_meta(prior_cursor)
                    mark_task_completed(
                        connection,
                        task.task_id,
                        cursor_json={
                            "stage": "httpx_probe",
                            "probe_count": 0,
                            "finding_count": 0,
                            "artifact_count": 0,
                            "input_probe_urls": [],
                            **empty_meta,
                            **scope_cursor_json,
                        },
                    )
                    completed_task_count += 1
                    task_summaries.append(
                        {
                            "task_id": task.task_id,
                            "module": task.module,
                            "tool": task.tool,
                            "scope": task.scope,
                            "state": "completed",
                            "input_count": len(probe_targets),
                            "finding_count": 0,
                            "scope_skipped_count": len(skipped_targets),
                            "scope_skipped_targets": skipped_targets,
                        }
                    )
                    continue
                run = runner_core._require_run(connection, run_id)
                request_headers = build_web_headers(run.config.extra_headers)
                latest_tool_progress: dict[str, Any] = {}
                def _sync_httpx_progress(progress: dict[str, Any]) -> None:
                    nonlocal latest_tool_progress
                    latest_tool_progress = dict(progress.get("tool_progress") or {})
                    runner_core._merge_task_cursor_json(
                        connection,
                        task.task_id,
                        {
                            "stage": "httpx_probe",
                            "request_headers": summarize_web_headers(request_headers),
                            **scope_cursor_json,
                            **progress,
                        },
                    )
                result = _run_httpx_probe_with_headers(
                    probe_targets,
                    run=run,
                    request_headers=request_headers,
                    progress_callback=_sync_httpx_progress,
                )
                artifact = runner_core._write_httpx_artifact(run, task, result)
                insert_artifact(connection, artifact)
                findings = normalize_httpx_probe_results(
                    result,
                    run_id=run.run_id,
                    task_id=task.task_id,
                )
                detected_tech_by_url: dict[str, list[str]] = {}
                auth_detection_count = 0
                auth_required_count = 0
                for finding in findings:
                    evidence_json = dict(finding.evidence_json)
                    probe_url = str(evidence_json.get("url") or finding.target).strip()
                    status_code = _coerce_optional_int(evidence_json.get("status_code"))
                    if status_code is not None and status_code > 0 and probe_url:
                        if probe_url not in detected_tech_by_url:
                            detected_tech_by_url[probe_url] = detect_technologies(
                                probe_url,
                                timeout_seconds=3.0,
                            )
                        merged_tech = sorted(
                            {
                                str(item).strip()
                                for item in [
                                    *list(evidence_json.get("technologies") or []),
                                    *detected_tech_by_url.get(probe_url, []),
                                ]
                                if str(item).strip()
                            }
                        )
                        evidence_json["technologies"] = merged_tech
                        evidence_json["metadata_json"] = {
                            **dict(evidence_json.get("metadata_json") or {}),
                            "technologies": merged_tech,
                            "technology_source": "httpx+wappalyzer",
                        }
                    evidence_json["type"] = "http_probe"
                    auth_detection = detect_auth_from_probe(
                        url=probe_url,
                        status_code=status_code,
                        title=_coerce_optional_str(evidence_json.get("title")),
                        content_type=_coerce_optional_str(evidence_json.get("content_type")),
                    )
                    evidence_json["auth_detection"] = auth_detection
                    evidence_json["request_headers"] = summarize_web_headers(request_headers)
                    finding.evidence_json = evidence_json
                    if auth_detection["auth_state"] != "public":
                        auth_detection_count += 1
                    if auth_detection["likely_auth_required"]:
                        auth_required_count += 1
                        if "auth-required" not in finding.tags:
                            finding.tags.append("auth-required")
                    elif auth_detection["auth_state"] == "review" and "auth-review" not in finding.tags:
                        finding.tags.append("auth-review")
                bootstrap_evidence = runner_core.summarize_bootstrap_evidence(findings)
                
                root_domain_review = None
                from scanner.config import classify_target
                if classify_target(run.target) != "domain":
                    root_domain_review = runner_core.classify_root_domain_candidates(bootstrap_evidence, run.target)
                    for accepted in root_domain_review["accepted"]:
                        enqueue_result = runner_core.enqueue_subdomain_enum_if_needed(
                            connection,
                            run.run_id,
                            accepted["hostname"],
                            classify_result=root_domain_review,
                        )
                        accepted["enqueued"] = enqueue_result["enqueued"]

                for finding in findings:
                    insert_finding(connection, finding)
                header_findings = []
                for entry in result.entries:
                    if getattr(entry, "response_headers", None):
                        header_findings.extend(
                            analyze_security_headers(
                                entry.url,
                                entry.response_headers,
                                run_id=run.run_id,
                                task_id=task.task_id,
                            )
                        )
                for hf in header_findings:
                    insert_finding(connection, hf)

                # WAF/IPS fingerprinting → warn when responses are being filtered
                waf_findings: list[Finding] = []
                seen_waf: set[tuple[str, str]] = set()
                for entry in result.entries:
                    detections = detect_waf(
                        webserver=getattr(entry, "webserver", None),
                        title=getattr(entry, "title", None),
                        response_headers=getattr(entry, "response_headers", None) or {},
                        status_code=getattr(entry, "status_code", None),
                    )
                    if not detections:
                        continue
                    from datetime import UTC, datetime
                    from uuid import uuid4
                    waf_host = str(getattr(entry, "host", None) or entry.url)
                    now_waf = datetime.now(UTC)
                    for detection in detections:
                        dedup_key = (waf_host.casefold(), detection.vendor.casefold())
                        if dedup_key in seen_waf:
                            continue
                        seen_waf.add(dedup_key)
                        waf_findings.append(Finding(
                            finding_id=f"waf-{uuid4().hex[:12]}",
                            run_id=run.run_id,
                            task_id=task.task_id,
                            module="http_probe",
                            target=waf_host,
                            status="observed",
                            summary=(
                                f"WAF/IPS detected on {waf_host}: {detection.vendor} "
                                "— downstream scan results may be filtered/blocked"
                            ),
                            evidence_json={
                                "type": "waf_detected",
                                "host": waf_host,
                                "url": entry.url,
                                "vendor": detection.vendor,
                                "indicators": detection.indicators,
                                "status_code": getattr(entry, "status_code", None),
                            },
                            tags=["waf", "ips", "warning"],
                            created_at=now_waf,
                        ))
                for wf in waf_findings:
                    insert_finding(connection, wf)

                # gau (wayback) → historical URL recovery
                gau_findings: list[Finding] = []
                if bool(getattr(run.config, "gau_enabled", False)):
                    from datetime import UTC, datetime
                    from uuid import uuid4
                    from scanner.adapters.gau_runner import (
                        GauError,
                        group_urls_by_host,
                        is_gau_available,
                        run_gau,
                    )
                    gau_bin = str(getattr(run.config, "gau_bin", "gau") or "gau")
                    gau_max = int(getattr(run.config, "gau_max_urls_per_host", 500) or 500)
                    if is_gau_available(gau_bin):
                        # Extract unique hostnames from result for gau input
                        gau_targets = sorted({
                            entry.host for entry in result.entries
                            if entry.host and "." in entry.host
                        })
                        if gau_targets:
                            try:
                                gau_result = run_gau(gau_targets, gau_bin=gau_bin)
                            except GauError:
                                gau_result = None
                            if gau_result and gau_result.urls:
                                grouped = group_urls_by_host(gau_result.urls)
                                now_gau = datetime.now(UTC)
                                for host, host_urls in grouped.items():
                                    trimmed = host_urls[:gau_max]
                                    if not trimmed:
                                        continue
                                    gau_findings.append(Finding(
                                        finding_id=f"gau-{uuid4().hex[:12]}",
                                        run_id=run.run_id,
                                        task_id=task.task_id,
                                        module="http_probe",
                                        target=host,
                                        status="observed",
                                        summary=f"Historical URLs recovered via gau ({len(trimmed)} URLs)",
                                        evidence_json={
                                            "type": "wayback_urls",
                                            "host": host,
                                            "url_count": len(trimmed),
                                            "total_seen": len(host_urls),
                                            "urls": trimmed,
                                        },
                                        tags=["wayback", "gau", "historical-url"],
                                        created_at=now_gau,
                                    ))
                                for gf in gau_findings:
                                    insert_finding(connection, gf)

                # TLS SAN extraction → new subdomain candidates
                tls_findings: list[Finding] = []
                if bool(getattr(run.config, "tls_san_discovery_enabled", False)):
                    from datetime import UTC, datetime
                    from uuid import uuid4
                    san_hosts = extract_tls_san_hostnames(list(result.entries))
                    seen_targets = {f.target.strip().lower() for f in findings}
                    now = datetime.now(UTC)
                    for host in san_hosts:
                        if host in seen_targets:
                            continue
                        tls_findings.append(Finding(
                            finding_id=f"san-{uuid4().hex[:12]}",
                            run_id=run.run_id,
                            task_id=task.task_id,
                            module="http_probe",
                            target=host,
                            status="observed",
                            summary=f"Hostname discovered via TLS SAN: {host}",
                            evidence_json={
                                "type": "tls_san_discovery",
                                "host": host,
                            },
                            tags=["tls-san", "discovery"],
                            created_at=now,
                        ))
                    for tf in tls_findings:
                        insert_finding(connection, tf)
                    if san_hosts:
                        runner_core.enqueue_tls_san_http_probe_tasks(
                            connection,
                            run.run_id,
                            hostnames=san_hosts,
                            trigger_task_id=task.task_id,
                        )

                # Auth form auto-login → session cookies for downstream stages
                auth_cookies: list[dict[str, Any]] = []
                auth_cookie_header = ""
                auth_login_summary: dict[str, Any] = {}
                if bool(getattr(run.config, "auth_login_enabled", False)):
                    auth_cookies, auth_cookie_header, auth_login_summary = _attempt_auth_login(run.config)

                # JS render + optional SPA crawling
                js_render_findings: list[Finding] = []
                js_render_summary: dict[str, Any] = {}
                if bool(getattr(run.config, "js_render_enabled", False)):
                    js_render_findings, js_render_summary = _run_js_render(
                        result=result,
                        config=run.config,
                        run_id=run.run_id,
                        task_id=task.task_id,
                        request_headers=request_headers,
                        cookies=auth_cookies,
                    )
                    for jf in js_render_findings:
                        insert_finding(connection, jf)

                prior_after = dict(get_task(connection, task.task_id).cursor_json or {})
                inc_meta = runner_core.incremental_http_probe_cursor_meta(prior_after)
                mark_task_completed(
                    connection,
                    task.task_id,
                    cursor_json={
                        "artifact_path": str(artifact.path),
                        "probe_count": len(result.entries),
                        "finding_count": len(findings) + len(header_findings) + len(waf_findings) + len(tls_findings) + len(gau_findings) + len(js_render_findings),
                        "header_finding_count": len(header_findings),
                        "waf_finding_count": len(waf_findings),
                        "tls_san_finding_count": len(tls_findings),
                        "gau_finding_count": len(gau_findings),
                        "js_render_finding_count": len(js_render_findings),
                        "js_render_summary": js_render_summary,
                        "auth_login_summary": auth_login_summary,
                        "auth_cookie_header_present": bool(auth_cookie_header),
                        "artifact_count": 1,
                        "request_headers": summarize_web_headers(request_headers),
                        "auth_detection_count": auth_detection_count,
                        "auth_required_count": auth_required_count,
                        "tool_progress": latest_tool_progress,
                        "bootstrap_evidence": bootstrap_evidence,
                        "root_domain_review": root_domain_review,
                        "input_probe_urls": sorted(probe_targets),
                        **inc_meta,
                        **scope_cursor_json,
                    },
                )
                runner_core.maybe_enqueue_incremental_dir_enum_tasks(
                    connection,
                    run.run_id,
                    http_probe_task_id=task.task_id,
                )
                completed_task_count += 1
                finding_count += len(findings) + len(header_findings) + len(waf_findings) + len(tls_findings) + len(gau_findings) + len(js_render_findings)
                artifact_count += 1
                task_summaries.append(
                    {
                        "task_id": task.task_id,
                        "module": task.module,
                        "tool": task.tool,
                        "scope": task.scope,
                        "state": "completed",
                        "input_count": len(probe_targets),
                        "finding_count": len(findings),
                        "artifact_path": str(artifact.path),
                        "scope_skipped_count": len(skipped_targets),
                        "scope_skipped_targets": skipped_targets,
                    }
                )
            except Exception as exc:
                mark_task_failed(
                    connection,
                    task.task_id,
                    str(exc),
                    cursor_json={"stage": "httpx_failed"},
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


def _run_httpx_probe_with_headers(
    targets: list[str],
    *,
    run: Any,
    request_headers: dict[str, str],
    progress_callback: Any | None = None,
) -> httpx_adapter.HttpxRunResult:
    proxy_mode = str(getattr(run.config, "proxy_mode", "none") or "none").strip().lower()
    proxy_url = str(getattr(run.config, "proxy_url", "") or "").strip()
    proxy_value = proxy_url if proxy_mode in {"http", "socks"} and proxy_url else None
    if runner_core.run_httpx_probe.__module__ != "scanner.adapters.httpx_runner":
        try:
            return runner_core.run_httpx_probe(
                targets,
                httpx_bin=run.config.httpx_bin,
                profile=run.config.profile,
                timeout_seconds=run.config.httpx_timeout_seconds,
                threads=run.config.httpx_threads,
                rate_limit_per_second=run.config.httpx_rate_limit_per_second,
                proxy=proxy_value,
            )
        except TypeError:
            return runner_core.run_httpx_probe(
                targets,
                httpx_bin=run.config.httpx_bin,
                profile=run.config.profile,
                timeout_seconds=run.config.httpx_timeout_seconds,
                threads=run.config.httpx_threads,
                rate_limit_per_second=run.config.httpx_rate_limit_per_second,
            )

    normalized_targets = sorted({target.strip() for target in targets if target.strip()})
    command = httpx_adapter._build_httpx_command(
        httpx_bin=run.config.httpx_bin,
        profile=run.config.profile,
        timeout_seconds=run.config.httpx_timeout_seconds,
        threads=run.config.httpx_threads,
        rate_limit_per_second=run.config.httpx_rate_limit_per_second,
        proxy=proxy_value,
    )
    for name, value in request_headers.items():
        command.extend(["-H", f"{name}: {value}"])
    if not normalized_targets:
        return httpx_adapter.HttpxRunResult(command=command, targets=[], entries=[], raw_output="")
    if httpx_adapter._default_runner.__module__ != "scanner.adapters.httpx_runner":
        completed = httpx_adapter._default_runner(command, "\n".join(normalized_targets))
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip() or "httpx command failed"
            raise httpx_adapter.HttpxError(f"httpx exited with code {completed.returncode}: {detail}")
        raw_output = completed.stdout
        if not raw_output.strip():
            return httpx_adapter.HttpxRunResult(command=command, targets=normalized_targets, entries=[], raw_output=raw_output)
        return httpx_adapter.HttpxRunResult(
            command=command,
            targets=normalized_targets,
            entries=httpx_adapter._parse_jsonl_output(raw_output),
            raw_output=raw_output,
        )
    command.extend(["-stats", "-si", "2"])
    progress_state = {
        "processed_count": 0,
        "total_count": len(normalized_targets),
        "percent": 0.0,
        "stats_line": "",
    }
    state_lock = Lock()
    parsed_entries: list[httpx_adapter.HttpxProbeResult] = []

    def _handle_stdout(line: str) -> None:
        stripped = line.strip()
        if not stripped:
            return
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            return
        if not isinstance(payload, dict):
            return
        with state_lock:
            parsed_entries.append(httpx_adapter._parse_probe_entry(payload))
            progress_state["processed_count"] = max(
                cast(int, progress_state["processed_count"]),
                len(parsed_entries),
            )

    def _handle_stderr(line: str) -> None:
        ratio_match = HTTPX_RATIO_RE.search(line)
        percent_match = HTTPX_PERCENT_RE.search(line)
        with state_lock:
            progress_state["stats_line"] = line.strip()
            if ratio_match is not None:
                progress_state["processed_count"] = max(
                    cast(int, progress_state["processed_count"]),
                    int(ratio_match.group("processed")),
                )
                progress_state["total_count"] = max(
                    cast(int, progress_state["total_count"]),
                    int(ratio_match.group("total")),
                )
            if percent_match is not None:
                progress_state["percent"] = float(percent_match.group("percent"))

    def _snapshot() -> None:
        if progress_callback is None:
            return
        with state_lock:
            total_count = max(cast(int, progress_state["total_count"]), len(normalized_targets))
            processed_count = min(cast(int, progress_state["processed_count"]), total_count)
            percent = cast(float, progress_state["percent"])
            if total_count > 0 and percent <= 0.0:
                percent = round((processed_count / total_count) * 100, 2)
            snapshot = {
                "processed_count": processed_count,
                "total_targets": total_count,
                "tool_progress": {
                    "tool": "httpx",
                    "processed_count": processed_count,
                    "total_count": total_count,
                    "percent": percent,
                    "stats_line": str(progress_state["stats_line"]),
                },
            }
        progress_callback(snapshot)

    completed = runner_core._run_command_with_live_progress(
        command,
        stdin_text="\n".join(normalized_targets),
        stdout_handler=_handle_stdout,
        stderr_handler=_handle_stderr,
        snapshot_handler=_snapshot,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "httpx command failed"
        raise httpx_adapter.HttpxError(f"httpx exited with code {completed.returncode}: {detail}")
    raw_output = completed.stdout
    if not raw_output.strip():
        return httpx_adapter.HttpxRunResult(command=command, targets=normalized_targets, entries=[], raw_output=raw_output)
    return httpx_adapter.HttpxRunResult(
        command=command,
        targets=normalized_targets,
        entries=list(parsed_entries) if parsed_entries else httpx_adapter._parse_jsonl_output(raw_output),
        raw_output=raw_output,
    )


def _coerce_optional_int(value: object) -> int | None:
    return value if isinstance(value, int) else None


def _coerce_optional_str(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def extract_tls_san_hostnames(entries: list[Any], *, root_domain_hint: str = "") -> list[str]:
    """Extract Subject Alt Names from httpx -tls-grab output across entries.

    Returns deduplicated, lowercased hostnames (no wildcards). Filters out
    obvious junk like empty strings and IP literals.
    """
    found: set[str] = set()
    for entry in entries:
        raw = getattr(entry, "raw_entry", None) or {}
        tls = raw.get("tls") or raw.get("tls-grab") or {}
        if not isinstance(tls, dict):
            continue
        candidates: list[str] = []
        subject_cn = tls.get("subject_cn") or tls.get("subject_common_name")
        if isinstance(subject_cn, str):
            candidates.append(subject_cn)
        for key in ("subject_an", "subject_alt_names", "dns_names", "san"):
            value = tls.get(key)
            if isinstance(value, list):
                candidates.extend(v for v in value if isinstance(v, str))
            elif isinstance(value, str):
                candidates.append(value)
        for candidate in candidates:
            name = candidate.strip().lower().lstrip("*.")
            if not name or " " in name or "/" in name:
                continue
            # Skip IP literals
            if all(part.isdigit() for part in name.split(".")) and name.count(".") == 3:
                continue
            if root_domain_hint and not name.endswith(root_domain_hint.lower()):
                # Still keep — TLS SAN may reveal valid cross-domain assets;
                # caller can filter further.
                pass
            found.add(name)
    return sorted(found)


def _attempt_auth_login(config: Any) -> tuple[list[dict[str, Any]], str, dict[str, Any]]:
    """Try to log in via Playwright. Returns (cookies, cookie_header, summary).

    Returns empty results on any failure (no exception propagation).
    """
    from scanner.adapters.playwright_runner import auto_login, is_playwright_available

    login_url = str(getattr(config, "auth_login_url", "") or "").strip()
    username = str(getattr(config, "auth_username", "") or "").strip()
    password = str(getattr(config, "auth_password", "") or "")
    if not (login_url and username and password):
        return [], "", {"skipped": True, "reason": "missing login_url/username/password"}
    if not is_playwright_available():
        return [], "", {"skipped": True, "reason": "playwright not installed"}

    user_hints = [h.strip() for h in str(getattr(config, "auth_username_field_hints", "") or "").split(",") if h.strip()]
    pass_hints = [h.strip() for h in str(getattr(config, "auth_password_field_hints", "") or "").split(",") if h.strip()]
    success_keyword = str(getattr(config, "auth_login_success_keyword", "") or "").strip()

    kwargs: dict[str, Any] = {"success_url_keyword": success_keyword}
    if user_hints:
        kwargs["username_field_hints"] = user_hints
    if pass_hints:
        kwargs["password_field_hints"] = pass_hints

    result = auto_login(login_url, username, password, **kwargs)
    summary = {
        "skipped": False,
        "success": result.success,
        "final_url": result.final_url,
        "cookie_count": len(result.cookies),
        "message": result.message,
    }
    return list(result.cookies), result.cookie_header, summary


def _run_js_render(
    *,
    result: Any,
    config: Any,
    run_id: str,
    task_id: str,
    request_headers: dict[str, str],
    cookies: list[dict[str, Any]],
) -> tuple[list[Finding], dict[str, Any]]:
    """Render live HTTP probe targets via Playwright; emit findings for endpoints.

    Returns (findings, summary). Findings include discovered XHR endpoints and
    SPA DOM links not visible in static HTTP responses.
    """
    from datetime import UTC, datetime
    from uuid import uuid4

    from scanner.adapters.playwright_runner import crawl_pages, is_playwright_available

    summary: dict[str, Any] = {"skipped": False, "pages": 0, "endpoints": 0, "spa_crawled": False}
    if not is_playwright_available():
        summary["skipped"] = True
        summary["reason"] = "playwright not installed"
        return [], summary

    max_hosts = int(getattr(config, "js_render_max_hosts", 50) or 50)
    timeout_seconds = int(getattr(config, "js_render_timeout_seconds", 15) or 15)
    spa_enabled = bool(getattr(config, "spa_crawl_enabled", False))
    spa_depth = int(getattr(config, "spa_crawl_max_depth", 2) or 2) if spa_enabled else 0
    spa_max_pages = int(getattr(config, "spa_crawl_max_pages", 50) or 50) if spa_enabled else max_hosts
    same_origin = bool(getattr(config, "spa_crawl_same_origin_only", True))

    seed_urls: list[str] = []
    seen_hosts: set[str] = set()
    for entry in (result.entries or [])[:max_hosts * 4]:  # broader pick before dedup
        url = getattr(entry, "url", "")
        host = getattr(entry, "host", "")
        status = getattr(entry, "status_code", 0) or 0
        if not url or status >= 400 or not host:
            continue
        if host in seen_hosts:
            continue
        seen_hosts.add(host)
        seed_urls.append(url)
        if len(seed_urls) >= max_hosts:
            break
    if not seed_urls:
        summary["skipped"] = True
        summary["reason"] = "no live targets to render"
        return [], summary

    crawl_result = crawl_pages(
        seed_urls,
        max_depth=spa_depth,
        max_pages=spa_max_pages,
        timeout_seconds=timeout_seconds,
        same_origin_only=same_origin,
        extra_headers=dict(request_headers) if request_headers else None,
        cookies=cookies,
    )
    summary["pages"] = len(crawl_result.pages)
    summary["endpoints"] = len(crawl_result.discovered_endpoints)
    summary["spa_crawled"] = spa_enabled

    findings: list[Finding] = []
    now = datetime.now(UTC)
    for page in crawl_result.pages:
        if not page.dom_links and not page.xhr_endpoints and not page.forms:
            continue
        findings.append(Finding(
            finding_id=f"jsrender-{uuid4().hex[:12]}",
            run_id=run_id,
            task_id=task_id,
            module="http_probe",
            target=page.final_url or page.url,
            status="observed",
            summary=f"JS-rendered page: {len(page.dom_links)} links, {len(page.xhr_endpoints)} XHR endpoints, {len(page.forms)} forms",
            evidence_json={
                "type": "js_rendered_page",
                "url": page.url,
                "final_url": page.final_url,
                "status": page.status,
                "title": page.title,
                "dom_links": page.dom_links[:200],
                "js_files": page.js_files[:50],
                "xhr_endpoints": page.xhr_endpoints[:100],
                "forms": [
                    {
                        "method": f.method,
                        "action": f.action,
                        "fields": f.fields,
                        "has_password": f.has_password,
                    } for f in page.forms[:20]
                ],
            },
            tags=["js-render", "spa" if spa_enabled else "single-page"],
            created_at=now,
        ))
    return findings, summary
