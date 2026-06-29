from __future__ import annotations

import ipaddress
import json
import logging
import re
import sqlite3
import subprocess
import threading
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from time import monotonic, sleep
from typing import Any, Sequence, cast
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from scanner.adapters.ffuf_runner import FfufRunResult, run_ffuf_scan as _run_ffuf_scan
from scanner.adapters.httpx_runner import HttpxRunResult, run_httpx_probe as _run_httpx_probe
from scanner.adapters.nmap_runner import NmapRunResult, run_nmap_scan as _run_nmap_scan
from scanner.adapters.securitytrails_runner import (
    SecurityTrailsSubdomainsResult,
    fetch_subdomains as _fetch_subdomains,
)
from scanner.config import (
    build_scan_config,
    classify_target,
    plan_enabled_phases,
    resolve_state_db_path,
    resolve_tool,
)
from scanner.execution.cve_match import execute_cve_match_tasks as _execute_cve_match_tasks
from scanner.models import ArtifactRef, Finding, PhaseName, RunState, ScanConfig, ScanPhase, TaskState, TaskStatus
from scanner.state import (
    cancel_run_tasks,
    get_incomplete_tasks,
    get_run,
    get_task,
    mark_run_cancelled,
    mark_task_completed,
)
from scanner.state import get_tasks as _get_tasks
from scanner import runner_report
from scanner.runner_artifacts import (
    clear_task_outputs as _clear_task_outputs,
    ffuf_output_path as _ffuf_output_path,
    write_ffuf_artifact as _write_ffuf_artifact,
    write_httpx_artifact as _write_httpx_artifact,
    write_nmap_artifact as _write_nmap_artifact,
    write_securitytrails_artifact as _write_securitytrails_artifact,
)
from scanner.runner_cursor import (
    canonical_http_probe_input_key as _canonical_http_probe_input_key,
    dir_enum_url_keys_scheduled_or_completed as _dir_enum_url_keys_scheduled_or_completed,
    http_probe_url_keys_scheduled_or_completed as _http_probe_url_keys_scheduled_or_completed,
    incremental_dir_enum_cursor_meta,
    incremental_http_probe_cursor_meta,
    normalize_dirscan_target as _normalize_dirscan_target,
    parse_task_cursor_json as _parse_task_cursor_json,
    pending_incremental_dir_enum_target_keysets as _pending_incremental_dir_enum_target_keysets,
    pending_incremental_http_probe_target_keysets as _pending_incremental_http_probe_target_keysets,
)
from scanner.runner_report import (
    artifact_command_candidates as _artifact_command_candidates,
    artifact_host_key as _artifact_host_key,
    artifact_sort_key as _artifact_sort_key,
    build_host_groups as _build_host_groups,
    build_report_sections as _build_report_sections,
    dict_items as _dict_items,
    diff_section as _diff_section,
    evidence_dict as _evidence_dict,
    finding_diff_key as _finding_diff_key,
    host_key_from_finding as _host_key_from_finding,
    load_artifacts as _load_artifacts,
    load_findings as _load_findings,
    load_report_errors as _load_report_errors,
    normalize_host_key as _normalize_host_key,
    open_port_diff_parts as _open_port_diff_parts,
    report_item_sort_key as _report_item_sort_key,
    status_code as _status_code,
    string_list as _string_list,
)
from scanner.storage import connect, create_run, init_db, insert_task, update_task_state
from scanner.utils.process import open_text_pipe

_log = logging.getLogger(__name__)

fetch_subdomains = _fetch_subdomains
run_httpx_probe = _run_httpx_probe
run_ffuf_scan = _run_ffuf_scan
run_nmap_scan = _run_nmap_scan


def create_scan_run(
    target: str,
    *,
    modules: Sequence[str] | None = None,
    profile: str = "safe",
    workspace: Path | None = None,
    scan_mode: str = "balanced",
    mode_skip_fields: frozenset[str] | None = None,
    bulk_targets: Sequence[str] | None = None,
    any_line_is_domain: bool = False,
) -> dict[str, Any]:
    from scanner.scan_mode import apply_scan_mode_defaults

    run_id = _new_run_id(target)
    config = build_scan_config(
        target,
        run_id,
        profile=profile,
        modules=modules,
        workspace=workspace,
        scan_mode=scan_mode,
        any_line_is_domain=any_line_is_domain,
    )
    config = apply_scan_mode_defaults(config, skip_fields=mode_skip_fields)
    _ensure_run_directories(config.output_root, config.artifacts_dir, config.report_json_path)
    connection = init_db(config.state_db_path)
    try:
        run = _build_run_state(run_id, target, config)
        create_run(connection, run)
        tasks = _enqueue_initial_tasks(connection, run_id, target, config.enabled_phases)
        bulk_list = [str(x).strip() for x in bulk_targets] if bulk_targets is not None else []
        extra_tasks = _enqueue_extra_subdomain_enum_tasks(connection, run_id, bulk_list, config.enabled_phases)
        tasks.extend(extra_tasks)
        return {
            "run_id": run.run_id,
            "target": run.target,
            "target_kind": classify_target(target),
            "status": run.status,
            "profile": config.profile,
            "modules": config.enabled_phases,
            "state_db_path": str(config.state_db_path),
            "task_count": len(tasks),
            "tasks": [_task_summary(task) for task in tasks],
        }
    finally:
        connection.close()


def resume_run(run_id: str, *, workspace: Path | None = None) -> dict[str, Any]:
    connection = _open_run_connection(run_id, workspace=workspace)
    try:
        run = _require_run(connection, run_id)
        tasks = get_incomplete_tasks(connection, run_id)
        return {
            "run_id": run.run_id,
            "target": run.target,
            "status": run.status,
            "modules": run.config.enabled_phases,
            "incomplete_task_count": len(tasks),
            "tasks": [_task_summary(task) for task in tasks],
        }
    finally:
        connection.close()


def extend_scan_run(
    run_id: str,
    *,
    modules: Sequence[str],
    workspace: Path | None = None,
) -> dict[str, Any]:
    connection = _open_run_connection(run_id, workspace=workspace)
    try:
        if not modules:
            raise ValueError("at least one module must be selected")
        run = _require_run(connection, run_id)
        if run.status == "cancelled":
            raise RuntimeError(f"run '{run_id}' is cancelled and cannot be extended")
        if _has_running_tasks(connection, run_id):
            raise RuntimeError(f"run '{run_id}' has a running task; wait for it to finish before adding modules")

        requested_modules = plan_enabled_phases(run.target, modules)
        merged_modules = plan_enabled_phases(
            run.target,
            [*run.config.enabled_phases, *requested_modules],
        )
        new_modules = [module for module in merged_modules if module not in run.config.enabled_phases]
        new_tasks = _enqueue_missing_tasks(connection, run_id, run.target, new_modules)
        if new_modules:
            _update_run_enabled_phases(connection, run, merged_modules, status="pending")
        refreshed_run = _require_run(connection, run_id)
        return {
            "run_id": refreshed_run.run_id,
            "target": refreshed_run.target,
            "status": refreshed_run.status,
            "modules": refreshed_run.config.enabled_phases,
            "added_modules": new_modules,
            "added_task_count": len(new_tasks),
            "tasks": [_task_summary(task) for task in new_tasks],
        }
    finally:
        connection.close()


def cancel_run(run_id: str, *, workspace: Path | None = None) -> dict[str, Any]:
    connection = _open_run_connection(run_id, workspace=workspace)
    try:
        run = _require_run(connection, run_id)
        if run.status in {"completed", "cancelled"}:
            return {
                "run_id": run.run_id,
                "target": run.target,
                "status": run.status,
                "cancelled_task_count": 0,
                "cancelled_task_ids": [],
            }
        cancelled_task_ids = cancel_run_tasks(connection, run_id)
        mark_run_cancelled(connection, run_id)
        cancelled_run = _require_run(connection, run_id)
        return {
            "run_id": cancelled_run.run_id,
            "target": cancelled_run.target,
            "status": cancelled_run.status,
            "cancelled_task_count": len(cancelled_task_ids),
            "cancelled_task_ids": cancelled_task_ids,
        }
    finally:
        connection.close()


def generate_report_summary(run_id: str, *, workspace: Path | None = None) -> dict[str, Any]:
    connection = _open_run_connection(run_id, workspace=workspace)
    try:
        run = _require_run(connection, run_id)
        findings = _load_findings(connection, run_id)
        artifacts = _load_artifacts(connection, run_id)
        sections = runner_report.build_report_sections(findings)
        host_groups = runner_report.build_host_groups(sections, artifacts)
        errors = runner_report.load_report_errors(connection, run_id)
        notes = summarize_execution_notes(_get_tasks(connection, run_id))
        return {
            "run_id": run.run_id,
            "target": run.target,
            "status": run.status,
            "modules": run.config.enabled_phases,
            "run_summary": {
                "started_at": run.started_at.isoformat() if run.started_at else None,
                "completed_at": run.completed_at.isoformat() if run.completed_at else None,
                "observed_finding_count": sum(
                    len(items)
                    for key, items in sections.items()
                    if key != "candidate_cves"
                ),
                "candidate_cve_count": len(sections["candidate_cves"]),
                "artifact_count": len(artifacts),
            },
            "sections": sections,
            "host_groups": host_groups,
            "errors": errors,
            "execution_notes": notes,
            "findings": {
                "total": len(findings),
                "by_module": dict(Counter(item["module"] for item in findings)),
                "items": findings,
            },
            "artifacts": {
                "total": len(artifacts),
                "by_module": dict(Counter(item["module"] for item in artifacts)),
                "items": artifacts,
            },
        }
    finally:
        connection.close()


def generate_run_diff(
    baseline_run_id: str,
    current_run_id: str,
    *,
    workspace: Path | None = None,
) -> dict[str, Any]:
    baseline_summary = generate_report_summary(baseline_run_id, workspace=workspace)
    current_summary = generate_report_summary(current_run_id, workspace=workspace)
    categories = {
        "subdomains": runner_report.diff_section("subdomains", baseline_summary, current_summary),
        "http_probe_results": runner_report.diff_section("http_probe_results", baseline_summary, current_summary),
        "directory_findings": runner_report.diff_section("directory_findings", baseline_summary, current_summary),
        "open_ports": runner_report.diff_section("open_ports", baseline_summary, current_summary),
        "candidate_cves": runner_report.diff_section("candidate_cves", baseline_summary, current_summary),
    }
    return {
        "baseline_run_id": baseline_run_id,
        "current_run_id": current_run_id,
        "baseline_target": baseline_summary["target"],
        "current_target": current_summary["target"],
        "categories": categories,
        "summary": {
            "added_total": sum(item["added_count"] for item in categories.values()),
            "removed_total": sum(item["removed_count"] for item in categories.values()),
            "unchanged_total": sum(item["unchanged_count"] for item in categories.values()),
        },
    }


def execute_subdomain_enum_tasks(run_id: str, *, workspace: Path | None = None) -> dict[str, Any]:
    from scanner.execution.subdomain import execute_subdomain_enum_tasks as _execute_subdomain_enum_tasks

    return _execute_subdomain_enum_tasks(run_id, workspace=workspace)


def execute_http_probe_tasks(run_id: str, *, workspace: Path | None = None) -> dict[str, Any]:
    from scanner.execution.http_probe import execute_http_probe_tasks as _execute_http_probe_tasks

    return _execute_http_probe_tasks(run_id, workspace=workspace)


def execute_dir_enum_tasks(run_id: str, *, workspace: Path | None = None) -> dict[str, Any]:
    from scanner.execution.dirscan import execute_dir_enum_tasks as _execute_dir_enum_tasks

    return _execute_dir_enum_tasks(run_id, workspace=workspace)


def execute_port_scan_tasks(run_id: str, *, workspace: Path | None = None) -> dict[str, Any]:
    from scanner.execution.portscan import execute_port_scan_tasks as _execute_port_scan_tasks

    return _execute_port_scan_tasks(run_id, workspace=workspace)


def execute_domain_discovery_tasks(run_id: str, *, workspace: Path | None = None) -> dict[str, Any]:
    from scanner.execution.domain_discovery import execute_domain_discovery_tasks as _execute_domain_discovery_tasks

    return _execute_domain_discovery_tasks(run_id, workspace=workspace)


def execute_banner_probe_tasks(run_id: str, *, workspace: Path | None = None) -> dict[str, Any]:
    from scanner.execution.banner_probe import execute_banner_probe_tasks as _execute_banner_probe_tasks

    return _execute_banner_probe_tasks(run_id, workspace=workspace)


def execute_cve_match_tasks(run_id: str, *, workspace: Path | None = None) -> dict[str, Any]:
    return _execute_cve_match_tasks(run_id, workspace=workspace)


def execute_ai_triage_tasks(run_id: str, *, workspace: Path | None = None) -> dict[str, Any]:
    from scanner.execution.ai_triage import execute_ai_triage_tasks as _execute_ai_triage_tasks

    return _execute_ai_triage_tasks(run_id, workspace=workspace)


def render_summary_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True)


def _merge_task_cursor_json(
    connection: sqlite3.Connection,
    task_id: str,
    cursor_updates: dict[str, Any],
) -> dict[str, Any]:
    # Atomic read-modify-write: the WHERE guards against overwriting a cancelled state.
    # json_patch (RFC 7396 merge patch) merges at the SQL level in one statement,
    # eliminating the TOCTOU window between Python read and write.
    patch = json.dumps(cursor_updates, sort_keys=True, separators=(",", ":"))
    now = _now().isoformat()
    connection.execute(
        """
        UPDATE tasks
        SET cursor_json = json_patch(COALESCE(cursor_json, '{}'), ?),
            updated_at = ?
        WHERE task_id = ? AND state != 'cancelled'
        """,
        (patch, now, task_id),
    )
    connection.commit()
    current = get_task(connection, task_id)
    return dict(current.cursor_json or {})


def _run_command_with_live_progress(
    command: list[str],
    *,
    stdin_text: str | None = None,
    stdout_handler: Callable[[str], None] | None = None,
    stderr_handler: Callable[[str], None] | None = None,
    snapshot_handler: Callable[[], None] | None = None,
    snapshot_interval_seconds: float = 2.0,
) -> subprocess.CompletedProcess[str]:
    process = open_text_pipe(command, stdin_pipe=stdin_text is not None)

    if stdin_text is not None and process.stdin is not None:
        process.stdin.write(stdin_text)
        process.stdin.close()

    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []

    def _reader(
        stream: Any,
        buffer: list[str],
        handler: Callable[[str], None] | None,
    ) -> None:
        for line in iter(stream.readline, ""):
            buffer.append(line)
            if handler is not None:
                handler(line)
        stream.close()

    threads = [
        threading.Thread(
            target=_reader,
            args=(process.stdout, stdout_chunks, stdout_handler),
            daemon=True,
            name=f"scanner-stream-stdout-{Path(command[0]).name}",
        ),
        threading.Thread(
            target=_reader,
            args=(process.stderr, stderr_chunks, stderr_handler),
            daemon=True,
            name=f"scanner-stream-stderr-{Path(command[0]).name}",
        ),
    ]
    for thread in threads:
        thread.start()

    last_snapshot_at = 0.0
    while process.poll() is None:
        if snapshot_handler is not None and monotonic() - last_snapshot_at >= snapshot_interval_seconds:
            snapshot_handler()
            last_snapshot_at = monotonic()
        sleep(0.1)

    for thread in threads:
        thread.join(timeout=2)
    if snapshot_handler is not None:
        snapshot_handler()

    return subprocess.CompletedProcess(
        command,
        process.returncode,
        stdout="".join(stdout_chunks),
        stderr="".join(stderr_chunks),
    )


def _build_run_state(run_id: str, target: str, config: ScanConfig) -> RunState:
    now = _now()
    current_phase = config.enabled_phases[0] if config.enabled_phases else None
    phase_statuses: dict[PhaseName, TaskStatus] = {
        cast(PhaseName, module): "pending" for module in config.enabled_phases
    }
    return RunState(
        run_id=run_id,
        target=target,
        status="pending",
        current_phase=current_phase,
        phase_statuses=phase_statuses,
        config=config,
        created_at=now,
        updated_at=now,
    )


def _enqueue_initial_tasks(
    connection: sqlite3.Connection,
    run_id: str,
    target: str,
    modules: Sequence[ScanPhase],
) -> list[TaskState]:
    return _enqueue_missing_tasks(connection, run_id, target, modules)


def _enqueue_extra_subdomain_enum_tasks(
    connection: sqlite3.Connection,
    run_id: str,
    bulk_targets: list[str],
    phases: Sequence[ScanPhase],
) -> list[TaskState]:
    if "subdomain_enum" not in phases or len(bulk_targets) <= 1:
        return []
    from scanner.config import subdomain_scope_for_line

    primary_scope = subdomain_scope_for_line(bulk_targets[0])
    tasks: list[TaskState] = []
    seen: set[str] = set()
    if primary_scope:
        seen.add(primary_scope)
    for line in bulk_targets[1:]:
        scope = subdomain_scope_for_line(line)
        if not scope or scope in seen:
            continue
        seen.add(scope)
        if _task_exists(connection, run_id, "subdomain_enum", scope):
            continue
        now = _now()
        task = TaskState(
            task_id=f"task-{uuid4().hex}",
            run_id=run_id,
            module="subdomain_enum",
            tool=resolve_tool("subdomain_enum"),
            scope=scope,
            state="pending",
            created_at=now,
            updated_at=now,
        )
        insert_task(connection, task)
        tasks.append(task)
    return tasks


def _enqueue_missing_tasks(
    connection: sqlite3.Connection,
    run_id: str,
    target: str,
    modules: Sequence[ScanPhase],
) -> list[TaskState]:
    from scanner.config import subdomain_scope_for_line

    now = _now()
    tasks: list[TaskState] = []
    for module in modules:
        scope = target
        if module == "subdomain_enum":
            extracted = subdomain_scope_for_line(target)
            if extracted:
                scope = extracted
        if _task_exists(connection, run_id, module, scope):
            continue
        task = TaskState(
            task_id=f"task-{uuid4().hex}",
            run_id=run_id,
            module=module,
            tool=resolve_tool(module),
            scope=scope,
            state="pending",
            created_at=now,
            updated_at=now,
        )
        insert_task(connection, task)
        tasks.append(task)
    return tasks


def _update_run_enabled_phases(
    connection: sqlite3.Connection,
    run: RunState,
    modules: Sequence[ScanPhase],
    *,
    status: str,
) -> None:
    now = _now()
    updated_config = run.config.model_copy(update={"enabled_phases": list(modules)})
    connection.execute(
        """
        UPDATE runs
        SET status = ?,
            config_json = ?,
            completed_at = NULL,
            updated_at = ?
        WHERE run_id = ?
        """,
        (
            status,
            json.dumps(updated_config.model_dump(mode="json"), sort_keys=True, separators=(",", ":")),
            now.isoformat(),
            run.run_id,
        ),
    )
    connection.commit()


def _task_exists(
    connection: sqlite3.Connection,
    run_id: str,
    module: ScanPhase,
    scope: str,
) -> bool:
    row = connection.execute(
        "SELECT 1 FROM tasks WHERE run_id = ? AND module = ? AND scope = ? LIMIT 1",
        (run_id, module, scope),
    ).fetchone()
    return row is not None


def _has_running_tasks(connection: sqlite3.Connection, run_id: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM tasks WHERE run_id = ? AND state = 'running' LIMIT 1",
        (run_id,),
    ).fetchone()
    return row is not None


def _open_run_connection(run_id: str, *, workspace: Path | None = None) -> sqlite3.Connection:
    db_path = resolve_state_db_path(run_id, workspace=workspace)
    if not db_path.exists():
        raise FileNotFoundError(f"run state database not found for run_id '{run_id}'")
    return connect(db_path)


def _require_run(connection: sqlite3.Connection, run_id: str) -> RunState:
    run = get_run(connection, run_id)
    if run is None:
        raise LookupError(f"run_id '{run_id}' was not found")
    return run



def _task_summary(task: TaskState) -> dict[str, Any]:
    return {
        "task_id": task.task_id,
        "module": task.module,
        "tool": task.tool,
        "scope": task.scope,
        "state": task.state,
        "attempts": task.attempts,
        "last_error": task.last_error,
        "cursor_json": task.cursor_json,
    }


def summarize_bootstrap_evidence(findings: Sequence[Finding]) -> dict[str, Any]:
    domain_candidates: list[dict[str, str]] = []
    seen_candidates: set[tuple[str, str, str]] = set()
    observed_hosts: list[str] = []
    observed_ips: list[str] = []
    for finding in findings:
        evidence = finding.evidence_json
        for field in ("host", "hostname", "cname"):
            value = evidence.get(field)
            if not isinstance(value, str) or not value.strip():
                continue
            candidate = value.strip().rstrip(".")
            if classify_target(candidate) != "domain":
                continue
            entry = (candidate.lower(), field, finding.module)
            if entry in seen_candidates:
                continue
            seen_candidates.add(entry)
            domain_candidates.append(
                {
                    "hostname": candidate,
                    "source_field": field,
                    "source_module": finding.module,
                }
            )
            if candidate not in observed_hosts:
                observed_hosts.append(candidate)
        ip_value = evidence.get("ip")
        if isinstance(ip_value, str) and ip_value and ip_value not in observed_ips:
            observed_ips.append(ip_value)
    return {
        "domain_candidates": domain_candidates,
        "observed_hosts": observed_hosts,
        "observed_ips": observed_ips,
    }


def summarize_execution_notes(tasks: list[TaskState]) -> dict[str, list[dict[str, Any]]]:
    confirmation_required_targets: list[dict[str, Any]] = []
    calibrations: list[dict[str, Any]] = []
    root_domain_accepted_list: list[dict[str, Any]] = []
    root_domain_review_list: list[dict[str, Any]] = []
    root_domain_rejected_list: list[dict[str, Any]] = []

    def _dict_list(value: Any) -> list[dict[str, Any]]:
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        return []

    for task in tasks:
        cursor_json = task.cursor_json or {}
        if not isinstance(cursor_json, dict):
            continue
        for item in _dict_list(cursor_json.get("confirmation_required_targets")):
            confirmation_required_targets.append(
                {
                    "task_id": str(task.task_id),
                    "module": str(task.module),
                    "tool": str(task.tool),
                    "scope": str(task.scope),
                    **item,
                }
            )
        for item in _dict_list(cursor_json.get("calibrations")):
            calibrations.append(
                {
                    "task_id": str(task.task_id),
                    "module": str(task.module),
                    "tool": str(task.tool),
                    "scope": str(task.scope),
                    **item,
                }
            )

        root_domain_review = cursor_json.get("root_domain_review")
        if root_domain_review and isinstance(root_domain_review, dict):
            for item in _dict_list(root_domain_review.get("accepted")):
                root_domain_accepted_list.append(
                    {
                        "task_id": str(task.task_id),
                        "module": str(task.module),
                        "tool": str(task.tool),
                        "scope": str(task.scope),
                        **item,
                    }
                )
            for item in _dict_list(root_domain_review.get("review_required")):
                root_domain_review_list.append(
                    {
                        "task_id": str(task.task_id),
                        "module": str(task.module),
                        "tool": str(task.tool),
                        "scope": str(task.scope),
                        **item,
                    }
                )
            for item in _dict_list(root_domain_review.get("rejected")):
                root_domain_rejected_list.append(
                    {
                        "task_id": str(task.task_id),
                        "module": str(task.module),
                        "tool": str(task.tool),
                        "scope": str(task.scope),
                        **item,
                    }
                )

    return {
        "confirmation_required_targets": confirmation_required_targets,
        "calibrations": calibrations,
        "root_domain_accepted_list": root_domain_accepted_list,
        "root_domain_review_list": root_domain_review_list,
        "root_domain_rejected_list": root_domain_rejected_list,
    }


def classify_root_domain_candidates(evidence_summary: dict[str, Any], target: str) -> dict[str, Any]:
    from scanner.config import _is_private_hostname

    candidates = evidence_summary.get("domain_candidates", [])
    rejected: dict[str, dict[str, Any]] = {}
    # hostname -> list of {source_field, source_module}
    hostname_evidence: dict[str, list[dict[str, Any]]] = {}

    target_clean = target.strip().lower().rstrip(".")

    for candidate in candidates:
        hostname = str(candidate.get("hostname", "")).strip().lower().rstrip(".")
        if not hostname:
            continue

        source_field = str(candidate.get("source_field", ""))
        source_module = str(candidate.get("source_module", ""))

        if hostname == target_clean:
            rejected.setdefault(hostname, {"hostname": hostname, "source_field": source_field,
                                            "source_module": source_module,
                                            "reason": f"Same as scan target {target}"})
            continue
        if hostname.startswith("*."):
            rejected.setdefault(hostname, {"hostname": hostname, "source_field": source_field,
                                            "source_module": source_module,
                                            "reason": "Wildcard root domain"})
            continue
        if _is_private_hostname(hostname):
            rejected.setdefault(hostname, {"hostname": hostname, "source_field": source_field,
                                            "source_module": source_module,
                                            "reason": "Private hostname"})
            continue

        if hostname not in rejected:
            hostname_evidence.setdefault(hostname, []).append(
                {"source_field": source_field, "source_module": source_module}
            )

    accepted: dict[str, dict[str, Any]] = {}
    review_required: dict[str, dict[str, Any]] = {}

    def _is_strong(source_field: str) -> bool:
        lf = source_field.lower()
        return "tls" in lf or "cert" in lf or source_field in ("tls_cn", "subject_cn")

    for hostname, sources in hostname_evidence.items():
        first = sources[0]
        strong = [s for s in sources if _is_strong(s["source_field"])]
        if strong:
            sf = strong[0]["source_field"]
            accepted[hostname] = {
                "hostname": hostname,
                "source_field": sf,
                "source_module": strong[0]["source_module"],
                "reason": f"Strong evidence from TLS ({sf})",
            }
        elif len(sources) >= 2:
            fields = ", ".join(s["source_field"] for s in sources[:3])
            accepted[hostname] = {
                "hostname": hostname,
                "source_field": first["source_field"],
                "source_module": first["source_module"],
                "reason": f"Multiple weak evidence sources ({fields})",
            }
        else:
            review_required[hostname] = {
                "hostname": hostname,
                "source_field": first["source_field"],
                "source_module": first["source_module"],
                "reason": f"Single weak evidence source ({first['source_field']})",
            }

    return {
        "accepted": list(accepted.values()),
        "review_required": list(review_required.values()),
        "rejected": list(rejected.values()),
    }


def enqueue_subdomain_enum_if_needed(
    connection: sqlite3.Connection,
    run_id: str,
    root_domain: str,
    *,
    classify_result: dict[str, Any],
) -> dict[str, Any]:
    run = get_run(connection, run_id)
    if not run:
        return {"enqueued": False, "scope": root_domain, "reason": "Run not found"}
        
    if run.status == "cancelled":
        return {"enqueued": False, "scope": root_domain, "reason": "Run is cancelled"}
        
    if "subdomain_enum" in run.config.enabled_phases:
        return {"enqueued": False, "scope": root_domain, "reason": "Phase already enabled"}

    # Check if duplicate exists
    existing = connection.execute(
        "SELECT task_id FROM tasks WHERE run_id = ? AND module = 'subdomain_enum' AND scope = ?",
        (run_id, root_domain)
    ).fetchone()
    
    if existing:
         return {"enqueued": False, "scope": root_domain, "reason": "Duplicate task exists"}

    from scanner.config import resolve_tool
    now = _now()
    task = TaskState(
        task_id=f"task-{uuid4().hex}",
        run_id=run_id,
        module="subdomain_enum",
        tool=resolve_tool("subdomain_enum"),
        scope=root_domain,
        state="pending",
        created_at=now,
        updated_at=now,
    )
    insert_task(connection, task)
    return {"enqueued": True, "scope": root_domain, "reason": "Auto-enqueued from bootstrap evidence"}






def suppress_primary_scope_tasks_for_cidr_chunk_pipeline(
    connection: sqlite3.Connection,
    run: RunState,
) -> dict[str, bool]:
    """Complete pending scope==target http_probe/dir_enum tasks so chunk-level incrementals do not duplicate full scans."""
    suppressed: dict[str, bool] = {"http_probe": False, "dir_enum": False}
    for module in ("http_probe", "dir_enum"):
        if module not in run.config.enabled_phases:
            continue
        row = connection.execute(
            """
            SELECT task_id FROM tasks
            WHERE run_id = ?
              AND module = ?
              AND scope = ?
              AND state = 'pending'
            LIMIT 1
            """,
            (run.run_id, module, run.target),
        ).fetchone()
        if row is None:
            continue
        mark_task_completed(
            connection,
            row["task_id"],
            cursor_json={
                "cidr_chunk_pipeline_primary_suppressed": True,
                "finding_count": 0,
                "artifact_count": 0,
                "bootstrap_evidence": {},
                "reason": (
                    "Primary task suppressed: CIDR chunk pipeline runs http_probe/dir_enum incrementally "
                    "after each port_scan chunk."
                ),
            },
        )
        connection.commit()
        suppressed[module] = True
    return suppressed


def _enqueue_incremental_http_probe_from_candidate_urls(
    connection: sqlite3.Connection,
    run_id: str,
    candidates: Sequence[str],
    *,
    trigger_task_id: str | None,
    require_initial_http_done: bool,
    triggered_by: str = "port_scan",
) -> dict[str, Any]:
    run = get_run(connection, run_id)
    if run is None:
        return {"enqueued": False, "reason": "run not found"}
    if run.status == "cancelled":
        return {"enqueued": False, "reason": "cancelled"}
    if "http_probe" not in run.config.enabled_phases:
        return {"enqueued": False, "reason": "http_probe disabled"}

    if require_initial_http_done:
        initial_http_done = connection.execute(
            """
            SELECT 1 FROM tasks
            WHERE run_id = ?
              AND module = 'http_probe'
              AND state = 'completed'
            LIMIT 1
            """,
            (run_id,),
        ).fetchone()
        if initial_http_done is None:
            return {"enqueued": False, "reason": "awaiting initial http_probe before incremental"}

    reserved_keys = _http_probe_url_keys_scheduled_or_completed(connection, run_id)
    new_urls: list[str] = []
    for url in candidates:
        if not isinstance(url, str) or not url.strip():
            continue
        key = _canonical_http_probe_input_key(url)
        if key is None or key in reserved_keys:
            continue
        reserved_keys.add(key)
        normalized = _normalize_dirscan_target(url) or url.strip()
        new_urls.append(normalized)

    if not new_urls:
        return {"enqueued": False, "reason": "no new http probe targets", "new_urls": []}

    new_keyset = frozenset(
        _canonical_http_probe_input_key(u) for u in new_urls if _canonical_http_probe_input_key(u)
    )
    for pending_keys in _pending_incremental_http_probe_target_keysets(connection, run_id):
        if pending_keys == new_keyset:
            return {"enqueued": False, "reason": "duplicate pending incremental task", "new_urls": new_urls}

    now = _now()
    scope = f"incremental:http_probe:{uuid4().hex[:12]}"
    revisit_reason = (
        f"http_probe revisited ({triggered_by}) for {len(new_urls)} HTTP(S) endpoint(s)"
    )
    task = TaskState(
        task_id=f"task-{uuid4().hex}",
        run_id=run_id,
        module="http_probe",
        tool=resolve_tool("http_probe"),
        scope=scope,
        state="pending",
        cursor_json={
            "explicit_http_probe_targets": new_urls,
            "incremental": True,
            "triggered_by": triggered_by,
            "trigger_task_id": trigger_task_id,
            "new_scope_count": len(new_urls),
            "revisit_reason": revisit_reason,
        },
        created_at=now,
        updated_at=now,
    )
    insert_task(connection, task)
    return {
        "enqueued": True,
        "task_id": task.task_id,
        "new_urls": new_urls,
        "revisit_reason": revisit_reason,
    }


def maybe_enqueue_incremental_http_probe_tasks(
    connection: sqlite3.Connection,
    run_id: str,
    *,
    trigger_task_id: str | None = None,
) -> dict[str, Any]:
    candidates = _load_http_probe_targets_from_port_scan(connection, run_id)
    return _enqueue_incremental_http_probe_from_candidate_urls(
        connection,
        run_id,
        candidates,
        trigger_task_id=trigger_task_id,
        require_initial_http_done=True,
        triggered_by="port_scan",
    )


def enqueue_chunk_incremental_http_probe_tasks(
    connection: sqlite3.Connection,
    run_id: str,
    *,
    urls: Sequence[str],
    trigger_task_id: str | None = None,
) -> dict[str, Any]:
    """Like maybe_enqueue_incremental_http_probe_tasks but uses explicit URLs and skips the initial http_probe gate."""
    return _enqueue_incremental_http_probe_from_candidate_urls(
        connection,
        run_id,
        urls,
        trigger_task_id=trigger_task_id,
        require_initial_http_done=False,
        triggered_by="port_scan_chunk",
    )


def enqueue_tls_san_http_probe_tasks(
    connection: sqlite3.Connection,
    run_id: str,
    *,
    hostnames: Sequence[str],
    trigger_task_id: str | None = None,
) -> dict[str, Any]:
    """Re-probe hostnames discovered via TLS SAN.

    SAN certs frequently list vhosts that never appear in DNS enumeration; left
    as bare findings they are never actually probed. We expand each hostname to
    https:// (and http:// fallback) candidate URLs and feed them through the
    standard incremental http_probe path, which dedups against already-probed
    hosts and is scope-filtered at execution time.
    """
    candidates: list[str] = []
    for hostname in hostnames:
        host = str(hostname or "").strip().strip(".").casefold()
        if not host or "." not in host or "*" in host:
            continue
        candidates.append(f"https://{host}/")
        candidates.append(f"http://{host}/")
    if not candidates:
        return {"enqueued": False, "reason": "no tls san candidates", "new_urls": []}
    return _enqueue_incremental_http_probe_from_candidate_urls(
        connection,
        run_id,
        candidates,
        trigger_task_id=trigger_task_id,
        require_initial_http_done=False,
        triggered_by="tls_san",
    )


def _alive_dirscan_bases_from_http_probe_task(
    connection: sqlite3.Connection,
    run_id: str,
    http_probe_task_id: str,
) -> list[str]:
    rows = connection.execute(
        """
        SELECT evidence_json, tags_json
        FROM findings
        WHERE run_id = ?
          AND module = 'http_probe'
          AND task_id = ?
        ORDER BY created_at ASC, finding_id ASC
        """,
        (run_id, http_probe_task_id),
    ).fetchall()
    targets: list[str] = []
    seen_targets: set[str] = set()
    for row in rows:
        tags = json.loads(row["tags_json"]) if row["tags_json"] else []
        if "alive" not in tags or "host" not in tags:
            continue
        evidence = json.loads(row["evidence_json"])
        if not isinstance(evidence, dict):
            continue
        status_code = evidence.get("status_code")
        if not isinstance(status_code, int) or status_code not in {200, 301, 302}:
            continue
        scheme = str(evidence.get("scheme") or "").strip().lower()
        if scheme and scheme not in {"http", "https"}:
            continue
        base_url = _normalize_dirscan_target(cast(object, evidence.get("url")))
        if base_url is None or base_url in seen_targets:
            continue
        seen_targets.add(base_url)
        targets.append(base_url)
    return targets


def maybe_enqueue_incremental_dir_enum_tasks(
    connection: sqlite3.Connection,
    run_id: str,
    *,
    http_probe_task_id: str,
) -> dict[str, Any]:
    run = get_run(connection, run_id)
    if run is None:
        return {"enqueued": False, "reason": "run not found"}
    if run.status == "cancelled":
        return {"enqueued": False, "reason": "cancelled"}
    if "dir_enum" not in run.config.enabled_phases:
        return {"enqueued": False, "reason": "dir_enum disabled"}

    pending_primary_dir = connection.execute(
        """
        SELECT 1 FROM tasks
        WHERE run_id = ?
          AND module = 'dir_enum'
          AND state = 'pending'
          AND scope NOT LIKE 'incremental:dir_enum:%'
        LIMIT 1
        """,
        (run_id,),
    ).fetchone()
    if pending_primary_dir is not None:
        return {"enqueued": False, "reason": "pending primary dir_enum will include new http_probe results"}

    alive = _alive_dirscan_bases_from_http_probe_task(connection, run_id, http_probe_task_id)
    reserved_keys = _dir_enum_url_keys_scheduled_or_completed(connection, run_id)
    new_urls: list[str] = []
    for url in alive:
        key = _canonical_http_probe_input_key(url)
        if key is None or key in reserved_keys:
            continue
        reserved_keys.add(key)
        new_urls.append(url)

    if not new_urls:
        return {"enqueued": False, "reason": "no new dir_enum targets", "new_urls": []}

    new_keyset = frozenset(_canonical_http_probe_input_key(u) for u in new_urls if _canonical_http_probe_input_key(u))
    for pending_keys in _pending_incremental_dir_enum_target_keysets(connection, run_id):
        if pending_keys == new_keyset:
            return {"enqueued": False, "reason": "duplicate pending incremental task", "new_urls": new_urls}

    now = _now()
    scope = f"incremental:dir_enum:{uuid4().hex[:12]}"
    revisit_reason = (
        f"dir_enum revisited after http_probe produced {len(new_urls)} new alive base URL(s) not yet scanned"
    )
    task = TaskState(
        task_id=f"task-{uuid4().hex}",
        run_id=run_id,
        module="dir_enum",
        tool=resolve_tool("dir_enum"),
        scope=scope,
        state="pending",
        cursor_json={
            "explicit_dirscan_targets": new_urls,
            "incremental": True,
            "triggered_by": "http_probe",
            "trigger_task_id": http_probe_task_id,
            "new_scope_count": len(new_urls),
            "revisit_reason": revisit_reason,
        },
        created_at=now,
        updated_at=now,
    )
    insert_task(connection, task)
    return {
        "enqueued": True,
        "task_id": task.task_id,
        "new_urls": new_urls,
        "revisit_reason": revisit_reason,
    }


def enqueue_manual_dir_enum_targets(
    connection: sqlite3.Connection,
    run_id: str,
    *,
    base_urls: list[str],
    force: bool = False,
    trigger_label: str = "manual_followup",
    recursive: bool = False,
    max_depth: int | None = None,
) -> dict[str, Any]:
    run = get_run(connection, run_id)
    if run is None:
        return {"enqueued": False, "reason": "run not found", "queued_urls": [], "skipped_urls": [], "skipped_entries": []}
    if run.status == "cancelled":
        skipped = [{"base_url": str(item), "reason": "run_cancelled"} for item in base_urls]
        return {"enqueued": False, "reason": "cancelled", "queued_urls": [], "skipped_urls": list(base_urls), "skipped_entries": skipped}
    if "dir_enum" not in run.config.enabled_phases:
        skipped = [{"base_url": str(item), "reason": "dir_enum_disabled"} for item in base_urls]
        return {
            "enqueued": False,
            "reason": "dir_enum disabled",
            "queued_urls": [],
            "skipped_urls": list(base_urls),
            "skipped_entries": skipped,
        }

    normalized_urls: list[str] = []
    skipped_entries: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in base_urls:
        normalized = _normalize_dirscan_target(cast(object, item))
        if normalized is None:
            skipped_entries.append({"base_url": str(item), "reason": "invalid_target"})
            continue
        key = _canonical_http_probe_input_key(normalized)
        if key is None:
            skipped_entries.append({"base_url": normalized, "reason": "invalid_target"})
            continue
        if key in seen:
            skipped_entries.append({"base_url": normalized, "reason": "duplicate_request"})
            continue
        seen.add(key)
        normalized_urls.append(normalized)
    if not normalized_urls:
        return {
            "enqueued": False,
            "reason": "no valid web targets",
            "queued_urls": [],
            "skipped_urls": [],
            "skipped_entries": skipped_entries,
        }

    queued_urls: list[str] = []
    skipped_urls: list[str] = []
    reserved = _dir_enum_url_keys_scheduled_or_completed(connection, run_id)
    for url in normalized_urls:
        key = _canonical_http_probe_input_key(url)
        if key is None:
            skipped_urls.append(url)
            skipped_entries.append({"base_url": url, "reason": "invalid_target"})
            continue
        if not force and key in reserved:
            skipped_urls.append(url)
            skipped_entries.append({"base_url": url, "reason": "already_scanned"})
            continue
        reserved.add(key)
        queued_urls.append(url)
    if not queued_urls:
        return {
            "enqueued": False,
            "reason": "already queued or completed",
            "queued_urls": [],
            "skipped_urls": skipped_urls,
            "skipped_entries": skipped_entries,
        }

    keyset = frozenset(
        k
        for u in queued_urls
        for k in (_canonical_http_probe_input_key(u),)
        if k
    )
    if not force:
        for pending in _pending_incremental_dir_enum_target_keysets(connection, run_id):
            if pending == keyset:
                return {
                    "enqueued": False,
                    "reason": "duplicate pending incremental task",
                    "queued_urls": [],
                    "skipped_urls": queued_urls + skipped_urls,
                    "skipped_entries": [
                        *skipped_entries,
                        *[
                            {"base_url": url, "reason": "duplicate_pending"}
                            for url in queued_urls
                        ],
                    ],
                }

    now = _now()
    scope = f"manual:dir_enum:{uuid4().hex[:12]}"
    task = TaskState(
        task_id=f"task-{uuid4().hex}",
        run_id=run_id,
        module="dir_enum",
        tool=resolve_tool("dir_enum"),
        scope=scope,
        state="pending",
        cursor_json={
            "explicit_dirscan_targets": sorted(queued_urls),
            "incremental": True,
            "triggered_by": trigger_label,
            "new_scope_count": len(queued_urls),
            "revisit_reason": f"manual dir_enum follow-up ({len(queued_urls)} selected web service target(s))",
            "manual_followup": True,
            "recursive_requested": bool(recursive),
            "max_depth_requested": int(max_depth) if isinstance(max_depth, int) else None,
            "force_rerun": bool(force),
        },
        created_at=now,
        updated_at=now,
    )
    insert_task(connection, task)
    return {
        "enqueued": True,
        "task_id": task.task_id,
        "queued_urls": sorted(queued_urls),
        "skipped_urls": skipped_urls,
        "skipped_entries": skipped_entries,
    }


# --- Recursive dir_enum (optional, default off) ---------------------------------

_DIR_FINDER_EXT_RE = re.compile(
    r"\.(?:html?|mjs|js|map|css|json|xml|png|jpe?g|gif|svg|ico|pdf|zip|7z|tar|gz|bz2|woff2?|ttf|eot|otf|wasm|ts|txt|log|md)(?:$|[?#])",
    re.IGNORECASE,
)


def is_directory_like_path(
    full_url: str,
    status_code: int | None,
    evidence: dict[str, Any] | None = None,
) -> bool:
    if status_code is None:
        return False
    safe = {200, 204, 301, 302, 307, 308, 401, 403}
    if status_code not in safe:
        return False
    try:
        parsed = urlsplit(full_url.strip())
    except ValueError:
        return False
    path = parsed.path or "/"
    if _DIR_FINDER_EXT_RE.search(path):
        return False
    if path.rstrip("/").endswith(".well-known"):
        return True
    if path.endswith("/") or path == "":
        return True
    last = path.rsplit("/", 1)[-1]
    if "." in last and not last.endswith("/"):
        return False
    return True


def child_dirscan_base_url_from_finding(discovered_url: str) -> str | None:
    if not isinstance(discovered_url, str) or not discovered_url.strip():
        return None
    parsed = urlsplit(discovered_url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    path = parsed.path or "/"
    if not path.endswith("/"):
        path = f"{path}/"
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _url_host_key(url: str) -> str | None:
    try:
        h = urlsplit(url).hostname
    except ValueError:
        return None
    return h.casefold() if h else None


def _same_registrable_host(a: str, b: str) -> bool:
    ka = _url_host_key(a)
    kb = _url_host_key(b)
    return bool(ka and kb and ka == kb)


def preserve_dir_enum_lineage_metadata(prior: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "recursion_depth",
        "lineage",
        "parent_base_url",
        "parent_path",
        "parent_target",
        "recursive",
        "triggered_by",
        "trigger_task_id",
        "revisit_reason",
        "new_scope_count",
        "incremental",
        "explicit_dirscan_targets",
    )
    return {k: prior[k] for k in keys if k in prior}


def _count_recursive_dirscan_bases_by_host(
    connection: sqlite3.Connection,
    run_id: str,
) -> dict[str, int]:
    from collections import defaultdict

    counts: dict[str, int] = defaultdict(int)
    for row in connection.execute(
        "SELECT cursor_json, scope FROM tasks WHERE run_id = ? AND module = 'dir_enum'",
        (run_id,),
    ).fetchall():
        cur = _parse_task_cursor_json(row[0])
        if not (cur.get("recursive") is True or str(row[1] or "").startswith("recursive:dir_enum:")):
            continue
        for item in cur.get("explicit_dirscan_targets") or []:
            if not isinstance(item, str):
                continue
            k = _url_host_key(item)
            if k:
                counts[k] += 1
    return dict(counts)


def maybe_enqueue_recursive_dir_enum_tasks(
    connection: sqlite3.Connection,
    run_id: str,
    source_task_id: str,
    *,
    workspace: Path,
) -> dict[str, Any]:
    from scanner.execution.subdomain import load_run_scope_controls, filter_scope_urls

    run = get_run(connection, run_id)
    if run is None:
        return {"enqueued": False, "reason": "run not found"}
    if run.status == "cancelled":
        return {"enqueued": False, "reason": "cancelled"}
    if not run.config.dir_recursive_enabled:
        return {"enqueued": False, "reason": "dir_recursive disabled"}
    if "dir_enum" not in run.config.enabled_phases:
        return {"enqueued": False, "reason": "dir_enum disabled"}

    task = get_task(connection, source_task_id)
    if task.module != "dir_enum":
        return {"enqueued": False, "reason": "not a dir_enum task"}
    prior = task.cursor_json or {}
    current_depth = int(prior.get("recursion_depth") or 0)
    next_depth = current_depth + 1
    max_d = int(run.config.dir_recursive_max_depth)
    if next_depth > max_d:
        return {"enqueued": False, "reason": "max recursion depth", "recursion_depth": current_depth}

    scope_controls = load_run_scope_controls(run_id, workspace=workspace)
    found_rows = connection.execute(
        """
        SELECT evidence_json
        FROM findings
        WHERE run_id = ? AND task_id = ? AND module = 'dir_enum'
        ORDER BY created_at ASC, finding_id ASC
        """,
        (run_id, source_task_id),
    ).fetchall()
    used_map = _count_recursive_dirscan_bases_by_host(connection, run_id)
    new_urls: list[str] = []
    per_host_in_batch: dict[str, int] = {}
    seen: set[str] = set()
    max_paths = int(run.config.dir_recursive_max_paths_per_host)
    for row in found_rows:
        try:
            evidence = json.loads(row["evidence_json"])
        except json.JSONDecodeError:
            _log.warning("skipping finding %s: malformed evidence_json", row["finding_id"])
            continue
        if not isinstance(evidence, dict):
            continue
        url = str(evidence.get("url") or "").strip()
        if not url:
            continue
        st = evidence.get("status_code")
        if isinstance(st, (int, float)):
            status = int(st)
        else:
            status = None
        if not is_directory_like_path(url, status, evidence):
            continue
        rdir = str(evidence.get("redirect_target") or "").strip()
        if rdir and run.config.dir_recursive_same_host_only and not _same_registrable_host(url, rdir):
            continue
        child = child_dirscan_base_url_from_finding(url)
        if not child:
            continue
        host = _url_host_key(child)
        if not host:
            continue
        if int(used_map.get(host, 0)) + int(per_host_in_batch.get(host, 0)) >= max_paths:
            continue
        key = _canonical_http_probe_input_key(child)
        if not key or key in seen:
            continue
        reserved = _dir_enum_url_keys_scheduled_or_completed(connection, run_id)
        if key in reserved:
            continue
        seen.add(key)
        per_host_in_batch[host] = int(per_host_in_batch.get(host, 0)) + 1
        new_urls.append(child)

    if not new_urls:
        return {"enqueued": False, "reason": "no recursive dir targets", "new_urls": []}

    new_urls, skipped_scope = filter_scope_urls(new_urls, scope_controls)
    if not new_urls:
        return {"enqueued": False, "reason": "scope filter removed all candidates", "scope_skipped": skipped_scope}

    new_keyset = frozenset(
        k for u in new_urls for k in (_canonical_http_probe_input_key(u),) if k
    )
    for pending_keys in _pending_incremental_dir_enum_target_keysets(connection, run_id):
        if pending_keys == new_keyset and new_keyset:
            return {
                "enqueued": False,
                "reason": "duplicate pending incremental keyset (recursive)",
                "new_urls": new_urls,
            }
    for pending_keys in _pending_recursive_dir_enum_target_keysets(connection, run_id):
        if pending_keys == new_keyset and new_keyset:
            return {
                "enqueued": False,
                "reason": "duplicate pending recursive keyset",
                "new_urls": new_urls,
            }

    now = _now()
    parent_lineage = list(prior.get("lineage") or [])
    if isinstance(parent_lineage, list):
        chain = [str(x) for x in parent_lineage if isinstance(x, str)]
    else:
        chain = []
    base_label = (prior.get("explicit_dirscan_targets") or [None])
    p0: str | None
    if isinstance(base_label, list) and base_label and isinstance(base_label[0], str):
        p0 = base_label[0]
    else:
        p0 = str(prior.get("parent_target") or "")
    if p0:
        chain = [*chain, p0]

    scope = f"recursive:dir_enum:{uuid4().hex[:12]}"
    revisit = (
        f"dir_enum recursive depth {next_depth} from task {source_task_id} "
        f"({len(new_urls)} path(s) / max_depth={max_d})"
    )
    n_task = TaskState(
        task_id=f"task-{uuid4().hex}",
        run_id=run_id,
        module="dir_enum",
        tool=resolve_tool("dir_enum"),
        scope=scope,
        state="pending",
        cursor_json={
            "explicit_dirscan_targets": sorted(new_urls),
            "incremental": False,
            "recursive": True,
            "recursion_depth": next_depth,
            "lineage": chain[-16:],
            "parent_target": p0,
            "triggered_by": "dir_enum",
            "trigger_task_id": source_task_id,
            "new_scope_count": len(new_urls),
            "revisit_reason": revisit,
        },
        created_at=now,
        updated_at=now,
    )
    insert_task(connection, n_task)
    return {
        "enqueued": True,
        "task_id": n_task.task_id,
        "new_urls": new_urls,
        "revisit_reason": revisit,
        "recursion_depth": next_depth,
    }


def _pending_recursive_dir_enum_target_keysets(connection: sqlite3.Connection, run_id: str) -> list[frozenset[str]]:
    keysets: list[frozenset[str]] = []
    for row in connection.execute(
        """
        SELECT cursor_json
        FROM tasks
        WHERE run_id = ?
          AND module = 'dir_enum'
          AND state = 'pending'
        """,
        (run_id,),
    ).fetchall():
        cursor = _parse_task_cursor_json(row[0])
        if not cursor.get("recursive"):
            continue
        explicit = cursor.get("explicit_dirscan_targets")
        if not isinstance(explicit, list) or not explicit:
            continue
        keys = frozenset(
            k
            for item in explicit
            if isinstance(item, str)
            for k in (_canonical_http_probe_input_key(item),)
            if k
        )
        if keys:
            keysets.append(keys)
    return keysets


def _scope_workspace_from_run(connection: sqlite3.Connection, run_id: str) -> Path | None:
    run = get_run(connection, run_id)
    if run is None:
        return None
    return Path(run.config.output_root).parent.parent


def _is_explicit_scope_seed(value: str) -> bool:
    text = value.strip().lower()
    return "://" in text or ("/" in text and _is_ipv4_cidr_target(text))


def _http_probe_seeds_from_scope_include(
    connection: sqlite3.Connection,
    run_id: str,
    *,
    include_plain: bool,
) -> list[str]:
    from scanner.execution.subdomain import load_run_scope_controls

    controls = load_run_scope_controls(run_id, workspace=_scope_workspace_from_run(connection, run_id))
    if not controls.include:
        return []
    seeds: list[str] = []
    seen: set[str] = set()
    for item in controls.include:
        if not include_plain and not _is_explicit_scope_seed(item):
            continue
        n = _normalize_http_probe_seed_target(item)
        if n and n not in seen:
            seen.add(n)
            seeds.append(n)
    return seeds


def _port_scan_targets_from_scope_include(
    connection: sqlite3.Connection,
    run_id: str,
    *,
    include_plain: bool,
) -> list[str]:
    from scanner.execution.subdomain import load_run_scope_controls

    controls = load_run_scope_controls(run_id, workspace=_scope_workspace_from_run(connection, run_id))
    if not controls.include:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in controls.include:
        if not include_plain and not _is_explicit_scope_seed(item):
            continue
        n = _normalize_port_scan_target(item)
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return out


def _load_http_probe_targets(connection: sqlite3.Connection, run_id: str, task: TaskState) -> list[str]:
    cursor = task.cursor_json or {}
    explicit = cursor.get("explicit_http_probe_targets")
    if isinstance(explicit, list) and explicit:
        normalized: list[str] = []
        seen_keys: set[str] = set()
        for item in explicit:
            if not isinstance(item, str) or not item.strip():
                continue
            key = _canonical_http_probe_input_key(item)
            if key is None or key in seen_keys:
                continue
            seen_keys.add(key)
            base = _normalize_dirscan_target(item) or item.strip()
            normalized.append(base)
        return sorted(normalized)

    rows = connection.execute(
        """
        SELECT DISTINCT target
        FROM findings
        WHERE run_id = ?
          AND module = 'subdomain_enum'
        ORDER BY target ASC
        """,
        (run_id,),
    ).fetchall()
    merged: list[str] = []
    seen: set[str] = set()
    for row in rows:
        t = str(row["target"])
        if t and t not in seen:
            seen.add(t)
            merged.append(t)
    has_discovered_targets = bool(rows)
    for seed in _http_probe_seeds_from_scope_include(
        connection,
        run_id,
        include_plain=not has_discovered_targets,
    ):
        if seed not in seen:
            seen.add(seed)
            merged.append(seed)
    if merged:
        return sorted(merged)
    targets = _load_http_probe_targets_from_port_scan(connection, run_id)
    if targets:
        return targets
    run = get_run(connection, run_id)
    if run is None:
        return []
    fallback_target = _normalize_http_probe_seed_target(run.target)
    return [fallback_target] if fallback_target is not None else []


def _load_http_probe_targets_from_port_scan(connection: sqlite3.Connection, run_id: str) -> list[str]:
    rows = connection.execute(
        """
        SELECT evidence_json
        FROM findings
        WHERE run_id = ?
          AND module = 'port_scan'
        ORDER BY created_at ASC, finding_id ASC
        """,
        (run_id,),
    ).fetchall()
    targets: list[str] = []
    seen_targets: set[str] = set()
    for row in rows:
        try:
            evidence = json.loads(row["evidence_json"])
        except json.JSONDecodeError:
            _log.warning("skipping port_scan finding: malformed evidence_json")
            continue
        base_url = _candidate_http_probe_target_from_port_scan_evidence(evidence)
        if base_url is None or base_url in seen_targets:
            continue
        seen_targets.add(base_url)
        targets.append(base_url)
    return targets


def _load_dirscan_targets(connection: sqlite3.Connection, run_id: str, task: TaskState) -> list[str]:
    cursor = task.cursor_json or {}
    explicit = cursor.get("explicit_dirscan_targets")
    if isinstance(explicit, list) and explicit:
        targets: list[str] = []
        seen_targets: set[str] = set()
        for item in explicit:
            if not isinstance(item, str) or not item.strip():
                continue
            base_url = _normalize_dirscan_target(item)
            if base_url is None or base_url in seen_targets:
                continue
            seen_targets.add(base_url)
            targets.append(base_url)
        return sorted(targets)

    rows = connection.execute(
        """
        SELECT evidence_json, tags_json
        FROM findings
        WHERE run_id = ?
          AND module = 'http_probe'
        ORDER BY created_at ASC, finding_id ASC
        """,
        (run_id,),
    ).fetchall()
    glob_targets: list[str] = []
    glob_seen: set[str] = set()
    for row in rows:
        tags = json.loads(row["tags_json"]) if row["tags_json"] else []
        if "alive" not in tags or "host" not in tags:
            continue
        evidence = json.loads(row["evidence_json"])
        if not isinstance(evidence, dict):
            continue
        base_url = _normalize_dirscan_target(cast(object, evidence.get("url")))
        if base_url is None or base_url in glob_seen:
            continue
        glob_seen.add(base_url)
        glob_targets.append(base_url)
    return glob_targets


def _load_port_scan_targets(connection: sqlite3.Connection, run_id: str) -> list[str]:
    rows = connection.execute(
        """
        SELECT module, target, evidence_json, tags_json
        FROM findings
        WHERE run_id = ?
          AND module IN ('http_probe', 'subdomain_enum')
        ORDER BY CASE module WHEN 'http_probe' THEN 0 ELSE 1 END, created_at ASC, finding_id ASC
        """,
        (run_id,),
    ).fetchall()
    targets: list[str] = []
    seen_targets: set[str] = set()
    for row in rows:
        target = _candidate_port_scan_target(
            module=str(row["module"]),
            target=str(row["target"]),
            evidence_json=row["evidence_json"],
            tags_json=row["tags_json"],
        )
        if target is None or target in seen_targets:
            continue
        seen_targets.add(target)
        targets.append(target)
    scope_targets = _port_scan_targets_from_scope_include(
        connection,
        run_id,
        include_plain=not bool(targets),
    )
    for scope_target in scope_targets:
        if scope_target in seen_targets:
            continue
        seen_targets.add(scope_target)
        targets.append(scope_target)
    if targets:
        return targets
    run = get_run(connection, run_id)
    if run is None:
        return []
    fallback_target = _normalize_port_scan_target(run.target)
    return [fallback_target] if fallback_target is not None else []
    


def _load_cve_match_source_findings(connection: sqlite3.Connection, run_id: str) -> list[Finding]:
    rows = connection.execute(
        """
        SELECT finding_id, run_id, task_id, module, target, status, summary, evidence_json, tags_json, created_at
        FROM findings
        WHERE run_id = ?
          AND module IN ('subdomain_enum', 'http_probe', 'dir_enum', 'port_scan')
        ORDER BY created_at ASC, finding_id ASC
        """,
        (run_id,),
    ).fetchall()
    return [
        Finding(
            finding_id=row["finding_id"],
            run_id=row["run_id"],
            task_id=row["task_id"],
            module=row["module"],
            target=row["target"],
            status=row["status"],
            summary=row["summary"],
            evidence_json=json.loads(row["evidence_json"]),
            tags=json.loads(row["tags_json"]) if row["tags_json"] else [],
            created_at=datetime.fromisoformat(row["created_at"]),
        )
        for row in rows
    ]


def _candidate_port_scan_target(
    *,
    module: str,
    target: str,
    evidence_json: str,
    tags_json: str | None,
) -> str | None:
    if module == "subdomain_enum":
        return _normalize_port_scan_target(target)

    tags = json.loads(tags_json) if tags_json else []
    if "host" not in tags:
        return None
    evidence = json.loads(evidence_json)
    if isinstance(evidence, dict):
        for key in ("host", "url"):
            normalized = _normalize_port_scan_target(cast(object, evidence.get(key)))
            if normalized is not None:
                return normalized
    return _normalize_port_scan_target(target)



def _normalize_http_probe_seed_target(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.strip()
    parsed = urlsplit(normalized)
    if parsed.scheme and parsed.netloc:
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
    return normalized


def _candidate_http_probe_target_from_port_scan_evidence(evidence: object) -> str | None:
    if not isinstance(evidence, dict):
        return None
    if str(evidence.get("state") or "").lower() != "open":
        return None
    host = _normalize_port_scan_target(evidence.get("host") or evidence.get("ip"))
    if host is None:
        return None
    port = evidence.get("port")
    if not isinstance(port, int):
        return None
    scheme = _infer_http_scheme_from_port_scan_evidence(
        port=port,
        service=evidence.get("service"),
    )
    if scheme is None:
        return None
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return f"{scheme}://{host}/"
    return f"{scheme}://{host}:{port}/"


def _infer_http_scheme_from_port_scan_evidence(*, port: int, service: object) -> str | None:
    normalized_service = str(service or "").strip().lower()
    if "https" in normalized_service:
        return "https"
    if "http" in normalized_service:
        return "http"
    if port in {443, 8443, 9443}:
        return "https"
    if port in {80, 81, 3000, 4000, 5000, 7001, 8000, 8080, 8081, 8888, 9000}:
        return "http"
    return None


def _normalize_port_scan_target(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.strip().lower().rstrip(".")
    parsed = urlsplit(normalized)
    if parsed.scheme and parsed.hostname:
        return parsed.hostname.lower().rstrip(".")
    if _is_ipv4_cidr_target(normalized):
        return normalized
    if "/" in normalized:
        return None
    return normalized


def _is_ipv4_cidr_target(value: str) -> bool:
    try:
        parsed = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return isinstance(parsed, ipaddress.IPv4Network)


def should_split_port_scan_cidr(
    run_config: ScanConfig,
    targets: list[str],
) -> bool:
    if not bool(run_config.cidr_split_enabled) or len(targets) != 1:
        return False
    t = targets[0]
    if not _is_ipv4_cidr_target(t):
        return False
    try:
        net = ipaddress.ip_network(t, strict=False)
    except ValueError:
        return False
    if not isinstance(net, ipaddress.IPv4Network):
        return False
    if net.prefixlen >= 28:
        return False
    return bool(net.num_addresses > run_config.cidr_split_max_hosts_per_chunk)


def split_ipv4_cidr_for_port_scan(
    cidr: str,
    max_hosts_per_chunk: int,
) -> list[str]:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return [cidr]
    if not isinstance(net, ipaddress.IPv4Network):
        return [cidr]
    if int(net.num_addresses) <= int(max(1, max_hosts_per_chunk)):
        return [str(net)]
    new_prefix = int(net.prefixlen)
    while new_prefix < 32 and (1 << (32 - new_prefix)) > max_hosts_per_chunk:
        new_prefix += 1
    if new_prefix > 32:
        new_prefix = 32
    return [str(sub) for sub in net.subnets(new_prefix=new_prefix)]


CIDR_EMA_ALPHA = 0.35


def _floatish(value: object) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    return None


def update_cidr_ema_chunk_duration(prior_sec: object, duration_sec: float) -> float:
    p = _floatish(prior_sec)
    d = max(0.0, float(duration_sec))
    if p is None or p <= 0.0:
        return d
    return CIDR_EMA_ALPHA * d + (1.0 - CIDR_EMA_ALPHA) * p


def calculate_next_chunk_size(
    avg_duration_sec: float,
    target_interval_minutes: int,
    current_size: int,
) -> int:
    if avg_duration_sec <= 0.0:
        return int(current_size)
    target_sec = float(target_interval_minutes) * 60.0
    ratio = target_sec / float(avg_duration_sec)
    ratio = max(0.5, min(2.0, ratio))
    new_size = int(int(current_size) * ratio)
    return max(8, min(new_size, 256))


def cidr_count_addresses_ipv4(network_cidr: str) -> int:
    try:
        net = ipaddress.ip_network(network_cidr, strict=False)
    except ValueError:
        return 0
    if not isinstance(net, ipaddress.IPv4Network):
        return 0
    return int(net.num_addresses)


def cidr_offset_range_target(
    network_cidr: str, start_index: int, size: int
) -> tuple[str, int, str | None, bool]:
    try:
        net = ipaddress.ip_network(network_cidr, strict=False)
    except ValueError:
        return network_cidr, start_index, None, True
    if not isinstance(net, ipaddress.IPv4Network):
        return network_cidr, start_index, None, True
    total = int(net.num_addresses)
    if start_index < 0:
        start_index = 0
    if start_index >= total or size <= 0:
        return "", start_index, None, True
    take = min(int(size), total - int(start_index))
    base = int(net.network_address)
    a_int = base + int(start_index)
    # Keep nmap input stable by emitting CIDR blocks only.
    # Pick the largest aligned power-of-two block not exceeding `take`.
    block = 1
    while (block * 2) <= take and (a_int % (block * 2) == 0):
        block *= 2
    prefix = 32 - (block.bit_length() - 1)
    target = f"{ipaddress.IPv4Address(a_int)}/{prefix}"
    next_index = int(start_index) + block
    b_int = a_int + block - 1
    b_s = str(ipaddress.IPv4Address(b_int))
    last_ip = b_s
    return target, next_index, last_ip, next_index >= total


def cidr_estimated_remaining_minutes(remaining: int, chunk_size: int, avg_sec: float) -> float | None:
    if remaining <= 0 or chunk_size <= 0 or avg_sec <= 0.0:
        return None
    chunks_left = (int(remaining) + int(chunk_size) - 1) // int(chunk_size)
    return (float(chunks_left) * float(avg_sec)) / 60.0


def _cidr_int_field(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value == int(value):
        return int(value)
    return None


def cursor_suggests_cidr_resume_incomplete(
    run_config: ScanConfig,
    cursor: dict[str, Any],
) -> bool:
    if not run_config.cidr_resume_enabled:
        return False
    if not cursor.get("cidr_resume_in_progress"):
        return False
    o = _cidr_int_field(cursor.get("cidr_next_offset"))
    t = _cidr_int_field(cursor.get("cidr_total_addresses"))
    if o is None or t is None or t <= 0:
        return False
    return o < t


def try_revive_resumable_cidr_port_scan(
    connection: sqlite3.Connection, run_id: str
) -> bool:
    run = get_run(connection, run_id)
    if run is None or str(run.status) != "cancelled" or not run.config.cidr_resume_enabled:
        return False
    row = connection.execute(
        """
        SELECT state, last_error, cursor_json, task_id
        FROM tasks
        WHERE run_id = ?
          AND module = 'port_scan'
          AND tool = 'nmap'
        LIMIT 1
        """,
        (run_id,),
    ).fetchone()
    if row is None:
        return False
    cursor = _parse_task_cursor_json(row["cursor_json"])
    st = str(row["state"] or "")
    le = str(row["last_error"] or "").lower()
    task_id = str(row["task_id"] or "")
    can_resume = cursor_suggests_cidr_resume_incomplete(
        run.config, cursor
    ) or (st == "failed" and "resumable" in le and bool(cursor.get("cidr_root")))
    if not can_resume:
        return False
    now = _now()
    should_reset_task = (
        task_id
        and (
            st == "cancelled"
            or (st == "failed" and "resumable" in le and bool(cursor.get("cidr_root")))
        )
    )
    if should_reset_task:
        pl = {**cursor, "cidr_restarted_at": now.isoformat()}
        update_task_state(
            connection,
            task_id,
            "pending",
            cursor_json=pl,
            last_error=None,
            completed_at=None,
        )
    n = connection.execute(
        """
        UPDATE runs
        SET status = 'pending',
            completed_at = NULL,
            updated_at = ?
        WHERE run_id = ?
          AND status = 'cancelled'
        """,
        (now.isoformat(), run_id),
    ).rowcount
    connection.commit()
    return n > 0


def _artifact_token(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()[:12]


def _ensure_run_directories(output_root: Path, artifacts_dir: Path, report_json_path: Path) -> None:
    output_root.mkdir(parents=True, exist_ok=True)
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    report_json_path.parent.mkdir(parents=True, exist_ok=True)


def _new_run_id(target: str) -> str:
    # Include microseconds so back-to-back run creation in the same second
    # does not collide on runs/<run_id>/state.db paths.
    timestamp = _now().strftime("%Y%m%d%H%M%S%f")
    return f"{_run_id_target_slug(target)}-{timestamp}"


def _run_id_target_slug(target: str) -> str:
    normalized = target.strip().lower()
    parsed = urlsplit(normalized)
    if parsed.hostname:
        normalized = parsed.hostname.lower().rstrip(".")
    normalized = normalized.rstrip(".")
    slug = re.sub(r"[^a-z0-9.-]+", "-", normalized).strip("-.")
    return slug or "target"


def _now() -> datetime:
    return datetime.now(UTC)
