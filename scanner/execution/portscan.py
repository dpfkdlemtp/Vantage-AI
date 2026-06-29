from __future__ import annotations

import json
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Any, cast

from scanner.adapters import nmap_runner as nmap_adapter

_CIDR_MAX_EVENTS = 100
from scanner import runner as runner_core
from scanner.execution.portscan_helpers import (
    NMAP_PERCENT_RE,
    NMAP_REMAINING_RE,
    estimated_remaining_min_from_stats_line as _estimated_remaining_min_from_stats_line,
    http_probe_urls_from_port_findings as _http_probe_urls_from_port_findings,
    load_port_scan_findings_for_task as _load_port_scan_findings_for_task,
    nmap_scan_warning_event as _nmap_scan_warning_event,
    record_nmap_scan_warnings as _record_nmap_scan_warnings,
    run_cancelled as _run_cancelled,
)
from scanner.execution.portscan_nmap import (
    run_masscan_nmap_two_pass as _run_masscan_nmap_two_pass,
    run_nmap_scan_with_progress as _run_nmap_scan_with_progress,
)


def _run_port_scan(
    targets: list[str],
    *,
    run: Any,
    progress_callback: Any | None = None,
) -> nmap_adapter.NmapRunResult:
    if getattr(run.config, "masscan_enabled", False) or getattr(run.config, "naabu_enabled", False):
        return _run_masscan_nmap_two_pass(targets, run=run, progress_callback=progress_callback)
    return _run_nmap_scan_with_progress(targets, run=run, progress_callback=progress_callback)
from scanner.execution.subdomain import (
    RunScopeControls,
    build_scope_cursor_json,
    filter_scope_hosts,
    filter_scope_urls,
    load_run_scope_controls,
    normalize_port_scan_execution_targets,
)
from scanner.models import Finding
from scanner.normalizers.portscan import normalize_nmap_results
from scanner.state import (
    get_task,
    get_incomplete_tasks,
    get_run,
    mark_run_finished,
    mark_run_running,
    mark_task_cancelled,
    mark_task_completed,
    mark_task_failed,
    mark_task_running,
)
from scanner.storage import insert_artifact, insert_finding





def _execute_cidr_chunk_downstream(
    connection: Any,
    run: Any,
    run_id: str,
    task: Any,
    workspace: Path | None,
    scope_controls: RunScopeControls,
    *,
    chunk_ordinal: int,
    chunk_total_estimate: int,
    chunk_findings: list[Finding],
    checkpoint_events: list[dict[str, Any]],
) -> None:
    """Run http_probe → dir_enum for one port_scan chunk (non-blocking on full port_scan)."""
    want = (
        "http_probe" in run.config.enabled_phases
        or "dir_enum" in run.config.enabled_phases
    )
    if not want:
        return
    if _run_cancelled(connection, run_id):
        return

    raw_urls = _http_probe_urls_from_port_findings(
        chunk_findings, probe_all_open_ports=run.config.http_probe_all_open_ports
    )
    allowed_urls, _skipped_urls = filter_scope_urls(raw_urls, scope_controls)

    from scanner.runner import (
        enqueue_chunk_incremental_http_probe_tasks,
        execute_dir_enum_tasks,
        execute_http_probe_tasks,
    )

    http_task_id: str | None = None
    if "http_probe" in run.config.enabled_phases and allowed_urls:
        runner_core._merge_task_cursor_json(
            connection,
            task.task_id,
            {
                "cidr_downstream_stage": "http_probe",
                "cidr_downstream_chunk": chunk_ordinal,
                "cidr_downstream_chunk_total": chunk_total_estimate,
            },
        )
        checkpoint_events.append(
            {
                "ts": datetime.now(UTC).isoformat(),
                "message": f"[http_probe] Starting downstream probe for chunk {chunk_ordinal}/{chunk_total_estimate}",
                "level": "info",
                "module": "http_probe",
                "data": {"chunk": chunk_ordinal, "total": chunk_total_estimate},
            }
        )
        enq_http = enqueue_chunk_incremental_http_probe_tasks(
            connection,
            run_id,
            urls=allowed_urls,
            trigger_task_id=task.task_id,
        )
        if enq_http.get("enqueued") and enq_http.get("task_id"):
            http_task_id = str(enq_http["task_id"])
            execute_http_probe_tasks(run_id, workspace=workspace)
            checkpoint_events.append(
                {
                    "ts": datetime.now(UTC).isoformat(),
                    "message": f"[http_probe] Downstream probe finished for chunk {chunk_ordinal}/{chunk_total_estimate}",
                    "level": "info",
                    "module": "http_probe",
                }
            )
        elif enq_http.get("reason"):
            checkpoint_events.append(
                {
                    "ts": datetime.now(UTC).isoformat(),
                    "message": f"[http_probe] Skipped incremental enqueue ({enq_http.get('reason')})",
                    "level": "warning",
                    "module": "http_probe",
                }
            )

    if _run_cancelled(connection, run_id):
        runner_core._merge_task_cursor_json(
            connection,
            task.task_id,
            {"cidr_downstream_stage": "cancelled"},
        )
        return

    if "dir_enum" in run.config.enabled_phases and http_task_id:
        runner_core._merge_task_cursor_json(
            connection,
            task.task_id,
            {"cidr_downstream_stage": "dir_enum"},
        )
        checkpoint_events.append(
            {
                "ts": datetime.now(UTC).isoformat(),
                "message": f"[dir_enum] Starting downstream directory scan for chunk {chunk_ordinal}/{chunk_total_estimate}",
                "level": "info",
                "module": "dir_enum",
            }
        )
        enq_dir = runner_core.maybe_enqueue_incremental_dir_enum_tasks(
            connection,
            run_id,
            http_probe_task_id=http_task_id,
        )
        if enq_dir.get("enqueued"):
            execute_dir_enum_tasks(run_id, workspace=workspace)
            checkpoint_events.append(
                {
                    "ts": datetime.now(UTC).isoformat(),
                    "message": f"[dir_enum] Downstream directory scan finished for chunk {chunk_ordinal}/{chunk_total_estimate}",
                    "level": "info",
                    "module": "dir_enum",
                }
            )

    if _run_cancelled(connection, run_id):
        runner_core._merge_task_cursor_json(
            connection,
            task.task_id,
            {"cidr_downstream_stage": "cancelled"},
        )
        return

    runner_core._merge_task_cursor_json(
        connection,
        task.task_id,
        {
            "cidr_downstream_stage": "chunk_done",
            "cidr_downstream_chunk": chunk_ordinal,
        },
    )
    checkpoint_events.append(
        {
            "ts": datetime.now(UTC).isoformat(),
            "message": f"[checkpoint] Partial downstream pipeline persisted for chunk {chunk_ordinal}/{chunk_total_estimate}",
            "level": "info",
            "module": "port_scan",
        }
    )




def _port_scan_cidr_adaptive_loop(
    connection: Any,
    run: Any,
    run_id: str,
    task: Any,
    port_scan_targets: list[str],
    prior0: dict[str, Any],
    skip_clear: bool,
    scope_cursor_json: dict[str, Any],
    skipped_targets: list[str],
    latest_tool_progress: dict[str, Any],
    workspace: Path | None = None,
    scope_controls: RunScopeControls | None = None,
) -> tuple[list[str], int, int, list[dict[str, Any]], bool, dict[str, Any] | None]:
    cidr_root = str(port_scan_targets[0])
    init_size = int(run.config.cidr_split_max_hosts_per_chunk)
    tot_addr = runner_core.cidr_count_addresses_ipv4(cidr_root)
    if not tot_addr:
        return [], 0, 0, [], False, None

    if skip_clear or runner_core.cursor_suggests_cidr_resume_incomplete(run.config, prior0):
        next_off = int(prior0.get("cidr_next_offset", 0) or 0)
        ch_sz = int(prior0.get("cidr_current_chunk_size", init_size) or init_size)
        raw_c = prior0.get("cidr_completed_chunks") or []
        completed = [int(x) for x in raw_c if isinstance(x, (int, float)) and int(x) == x]
        avg_sec = float(prior0.get("cidr_avg_chunk_duration_sec") or 0.0)
        c_events: list[dict[str, Any]] = list(prior0.get("cidr_checkpoint_events") or [])
        cidr_total_guess = int(
            prior0.get("cidr_chunks_total", max(1, (tot_addr + init_size - 1) // init_size)) or 1
        )
        if skip_clear:
            c_events = [
                *c_events,
                {
                    "ts": datetime.now(UTC).isoformat(),
                    "message": (
                        f"[CIDR] Resuming from offset {next_off} "
                        f"({len(completed)} chunk(s) already completed)"
                    ),
                    "level": "info",
                    "module": "port_scan",
                },
            ]
    else:
        next_off = 0
        ch_sz = init_size
        completed = []
        avg_sec = 0.0
        c_events = []
        cidr_total_guess = max(1, (tot_addr + init_size - 1) // init_size)
    art_paths: list[str] = []
    t_ports = 0
    t_hosts = 0
    task_aborted = False
    c_merge = {
        "stage": "nmap_scan",
        "cidr_resume_in_progress": True,
        "cidr_resume_eligible": True,
        "cidr_root": cidr_root,
        "cidr_total_addresses": tot_addr,
        "cidr_chunks_total": cidr_total_guess,
    }
    sc: RunScopeControls = scope_controls or load_run_scope_controls(run_id, workspace=workspace)
    want_chunk_pipeline = (
        "http_probe" in run.config.enabled_phases
        or "dir_enum" in run.config.enabled_phases
    )
    if want_chunk_pipeline and not prior0.get("cidr_chunk_pipeline_primaries_done"):
        runner_core.suppress_primary_scope_tasks_for_cidr_chunk_pipeline(connection, run)
        prior0["cidr_chunk_pipeline_primaries_done"] = True
        runner_core._merge_task_cursor_json(
            connection, task.task_id, {"cidr_chunk_pipeline_primaries_done": True}
        )
    while next_off < tot_addr:
        r = get_run(connection, run_id)
        if r is not None and str(r.status) == "cancelled":
            rem = max(0, tot_addr - next_off)
            eta = (
                runner_core.cidr_estimated_remaining_minutes(rem, ch_sz, avg_sec) if avg_sec > 0 else None
            )
            pl = {
                **c_merge,
                **scope_cursor_json,
                "scan_quality": "incomplete",
                "cidr_next_offset": next_off,
                "cidr_current_chunk_size": ch_sz,
                "cidr_completed_chunks": completed,
                "cidr_avg_chunk_duration_sec": max(0.0, float(avg_sec)),
                "cidr_checkpoint_events": c_events,
                "cidr_last_checkpoint_at": datetime.now(UTC).isoformat(),
                "scope_skipped_targets": skipped_targets,
            }
            if eta is not None:
                pl["cidr_estimated_remaining_min"] = float(eta)
            mark_task_failed(
                connection,
                task.task_id,
                "CIDR port scan stopped (resumable)",
                cursor_json=pl,
            )
            task_aborted = True
            return art_paths, t_ports, t_hosts, c_events, task_aborted, None
        t_str, next_idx, last_ip, _done_net = runner_core.cidr_offset_range_target(
            cidr_root, next_off, ch_sz
        )
        if not t_str or next_idx <= next_off:
            break
        ord_idx = len(completed)
        cur1 = ord_idx + 1
        ts0 = datetime.now(UTC).isoformat()
        rem2 = max(0, tot_addr - next_idx)
        eta0 = (
            runner_core.cidr_estimated_remaining_minutes(rem2, ch_sz, avg_sec) if avg_sec > 0 else None
        )
        c_events.append(
            {
                "ts": ts0,
                "message": f"Starting port_scan chunk {cur1} (~{cidr_total_guess} est.) {t_str}",
                "level": "info",
                "module": "port_scan",
                "data": {"chunk": cur1, "label": t_str, "est_total_chunks": cidr_total_guess},
            }
        )
        cur_payload = {
            **c_merge,
            **scope_cursor_json,
            "cidr_chunk_index": cur1,
            "cidr_chunk_total": cidr_total_guess,
            "cidr_chunk_label": t_str,
            "cidr_next_offset": next_off,
            "cidr_current_chunk_size": ch_sz,
            "cidr_completed_chunks": list(completed),
            "last_checkpoint_at": ts0,
            "cidr_checkpoint_events": list(c_events),
        }
        if avg_sec > 0:
            cur_payload["cidr_avg_chunk_min"] = round(avg_sec / 60.0, 2)
        if eta0 is not None:
            cur_payload["cidr_estimated_remaining_min"] = round(eta0, 2)
        if last_ip:
            cur_payload["cidr_last_processed_ip"] = last_ip
        runner_core._merge_task_cursor_json(connection, task.task_id, cur_payload)

        r_live = get_run(connection, run_id)
        if r_live is not None:
            run = r_live

        def _sync_nmap_progress(progress: dict[str, Any]) -> None:
            upd = dict(progress.get("tool_progress") or {})
            latest_tool_progress.clear()
            latest_tool_progress.update(upd)
            runner_core._merge_task_cursor_json(
                connection,
                task.task_id,
                {"stage": "nmap_scan", **scope_cursor_json, **progress},
            )

        t0m = time.monotonic()
        result = _run_port_scan(
            [t_str], run=run, progress_callback=_sync_nmap_progress
        )
        dur = max(0.0, time.monotonic() - t0m)
        _record_nmap_scan_warnings(connection, task.task_id, result)
        if not completed and not skip_clear:
            avg_sec = float(dur)
        else:
            avg_sec = float(runner_core.update_cidr_ema_chunk_duration(avg_sec, dur))
        aidx = cur1
        ctot = cidr_total_guess
        artifact = runner_core._write_nmap_artifact(
            run, task, result, chunk_index=aidx, chunk_total=ctot, chunk_label=t_str
        )
        insert_artifact(connection, artifact)
        chunk_findings = normalize_nmap_results(
            result, run_id=run.run_id, task_id=task.task_id
        )
        for finding in chunk_findings:
            insert_finding(connection, finding)
        art_paths.append(str(artifact.path))
        t_ports += sum(len(h.ports) for h in result.hosts)
        t_hosts += len(result.hosts)
        c_events.append(
            {
                "ts": datetime.now(UTC).isoformat(),
                "message": f"[CIDR] Chunk {cur1}/{cidr_total_guess} completed ({int(dur)}s)",
                "level": "info",
                "module": "port_scan",
            }
        )
        if want_chunk_pipeline:
            port_scan_ev = (
                "[port_scan] Chunk "
                + f"{cur1}/{cidr_total_guess}"
                + " persisted; starting incremental downstream phases"
            )
            c_events.append(
                {
                    "ts": datetime.now(UTC).isoformat(),
                    "message": port_scan_ev,
                    "level": "info",
                    "module": "port_scan",
                }
            )
            _execute_cidr_chunk_downstream(
                connection,
                run,
                run_id,
                task,
                workspace,
                sc,
                chunk_ordinal=cur1,
                chunk_total_estimate=int(cidr_total_guess),
                chunk_findings=chunk_findings,
                checkpoint_events=c_events,
            )
            r_ds = get_run(connection, run_id)
            if r_ds is not None and str(r_ds.status) == "cancelled":
                rem = max(0, tot_addr - next_off)
                eta = (
                    runner_core.cidr_estimated_remaining_minutes(rem, ch_sz, avg_sec)
                    if avg_sec > 0
                    else None
                )
                pl_ds = {
                    **c_merge,
                    **scope_cursor_json,
                    "scan_quality": "incomplete",
                    "cidr_next_offset": next_off,
                    "cidr_current_chunk_size": ch_sz,
                    "cidr_completed_chunks": completed,
                    "cidr_avg_chunk_duration_sec": max(0.0, float(avg_sec)),
                    "cidr_checkpoint_events": c_events,
                    "cidr_last_checkpoint_at": datetime.now(UTC).isoformat(),
                    "scope_skipped_targets": skipped_targets,
                }
                if eta is not None:
                    pl_ds["cidr_estimated_remaining_min"] = float(eta)
                mark_task_failed(
                    connection,
                    task.task_id,
                    "CIDR port scan stopped (resumable)",
                    cursor_json=pl_ds,
                )
                task_aborted = True
                return art_paths, t_ports, t_hosts, c_events, task_aborted, None
        completed.append(ord_idx)
        next_off = next_idx
        if run.config.cidr_split_adaptive_enabled and next_off < tot_addr:
            old_sz = ch_sz
            ch_sz = runner_core.calculate_next_chunk_size(
                avg_sec,
                int(run.config.cidr_split_target_interval_minutes),
                ch_sz,
            )
            if ch_sz != old_sz:
                c_events.append(
                    {
                        "ts": datetime.now(UTC).isoformat(),
                        "message": f"[CIDR] Adjust next chunk size -> {ch_sz} hosts (avg {int(avg_sec)}s/chunk)",
                        "level": "info",
                        "module": "port_scan",
                    }
                )
        if len(c_events) > _CIDR_MAX_EVENTS:
            c_events = c_events[-_CIDR_MAX_EVENTS:]
        rem3 = max(0, tot_addr - next_off)
        cidr_total_guess = max(
            cidr_total_guess,
            len(completed) + (rem3 + ch_sz - 1) // max(1, ch_sz),
        )
        ts1 = datetime.now(UTC).isoformat()
        pl2: dict[str, Any] = {
            **c_merge,
            "cidr_next_offset": next_off,
            "cidr_current_chunk_size": ch_sz,
            "cidr_completed_chunks": list(completed),
            "cidr_avg_chunk_duration_sec": max(0.0, float(avg_sec)),
            "cidr_chunks_total": cidr_total_guess,
            "last_checkpoint_at": ts1,
            "cidr_checkpoint_events": list(c_events),
        }
        if last_ip:
            pl2["cidr_last_processed_ip"] = last_ip
        e_rem = (
            runner_core.cidr_estimated_remaining_minutes(rem3, ch_sz, avg_sec) if avg_sec > 0 else None
        )
        if e_rem is not None:
            pl2["cidr_estimated_remaining_min"] = round(e_rem, 2)
        if avg_sec > 0:
            pl2["cidr_avg_chunk_min"] = round(avg_sec / 60.0, 2)
        runner_core._merge_task_cursor_json(
            connection, task.task_id, {**pl2, **scope_cursor_json}
        )
    if next_off < tot_addr and not task_aborted:
        pl_inc = {
            **c_merge,
            **scope_cursor_json,
            "cidr_next_offset": next_off,
            "cidr_current_chunk_size": ch_sz,
            "cidr_completed_chunks": list(completed),
            "cidr_avg_chunk_duration_sec": max(0.0, float(avg_sec)),
            "cidr_checkpoint_events": c_events,
            "cidr_last_checkpoint_at": datetime.now(UTC).isoformat(),
            "scope_skipped_targets": skipped_targets,
        }
        mark_task_failed(
            connection,
            task.task_id,
            "CIDR port scan incomplete (resumable)",
            cursor_json={**pl_inc, "scan_quality": "incomplete"},
        )
        return art_paths, t_ports, t_hosts, c_events, True, None
    done_meta: dict[str, Any] = {
        "cidr_root": cidr_root,
        "cidr_total_addresses": tot_addr,
        "cidr_chunks_total": cidr_total_guess,
    }
    return art_paths, t_ports, t_hosts, c_events, False, done_meta


def execute_port_scan_tasks(run_id: str, *, workspace: Path | None = None) -> dict[str, Any]:
    connection = runner_core._open_run_connection(run_id, workspace=workspace)
    try:
        run = runner_core._require_run(connection, run_id)
        scope_controls = load_run_scope_controls(run_id, workspace=workspace)
        tasks = [
            task
            for task in get_incomplete_tasks(connection, run_id)
            if task.module == "port_scan" and task.tool == "nmap"
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
                task_started_monotonic = time.monotonic()
                prior0: dict[str, Any] = dict(task.cursor_json or {})
                raw_port_scan_targets = runner_core._load_port_scan_targets(connection, run_id)
                filtered_targets, skipped_targets = filter_scope_hosts(raw_port_scan_targets, scope_controls)
                port_scan_targets = normalize_port_scan_execution_targets(filtered_targets)
                scope_cursor_json = build_scope_cursor_json(
                    scope_controls,
                    input_count=len(raw_port_scan_targets),
                    allowed_count=len(port_scan_targets),
                    skipped_targets=skipped_targets,
                )
                cidr0 = str(port_scan_targets[0]) if len(port_scan_targets) == 1 else ""
                cidr_tcount = (
                    runner_core.cidr_count_addresses_ipv4(cidr0) if cidr0 else 0
                )
                use_adaptive_cidr = bool(
                    len(port_scan_targets) == 1
                    and cidr_tcount > 0
                    and (
                        runner_core.should_split_port_scan_cidr(
                            run.config, port_scan_targets
                        )
                        or (
                            run.config.cidr_resume_enabled
                            and runner_core.cursor_suggests_cidr_resume_incomplete(
                                run.config, prior0
                            )
                        )
                    )
                )
                skip_clear = bool(
                    use_adaptive_cidr
                    and run.config.cidr_resume_enabled
                    and runner_core.cursor_suggests_cidr_resume_incomplete(
                        run.config, prior0
                    )
                    and (
                        not prior0.get("cidr_root")
                        or str(prior0.get("cidr_root")) == cidr0
                    )
                )
                if not skip_clear:
                    runner_core._clear_task_outputs(connection, task)
                mark_task_running(
                    connection,
                    task.task_id,
                    cursor_json={"stage": "nmap_scan", **scope_cursor_json},
                )
                if not port_scan_targets:
                    mark_task_completed(
                        connection,
                        task.task_id,
                        cursor_json={
                            "scan_quality": "partial",
                            "scan_quality_reason": "no_targets_after_scope_filter",
                            "host_count": 0,
                            "port_count": 0,
                            "artifact_count": 0,
                            "finding_count": 0,
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
                            "input_count": 0,
                            "finding_count": 0,
                            "artifact_path": None,
                            "scope_skipped_count": len(skipped_targets),
                            "scope_skipped_targets": skipped_targets,
                        }
                    )
                    continue

                latest_tool_progress: dict[str, Any] = {}
                cidr_done_meta: dict[str, Any] | None = None

                def _sync_nmap_progress(progress: dict[str, Any]) -> None:
                    nonlocal latest_tool_progress
                    latest_tool_progress = dict(progress.get("tool_progress") or {})
                    runner_core._merge_task_cursor_json(
                        connection,
                        task.task_id,
                        {
                            "stage": "nmap_scan",
                            **scope_cursor_json,
                            **progress,
                        },
                    )

                if use_adaptive_cidr:
                    ap, tpc, thc, ch_ev, task_aborted, cidr_done_meta = (
                        _port_scan_cidr_adaptive_loop(
                            connection,
                            run,
                            run_id,
                            task,
                            port_scan_targets,
                            prior0,
                            skip_clear,
                            scope_cursor_json,
                            skipped_targets,
                            latest_tool_progress,
                            workspace,
                            scope_controls,
                        )
                    )
                    artifact_path_list: list[str] = ap
                    total_port_count = tpc
                    total_host_count = thc
                    chunk_events = ch_ev
                    if task_aborted:
                        failed_task_count += 1
                        task_summaries.append(
                            {
                                "task_id": task.task_id,
                                "module": task.module,
                                "tool": task.tool,
                                "scope": task.scope,
                                "state": "failed",
                                "input_count": len(port_scan_targets),
                                "finding_count": 0,
                                "artifact_path": None,
                                "scope_skipped_count": len(skipped_targets),
                                "scope_skipped_targets": skipped_targets,
                                "last_error": "CIDR port scan (resumable stop)",
                            }
                        )
                        continue
                    findings = _load_port_scan_findings_for_task(
                        connection, run_id, task.task_id
                    )
                else:
                    if runner_core.should_split_port_scan_cidr(
                        run.config, port_scan_targets
                    ):
                        cidr_chunks = runner_core.split_ipv4_cidr_for_port_scan(
                            port_scan_targets[0],
                            int(run.config.cidr_split_max_hosts_per_chunk),
                        )
                        scan_jobs = [[c] for c in cidr_chunks]
                    else:
                        scan_jobs = [list(port_scan_targets)]

                    multichunk = len(scan_jobs) > 1
                    chunk_events = []
                    accumulated: list[Finding] = []
                    artifact_path_list = []
                    total_port_count = 0
                    total_host_count = 0
                    task_aborted = False
                    want_chunk_pipe = (
                        "http_probe" in run.config.enabled_phases
                        or "dir_enum" in run.config.enabled_phases
                    )
                    if (
                        multichunk
                        and want_chunk_pipe
                        and not prior0.get("cidr_chunk_pipeline_primaries_done")
                    ):
                        runner_core.suppress_primary_scope_tasks_for_cidr_chunk_pipeline(connection, run)
                        runner_core._merge_task_cursor_json(
                            connection,
                            task.task_id,
                            {"cidr_chunk_pipeline_primaries_done": True},
                        )

                    for idx, chunk_targets in enumerate(scan_jobs):
                        chunk_label = (
                            chunk_targets[0]
                            if len(chunk_targets) == 1
                            else f"{len(chunk_targets)} targets"
                        )
                        rstate = get_run(connection, run_id)
                        if rstate is not None and rstate.status == "cancelled":
                            mark_task_cancelled(
                                connection,
                                task.task_id,
                                cursor_json={
                                    "stage": "nmap_scan",
                                    "scope_skipped_targets": skipped_targets,
                                    "cidr_checkpoint_events": chunk_events,
                                    **scope_cursor_json,
                                },
                            )
                            task_aborted = True
                            task_summaries.append(
                                {
                                    "task_id": task.task_id,
                                    "module": task.module,
                                    "tool": task.tool,
                                    "scope": task.scope,
                                    "state": "cancelled",
                                    "input_count": len(port_scan_targets),
                                    "scope_skipped_count": len(skipped_targets),
                                    "scope_skipped_targets": skipped_targets,
                                }
                            )
                            break

                        ts0 = datetime.now(UTC).isoformat()
                        chunk_events.append(
                            {
                                "ts": ts0,
                                "message": f"Starting port_scan chunk {idx + 1}/{len(scan_jobs)} ({chunk_label})",
                                "level": "info",
                                "module": "port_scan",
                                "data": {
                                    "chunk": idx + 1,
                                    "total": len(scan_jobs),
                                    "label": chunk_label,
                                },
                            }
                        )
                        runner_core._merge_task_cursor_json(
                            connection,
                            task.task_id,
                            {
                                "stage": "nmap_scan",
                                "cidr_chunk_index": idx + 1,
                                "cidr_chunk_total": len(scan_jobs),
                                "cidr_chunk_label": str(chunk_label),
                                "last_checkpoint_at": ts0,
                                "cidr_checkpoint_events": list(chunk_events),
                                **scope_cursor_json,
                            },
                        )

                        r_chunk = get_run(connection, run_id)
                        if r_chunk is not None:
                            run = r_chunk

                        result = _run_port_scan(
                            chunk_targets,
                            run=run,
                            progress_callback=_sync_nmap_progress,
                        )
                        _record_nmap_scan_warnings(connection, task.task_id, result)
                        cidx: int | None = idx + 1 if multichunk else None
                        ctot: int | None = len(scan_jobs) if multichunk else None
                        clab: str | None = str(chunk_label) if multichunk else None
                        artifact = runner_core._write_nmap_artifact(
                            run,
                            task,
                            result,
                            chunk_index=cidx,
                            chunk_total=ctot,
                            chunk_label=clab,
                        )
                        insert_artifact(connection, artifact)
                        chunk_findings = normalize_nmap_results(
                            result,
                            run_id=run.run_id,
                            task_id=task.task_id,
                        )
                        for finding in chunk_findings:
                            insert_finding(connection, finding)
                        accumulated.extend(chunk_findings)
                        artifact_path_list.append(str(artifact.path))
                        total_port_count += sum(len(h.ports) for h in result.hosts)
                        total_host_count += len(result.hosts)

                        ts1 = datetime.now(UTC).isoformat()
                        chunk_events.append(
                            {
                                "ts": ts1,
                                "message": (
                                    f"Completed port_scan chunk {idx + 1}/{len(scan_jobs)} — "
                                    f"{len(chunk_findings)} finding(s) persisted; artifact saved"
                                ),
                                "level": "info",
                                "module": "port_scan",
                                "data": {
                                    "finding_count": len(chunk_findings),
                                    "path": str(artifact.path),
                                },
                            }
                        )
                        if "http_probe" in run.config.enabled_phases and not (
                            multichunk and want_chunk_pipe
                        ):
                            raw_urls = _http_probe_urls_from_port_findings(
                                chunk_findings,
                                probe_all_open_ports=run.config.http_probe_all_open_ports,
                            )
                            allowed_urls, _skipped_urls = filter_scope_urls(
                                raw_urls, scope_controls
                            )
                            if allowed_urls:
                                from scanner.runner import (
                                    enqueue_chunk_incremental_http_probe_tasks,
                                    execute_http_probe_tasks,
                                )

                                enq_http = enqueue_chunk_incremental_http_probe_tasks(
                                    connection,
                                    run_id,
                                    urls=allowed_urls,
                                    trigger_task_id=task.task_id,
                                )
                                if enq_http.get("enqueued"):
                                    execute_http_probe_tasks(run_id, workspace=workspace)
                                    chunk_events.append(
                                        {
                                            "ts": datetime.now(UTC).isoformat(),
                                            "message": (
                                                f"[http_probe] Incremental probe finished for chunk "
                                                f"{idx + 1}/{len(scan_jobs)}"
                                            ),
                                            "level": "info",
                                            "module": "http_probe",
                                        }
                                    )
                                elif enq_http.get("reason"):
                                    chunk_events.append(
                                        {
                                            "ts": datetime.now(UTC).isoformat(),
                                            "message": (
                                                f"[http_probe] Skipped incremental enqueue "
                                                f"({enq_http.get('reason')})"
                                            ),
                                            "level": "warning",
                                            "module": "http_probe",
                                        }
                                    )
                        if multichunk and want_chunk_pipe:
                            _execute_cidr_chunk_downstream(
                                connection,
                                run,
                                run_id,
                                task,
                                workspace,
                                scope_controls,
                                chunk_ordinal=idx + 1,
                                chunk_total_estimate=len(scan_jobs),
                                chunk_findings=chunk_findings,
                                checkpoint_events=chunk_events,
                            )
                            xc = get_run(connection, run_id)
                            if xc is not None and xc.status == "cancelled":
                                mark_task_cancelled(
                                    connection,
                                    task.task_id,
                                    cursor_json={
                                        "stage": "nmap_scan",
                                        "scope_skipped_targets": skipped_targets,
                                        "cidr_checkpoint_events": chunk_events,
                                        **scope_cursor_json,
                                    },
                                )
                                task_aborted = True
                                task_summaries.append(
                                    {
                                        "task_id": task.task_id,
                                        "module": task.module,
                                        "tool": task.tool,
                                        "scope": task.scope,
                                        "state": "cancelled",
                                        "input_count": len(port_scan_targets),
                                        "scope_skipped_count": len(skipped_targets),
                                        "scope_skipped_targets": skipped_targets,
                                    }
                                )
                                break
                        runner_core._merge_task_cursor_json(
                            connection,
                            task.task_id,
                            {
                                "last_checkpoint_at": ts1,
                                "cidr_checkpoint_events": list(chunk_events),
                                **scope_cursor_json,
                            },
                        )

                    if task_aborted:
                        continue

                    findings = accumulated

                bootstrap_evidence = runner_core.summarize_bootstrap_evidence(findings)
                root_domain_review = None
                from scanner.config import classify_target

                if classify_target(run.target) != "domain":
                    root_domain_review = runner_core.classify_root_domain_candidates(
                        bootstrap_evidence, run.target
                    )
                    for accepted in root_domain_review["accepted"]:
                        enqueue_result = runner_core.enqueue_subdomain_enum_if_needed(
                            connection,
                            run.run_id,
                            accepted["hostname"],
                            classify_result=root_domain_review,
                        )
                        accepted["enqueued"] = enqueue_result["enqueued"]
                first_path = artifact_path_list[0] if artifact_path_list else None
                duration_sec = max(0.0, time.monotonic() - task_started_monotonic)
                possible_filtered = len(findings) == 0 or int(total_port_count) == 0
                suspicious_result = duration_sec < 2.0
                quality = "partial" if (possible_filtered or suspicious_result) else "full"
                quality_reasons: list[str] = []
                if possible_filtered:
                    quality_reasons.extend(
                        [
                            "No open ports found",
                            "Possible reasons: Firewall filtering, ICMP blocked, or rate limiting",
                        ]
                    )
                if suspicious_result:
                    quality_reasons.append("Execution ended very quickly (<2s); result may be incomplete")
                _chunk_total = (
                    int(cidr_done_meta.get("cidr_chunks_total") or 0)
                    if use_adaptive_cidr and cidr_done_meta
                    else (len(scan_jobs) if not use_adaptive_cidr else 0)
                )
                _complete_cursor: dict[str, Any] = {
                    "artifact_path": first_path,
                    "artifact_paths": artifact_path_list,
                    "host_count": total_host_count,
                    "port_count": total_port_count,
                    "finding_count": len(findings),
                    "artifact_count": len(artifact_path_list),
                    "scan_duration_sec": round(duration_sec, 2),
                    "possible_filtered": bool(possible_filtered),
                    "suspicious_result": bool(suspicious_result),
                    "scan_quality": quality,
                    "scan_quality_reasons": quality_reasons,
                    "tool_progress": latest_tool_progress,
                    "bootstrap_evidence": bootstrap_evidence,
                    "root_domain_review": root_domain_review,
                    "cidr_chunk_total": _chunk_total,
                    "cidr_checkpoint_events": list(chunk_events),
                    "last_checkpoint_at": (
                        str(chunk_events[-1]["ts"]) if chunk_events else None
                    ),
                    **scope_cursor_json,
                }
                if use_adaptive_cidr and cidr_done_meta:
                    _complete_cursor["cidr_resume_in_progress"] = False
                    _complete_cursor["cidr_next_offset"] = cidr_done_meta.get(
                        "cidr_total_addresses", 0
                    )
                    _complete_cursor["cidr_total_addresses"] = cidr_done_meta.get(
                        "cidr_total_addresses", 0
                    )
                    _complete_cursor["cidr_chunks_total"] = cidr_done_meta.get(
                        "cidr_chunks_total", _chunk_total
                    )
                mark_task_completed(
                    connection,
                    task.task_id,
                    cursor_json=_complete_cursor,
                )
                completed_task_count += 1
                finding_count += len(findings)
                artifact_count += len(artifact_path_list)
                incremental_http = runner_core.maybe_enqueue_incremental_http_probe_tasks(
                    connection,
                    run.run_id,
                    trigger_task_id=task.task_id,
                )
                task_summaries.append(
                    {
                        "task_id": task.task_id,
                        "module": task.module,
                        "tool": task.tool,
                        "scope": task.scope,
                        "state": "completed",
                        "input_count": len(port_scan_targets),
                        "finding_count": len(findings),
                        "artifact_path": first_path,
                        "artifact_paths": artifact_path_list,
                        "scope_skipped_count": len(skipped_targets),
                        "scope_skipped_targets": skipped_targets,
                        "incremental_http_probe": incremental_http,
                        "scan_quality": quality,
                        "possible_filtered": bool(possible_filtered),
                        "suspicious_result": bool(suspicious_result),
                    }
                )
            except Exception as exc:
                mark_task_failed(
                    connection,
                    task.task_id,
                    str(exc),
                    cursor_json={"stage": "nmap_failed", "scan_quality": "incomplete"},
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


