from __future__ import annotations

import json
import sqlite3
import re
from collections import Counter, deque
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Lock
from typing import Any, cast
from urllib.parse import urlsplit

from scanner.adapters import ffuf_runner as ffuf_adapter
from scanner import runner as runner_core
from scanner.adapters.ffuf_runner import FfufResultEntry
from scanner.config import DEFAULT_FFUF_WORDLIST
from scanner.config import build_web_headers, choose_dirscan_strategy, summarize_web_headers
from scanner.execution.dirscan_helpers import (
    CALIBRATION_SAMPLE_COUNT,
    DOMINANT_LENGTH_RATIO,
    DirscanCalibrationDecision,
    DirscanConfirmationRequired,
    WINDOWS_HTTPX_INDICATORS,
    WINDOWS_PORTSCAN_INDICATORS,
    build_canary_paths as _build_canary_paths,
    casefold_wordlist_entries as _casefold_wordlist_entries,
    contains_indicator as _contains_indicator,
    derive_calibration_decision as _derive_calibration_decision,
    dirscan_note_key as _dirscan_note_key,
    dominant_length as _dominant_length,
    ensure_case_insensitive_wordlist as _ensure_case_insensitive_wordlist,
    estimate_ffuf_total_count as _estimate_ffuf_total_count,
    first_existing_wordlist as _first_existing_wordlist,
    get_dirscan_auth_detection as _get_dirscan_auth_detection,
    get_portscan_service_text as _get_portscan_service_text,
    get_target_technologies as _get_target_technologies,
    is_likely_windows_target as _is_likely_windows_target,
    is_user_defined_wordlist as _is_user_defined_wordlist,
    login_gate_fingerprint as _login_gate_fingerprint,
    matches_http_probe_host as _matches_http_probe_host,
    matches_port_scan_host as _matches_port_scan_host,
    resolve_dirscan_wordlist as _resolve_dirscan_wordlist,
)
from scanner.execution.subdomain import build_scope_cursor_json, filter_scope_urls, load_run_scope_controls
from scanner.normalizers.dirscan import normalize_ffuf_results
from scanner.state import (
    get_incomplete_tasks,
    get_task,
    mark_run_finished,
    mark_run_running,
    mark_task_completed,
    mark_task_failed,
    mark_task_running,
)
from scanner.storage import insert_artifact, insert_finding
from scanner.wordlist_recommendations import getRecommendedWordlists

LOGIN_GATE_DOMINANT_RATIO = 0.6
LOGIN_GATE_MIN_MATCH_COUNT = 3
FFUF_RATIO_RE = re.compile(r"(?P<processed>\d+)\s*/\s*(?P<total>\d+)")
DEFAULT_FFUF_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
)




@dataclass(frozen=True)
class DirscanWorkerOutcome:
    base_url: str
    artifact_path: str | None
    calibration_details: dict[str, Any] | None
    confirmation_required: dict[str, Any] | None
    finding_count: int
    artifact_count: int
    scanned: bool


def execute_dir_enum_tasks(run_id: str, *, workspace: Path | None = None) -> dict[str, Any]:
    workspace = workspace or Path.cwd()
    connection = runner_core._open_run_connection(run_id, workspace=workspace)
    try:
        run = runner_core._require_run(connection, run_id)
        scope_controls = load_run_scope_controls(run_id, workspace=workspace)
        tasks = [
            task
            for task in get_incomplete_tasks(connection, run_id)
            if task.module == "dir_enum" and task.tool == "ffuf"
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
                # Reload the latest run config at task boundary so pending updates
                # can affect upcoming dir_enum tasks without restarting execution.
                run = runner_core._require_run(connection, run_id)
                runner_core._clear_task_outputs(connection, task)
                raw_dirscan_targets = runner_core._load_dirscan_targets(connection, run_id, task)
                dirscan_targets, skipped_targets = filter_scope_urls(raw_dirscan_targets, scope_controls)
                scope_cursor_json = build_scope_cursor_json(
                    scope_controls,
                    input_count=len(raw_dirscan_targets),
                    allowed_count=len(dirscan_targets),
                    skipped_targets=skipped_targets,
                )
                prior_cursor = dict(get_task(connection, task.task_id).cursor_json or {})
                mark_task_running(
                    connection,
                    task.task_id,
                    cursor_json={**prior_cursor, "stage": "ffuf_scan", **scope_cursor_json},
                )
                if not dirscan_targets:
                    empty_meta = runner_core.incremental_dir_enum_cursor_meta(prior_cursor)
                    mark_task_completed(
                        connection,
                        task.task_id,
                        cursor_json={
                            "scan_count": 0,
                            "artifact_count": 0,
                            "finding_count": 0,
                            "confirmation_required_count": 0,
                            "confirmation_required_targets": [],
                            "calibrations": [],
                            "input_dirscan_urls": [],
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
                            "input_count": 0,
                            "finding_count": 0,
                            "artifact_paths": [],
                            "scope_skipped_count": len(skipped_targets),
                            "scope_skipped_targets": skipped_targets,
                        }
                    )
                    continue

                wordlist_path = run.config.ffuf_wordlist_path
                if wordlist_path is None:
                    raise ValueError("ffuf_wordlist_path must be configured before dir_enum tasks can run")

                from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

                from scanner.config import DIR_ENUM_MAX_WORKERS as _DIR_POOL_CAP

                task_artifact_paths: list[str] = []
                task_calibrations: list[dict[str, Any]] = []
                confirmation_required_targets: list[dict[str, Any]] = []
                task_finding_count = 0
                task_scan_count = 0
                
                queued_targets = list(dirscan_targets)
                running_targets: set[str] = set()
                completed_targets_list: list[str] = []
                tool_progress_targets: dict[str, dict[str, Any]] = {}
                progress_lock = Lock()

                def _update_progress(conn: sqlite3.Connection):
                    with progress_lock:
                        ordered_tool_progress = [
                            tool_progress_targets[base_url]
                            for base_url in sorted(tool_progress_targets)
                        ]
                        runner_core._merge_task_cursor_json(
                            conn,
                            task.task_id,
                            {
                                "stage": "ffuf_scan",
                                "total_targets": len(dirscan_targets),
                                "queued_targets": len(queued_targets),
                                "running_targets": len(running_targets),
                                "completed_targets": len(completed_targets_list),
                                "finding_count": task_finding_count,
                                "artifact_count": len(task_artifact_paths),
                                "tool_progress": ordered_tool_progress,
                                "tool_progress_target_count": len(ordered_tool_progress),
                                **scope_cursor_json,
                            },
                        )

                pcursor = prior_cursor
                rec_depth = int(pcursor.get("recursion_depth") or 0)
                ffuf_meta_extras: dict[str, Any] = {}
                if rec_depth or pcursor.get("recursive"):
                    st = "primary"
                    if pcursor.get("recursive"):
                        st = "recursive"
                    elif pcursor.get("incremental"):
                        st = "incremental"
                    ffuf_meta_extras = {
                        "recursion_depth": rec_depth,
                        "parent_base_url": pcursor.get("parent_target")
                        or pcursor.get("parent_base_url")
                        or None,
                        "parent_path": pcursor.get("parent_path") or None,
                        "seed_type": st,
                    }

                def _worker(base_url: str) -> DirscanWorkerOutcome:
                    t_conn = runner_core._open_run_connection(run_id, workspace=workspace)
                    try:
                        run = runner_core._require_run(t_conn, run_id)
                        wordlist_path = run.config.ffuf_wordlist_path
                        if wordlist_path is None:
                            raise ValueError("ffuf_wordlist_path must be configured before dir_enum tasks can run")
                        with progress_lock:
                            if base_url in queued_targets:
                                queued_targets.remove(base_url)
                            running_targets.add(base_url)
                        
                        _update_progress(t_conn)
                        
                        effective_wordlist_path, wordlist_details = _resolve_dirscan_wordlist(
                            t_conn,
                            run_id,
                            run,
                            base_url,
                            wordlist_path,
                            technologies=_get_target_technologies(t_conn, run_id, base_url),
                            auto_recommendation_enabled=bool(getattr(run.config, "auto_recommendation_enabled", True)),
                        )
                        try:
                            calibration = _plan_dirscan_filters(run, task, base_url)
                        except DirscanConfirmationRequired as exc:
                            exc.cursor_json.update(wordlist_details)
                            return DirscanWorkerOutcome(
                                base_url=base_url,
                                artifact_path=None,
                                calibration_details=exc.cursor_json,
                                confirmation_required=exc.cursor_json,
                                finding_count=0,
                                artifact_count=0,
                                scanned=False,
                            )

                        technologies = _get_target_technologies(t_conn, run_id, base_url)
                        auth_detection = _get_dirscan_auth_detection(t_conn, run_id, base_url)
                        dirscan_strategy = choose_dirscan_strategy(
                            headers=run.config.extra_headers,
                            auth_detection=auth_detection,
                        )
                        _split = urlsplit(base_url)
                        _origin = f"{_split.scheme}://{_split.netloc}/" if _split.scheme and _split.netloc else ""
                        request_headers = build_web_headers(
                            run.config.extra_headers,
                            referer=_origin,
                        )
                        from scanner.config import derive_extensions_from_tech
                        from scanner.extension_recommendations import (
                            getRecommendedExtensions,
                            merge_auto_extensions,
                            normalize_ffuf_extensions,
                        )

                        user_extensions = normalize_ffuf_extensions(
                            [str(x) for x in (run.config.ffuf_extensions or ())]
                        )
                        auto_recommendation_enabled = bool(getattr(run.config, "auto_recommendation_enabled", True))
                        h = urlsplit(base_url).hostname or ""
                        service_text = _get_portscan_service_text(t_conn, run_id, h)
                        tech_blob = " ".join(technologies)
                        derived_for_meta = derive_extensions_from_tech(technologies)
                        recommended_for_meta = getRecommendedExtensions(
                            service_text,
                            f"{tech_blob} {' '.join(technologies)}",
                        )
                        if user_extensions:
                            effective_extensions = user_extensions
                        elif not auto_recommendation_enabled:
                            effective_extensions = []
                        else:
                            effective_extensions = merge_auto_extensions(
                                derived_for_meta,
                                recommended_for_meta,
                            )
                        
                        calibration_details = {
                            **calibration.details,
                            **wordlist_details,
                            "tech_evidence": technologies,
                            "auth_detection": auth_detection,
                            "dirscan_strategy": dirscan_strategy,
                            "request_headers": summarize_web_headers(request_headers),
                            "derived_extensions": derived_for_meta,
                            "recommended_extensions": recommended_for_meta,
                            "used_extensions": list(effective_extensions),
                            "user_selected_extensions": list(user_extensions) if user_extensions else [],
                            "using_user_extensions": bool(user_extensions),
                            "auto_recommendation_enabled": auto_recommendation_enabled,
                            "using_default_extensions": (not user_extensions)
                            and not (derived_for_meta or recommended_for_meta),
                        }

                        def _sync_ffuf_progress(progress: dict[str, Any]) -> None:
                            with progress_lock:
                                tool_progress_targets[base_url] = {
                                    **progress.get("tool_progress", {}),
                                    "base_url": base_url,
                                    "dirscan_strategy": dirscan_strategy,
                                }
                            _update_progress(t_conn)
                        
                        raw_result = _run_ffuf_scan_with_headers(
                            base_url,
                            run=run,
                            task=task,
                            output_path=runner_core._ffuf_output_path(run, task, base_url),
                            wordlist_path=effective_wordlist_path,
                            extensions=effective_extensions,
                            request_headers=request_headers,
                            filter_sizes=calibration.filter_sizes,
                            filter_codes=calibration.filter_codes,
                            user_headers_provided=bool(run.config.extra_headers),
                            replay_proxy=str(getattr(run.config, "ffuf_replay_proxy", "") or ""),
                            proxy_mode=str(getattr(run.config, "proxy_mode", "none") or "none"),
                            proxy_url=str(getattr(run.config, "proxy_url", "") or ""),
                            progress_callback=_sync_ffuf_progress,
                        )
                        login_gate_note = _apply_login_gate_filter(
                            raw_result,
                            base_url=base_url,
                            strategy=dirscan_strategy,
                            auth_detection=auth_detection,
                        )[1]
                        calibration_details["login_gate_filter"] = login_gate_note
                        artifact = runner_core._write_ffuf_artifact(
                            run, 
                            task, 
                            base_url, 
                            raw_result, 
                            extensions=effective_extensions,
                            recommended_extensions=recommended_for_meta,
                            tech_evidence=technologies,
                            ffuf_extras=ffuf_meta_extras,
                        )
                        insert_artifact(t_conn, artifact)
                        findings = normalize_ffuf_results(
                            raw_result,
                            run_id=run.run_id,
                            task_id=task.task_id,
                        )
                        for finding in findings:
                            if ffuf_meta_extras:
                                ev = {**finding.evidence_json}
                                for k, v in ffuf_meta_extras.items():
                                    if v is not None and k in (
                                        "recursion_depth",
                                        "parent_base_url",
                                        "parent_path",
                                        "seed_type",
                                    ):
                                        ev[k] = v
                                finding = finding.model_copy(update={"evidence_json": ev})
                            insert_finding(t_conn, finding)
                        return DirscanWorkerOutcome(
                            base_url=base_url,
                            artifact_path=str(artifact.path),
                            calibration_details=calibration_details,
                            confirmation_required=None,
                            finding_count=len(findings),
                            artifact_count=1,
                            scanned=True,
                        )
                    finally:
                        with progress_lock:
                            if base_url in running_targets:
                                running_targets.remove(base_url)
                            completed_targets_list.append(base_url)
                        _update_progress(t_conn)
                        t_conn.close()

                def _drain_outcome(outcome: DirscanWorkerOutcome) -> None:
                    nonlocal task_scan_count, task_finding_count, artifact_count
                    with progress_lock:
                        if outcome.confirmation_required is not None:
                            confirmation_required_targets.append(outcome.confirmation_required)
                        if outcome.calibration_details is not None:
                            task_calibrations.append(outcome.calibration_details)
                        if outcome.artifact_path is not None:
                            task_artifact_paths.append(outcome.artifact_path)
                        if outcome.scanned:
                            task_scan_count += 1
                        task_finding_count += outcome.finding_count
                        artifact_count += outcome.artifact_count

                pool_cap = max(1, min(len(dirscan_targets), int(_DIR_POOL_CAP)))
                pending_urls: deque[str] = deque(dirscan_targets)
                active_futures: set[Any] = set()
                with ThreadPoolExecutor(max_workers=pool_cap) as executor:
                    while pending_urls or active_futures:
                        probe_conn = runner_core._open_run_connection(run_id, workspace=workspace)
                        try:
                            run_live = runner_core._require_run(probe_conn, run_id)
                        finally:
                            probe_conn.close()
                        max_parallel = min(
                            pool_cap,
                            _resolve_dirscan_worker_count(run_live, len(dirscan_targets)),
                        )
                        while len(active_futures) < max_parallel and pending_urls:
                            active_futures.add(executor.submit(_worker, pending_urls.popleft()))
                        if not active_futures:
                            break
                        done, _ = wait(active_futures, return_when=FIRST_COMPLETED)
                        for fut in done:
                            active_futures.discard(fut)
                            _drain_outcome(fut.result())

                task_artifact_paths.sort()
                task_calibrations = sorted(task_calibrations, key=_dirscan_note_key)
                confirmation_required_targets = sorted(
                    confirmation_required_targets,
                    key=_dirscan_note_key,
                )

                prior_after = dict(get_task(connection, task.task_id).cursor_json or {})
                inc_meta = runner_core.incremental_dir_enum_cursor_meta(prior_after)
                lineage = runner_core.preserve_dir_enum_lineage_metadata(prior_after)
                mark_task_completed(
                    connection,
                    task.task_id,
                    cursor_json={
                        "scan_count": task_scan_count,
                        "artifact_count": len(task_artifact_paths),
                        "finding_count": task_finding_count,
                        "calibrations": task_calibrations,
                        "confirmation_required_count": len(confirmation_required_targets),
                        "confirmation_required_targets": confirmation_required_targets,
                        "completed_targets": len(completed_targets_list),
                        "tool_progress": [
                            tool_progress_targets[base_url]
                            for base_url in sorted(tool_progress_targets)
                        ],
                        "tool_progress_target_count": len(tool_progress_targets),
                        "input_dirscan_urls": sorted(dirscan_targets),
                        **lineage,
                        **inc_meta,
                        **scope_cursor_json,
                    },
                )
                run = runner_core._require_run(connection, run_id)
                rec_res: dict[str, Any] = {}
                if run.config.dir_recursive_enabled:
                    rec_res = runner_core.maybe_enqueue_recursive_dir_enum_tasks(
                        connection,
                        run_id,
                        task.task_id,
                        workspace=workspace,
                    )
                completed_task_count += 1
                finding_count += task_finding_count
                task_summaries.append(
                    {
                        "task_id": task.task_id,
                        "module": task.module,
                        "tool": task.tool,
                        "scope": task.scope,
                        "state": "completed",
                        "input_count": len(dirscan_targets),
                        "scan_count": task_scan_count,
                        "finding_count": task_finding_count,
                        "artifact_paths": task_artifact_paths,
                        "calibrations": task_calibrations,
                        "confirmation_required_count": len(confirmation_required_targets),
                        "confirmation_required_targets": confirmation_required_targets,
                        "scope_skipped_count": len(skipped_targets),
                        "scope_skipped_targets": skipped_targets,
                        "recursive_dir_enum": rec_res,
                    }
                )
            except Exception as exc:
                mark_task_failed(
                    connection,
                    task.task_id,
                    str(exc),
                    cursor_json={"stage": "ffuf_failed"},
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
            # All discovery is drained — replay discovered endpoints
            # unauthenticated to surface broken access control. Best-effort:
            # a failure here must never block run completion.
            try:
                run = runner_core._require_run(connection, run_id)
                if bool(getattr(run.config, "access_control_test_enabled", False)):
                    from scanner.execution.access_control import run_access_control_checks

                    run_access_control_checks(connection, run_id, config=run.config)
            except Exception:
                pass
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


def _plan_dirscan_filters(run: Any, task: Any, base_url: str) -> DirscanCalibrationDecision:
    artifact_dir = run.config.artifacts_dir / "ffuf"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    canary_paths = _build_canary_paths(task.task_id, base_url)
    with TemporaryDirectory(prefix=f"{task.task_id}-calibration-", dir=artifact_dir) as temp_dir:
        temp_path = Path(temp_dir)
        wordlist_path = temp_path / "canary.txt"
        output_path = temp_path / "ffuf-calibration.json"
        wordlist_path.write_text("\n".join(canary_paths) + "\n", encoding="utf-8")
        result = runner_core.run_ffuf_scan(
            base_url,
            output_path=output_path,
            ffuf_bin=run.config.ffuf_bin,
            wordlist_path=wordlist_path,
            profile=run.config.profile,
            threads=run.config.ffuf_concurrency,
            match_status_codes=(),
            extensions=[],
            auto_calibration=False,
            per_host_auto_calibration=False,
            filter_sizes=[],
        )
    return _derive_calibration_decision(base_url, canary_paths, result.matches)


def _resolve_dirscan_worker_count(run: Any, target_count: int) -> int:
    from scanner.config import DIR_ENUM_MAX_WORKERS

    if not bool(getattr(run.config, "ffuf_parallel_enabled", True)):
        return 1
    if target_count <= 1:
        return 1
    if runner_core.run_ffuf_scan.__module__ != "scanner.adapters.ffuf_runner":
        return 1
    max_para = int(getattr(run.config, "ffuf_max_parallel_tasks", 3) or 1)
    return max(1, min(target_count, max_para, int(run.config.max_concurrency or 1), DIR_ENUM_MAX_WORKERS))




def _run_ffuf_scan_with_headers(
    base_url: str,
    *,
    run: Any,
    task: Any,
    output_path: Path,
    wordlist_path: Path,
    extensions: list[str],
    request_headers: dict[str, str],
    filter_sizes: list[int],
    filter_codes: list[int] | None = None,
    user_headers_provided: bool,
    replay_proxy: str,
    proxy_mode: str,
    proxy_url: str,
    progress_callback: Any | None = None,
) -> ffuf_adapter.FfufRunResult:
    proxy_mode_norm = str(proxy_mode or "").strip().lower()
    proxy_url_value = str(proxy_url or "").strip()
    ffuf_proxy = proxy_url_value if proxy_mode_norm in {"http", "socks"} and proxy_url_value else None
    filter_codes = filter_codes or []
    if runner_core.run_ffuf_scan.__module__ != "scanner.adapters.ffuf_runner":
        try:
            return runner_core.run_ffuf_scan(
                base_url,
                output_path=output_path,
                ffuf_bin=run.config.ffuf_bin,
                wordlist_path=wordlist_path,
                profile=run.config.profile,
                threads=run.config.ffuf_concurrency,
                match_status_codes=(),
                extensions=extensions,
                auto_calibration=True,
                per_host_auto_calibration=True,
                filter_sizes=filter_sizes,
                filter_codes=filter_codes,
                proxy=ffuf_proxy,
            )
        except TypeError:
            return runner_core.run_ffuf_scan(
                base_url,
                output_path=output_path,
                ffuf_bin=run.config.ffuf_bin,
                wordlist_path=wordlist_path,
                profile=run.config.profile,
                threads=run.config.ffuf_concurrency,
                match_status_codes=(),
                extensions=extensions,
                auto_calibration=True,
                per_host_auto_calibration=True,
                filter_sizes=filter_sizes,
            )

    normalized_base_url = ffuf_adapter._normalize_base_url(base_url)
    command = ffuf_adapter._build_ffuf_command(
        ffuf_bin=run.config.ffuf_bin,
        base_url=normalized_base_url,
        output_path=output_path,
        wordlist_path=wordlist_path,
        profile=run.config.profile,
        threads=run.config.ffuf_concurrency,
        match_status_codes=(),
        extensions=extensions,
        auto_calibration=True,
        per_host_auto_calibration=True,
        filter_sizes=filter_sizes,
        filter_codes=filter_codes,
    )
    command = [item for item in command if item != "-s"]
    seen_header_names: set[str] = set()
    for name, value in request_headers.items():
        lowered_name = str(name).strip().lower()
        if lowered_name in seen_header_names:
            continue
        if lowered_name == "user-agent" and not user_headers_provided:
            continue
        seen_header_names.add(lowered_name)
        command.extend(["-H", f"{name}: {value}"])
    if not user_headers_provided and "user-agent" not in seen_header_names:
        command.extend(["-H", f"User-Agent: {DEFAULT_FFUF_USER_AGENT}"])
        seen_header_names.add("user-agent")
    replay_proxy_value = replay_proxy.strip()
    if replay_proxy_value:
        if not replay_proxy_value.lower().startswith(("http://", "https://")):
            replay_proxy_value = f"http://{replay_proxy_value}"
        command.extend(["-replay-proxy", replay_proxy_value])
    if ffuf_proxy:
        command.extend(["-x", ffuf_proxy])
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if ffuf_adapter._default_runner.__module__ != "scanner.adapters.ffuf_runner":
        completed = ffuf_adapter._default_runner(command)
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip() or "ffuf command failed"
            raise ffuf_adapter.FfufError(f"ffuf exited with code {completed.returncode}: {detail}")
        if not output_path.exists():
            raise ffuf_adapter.FfufError("ffuf did not produce the expected JSON output file")
        raw_output = output_path.read_text(encoding="utf-8")
        if not raw_output.strip():
            return ffuf_adapter.FfufRunResult(
                command=command,
                base_url=normalized_base_url,
                output_path=output_path,
                matches=[],
                raw_output=raw_output,
            )
        return ffuf_adapter.FfufRunResult(
            command=command,
            base_url=normalized_base_url,
            output_path=output_path,
            matches=ffuf_adapter._parse_ffuf_output(raw_output),
            raw_output=raw_output,
        )
    progress_state = {
        "processed_count": 0,
        "total_count": _estimate_ffuf_total_count(wordlist_path, extensions),
        "stats_line": "",
    }
    state_lock = Lock()

    def _handle_progress_line(line: str) -> None:
        ratio_match = FFUF_RATIO_RE.search(line)
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

    def _snapshot() -> None:
        if progress_callback is None:
            return
        with state_lock:
            total_count = cast(int, progress_state["total_count"])
            current_processed_count = cast(int, progress_state["processed_count"])
            processed_count = min(current_processed_count, total_count) if total_count > 0 else current_processed_count
            percent = round((processed_count / total_count) * 100, 2) if total_count > 0 else 0.0
            snapshot = {
                "tool_progress": {
                    "tool": "ffuf",
                    "processed_count": processed_count,
                    "total_count": total_count,
                    "percent": percent,
                    "stats_line": str(progress_state["stats_line"]),
                },
            }
        progress_callback(snapshot)

    completed = runner_core._run_command_with_live_progress(
        command,
        stdout_handler=_handle_progress_line,
        stderr_handler=_handle_progress_line,
        snapshot_handler=_snapshot,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "ffuf command failed"
        raise ffuf_adapter.FfufError(f"ffuf exited with code {completed.returncode}: {detail}")
    if not output_path.exists():
        raise ffuf_adapter.FfufError("ffuf did not produce the expected JSON output file")
    raw_output = output_path.read_text(encoding="utf-8")
    if not raw_output.strip():
        return ffuf_adapter.FfufRunResult(
            command=command,
            base_url=normalized_base_url,
            output_path=output_path,
            matches=[],
            raw_output=raw_output,
        )
    return ffuf_adapter.FfufRunResult(
        command=command,
        base_url=normalized_base_url,
        output_path=output_path,
        matches=ffuf_adapter._parse_ffuf_output(raw_output),
        raw_output=raw_output,
    )




def _apply_login_gate_filter(
    result: ffuf_adapter.FfufRunResult,
    *,
    base_url: str,
    strategy: str,
    auth_detection: dict[str, Any] | None,
) -> tuple[ffuf_adapter.FfufRunResult, dict[str, Any]]:
    details = {
        "base_url": base_url,
        "dirscan_strategy": strategy,
        "applied": False,
        "filtered_match_count": 0,
        "reason": "not_applicable",
    }
    if strategy != "auth-limited" or not auth_detection or not auth_detection.get("likely_auth_required"):
        return result, details
    if len(result.matches) < LOGIN_GATE_MIN_MATCH_COUNT:
        details["reason"] = "insufficient_matches"
        return result, details

    fingerprint_counts = Counter(_login_gate_fingerprint(match) for match in result.matches)
    dominant_fingerprint, dominant_count = fingerprint_counts.most_common(1)[0]
    dominant_ratio = dominant_count / len(result.matches)
    if dominant_count < LOGIN_GATE_MIN_MATCH_COUNT or dominant_ratio < LOGIN_GATE_DOMINANT_RATIO:
        details["reason"] = "no_dominant_fingerprint"
        details["dominant_ratio"] = round(dominant_ratio, 3)
        return result, details

    filtered_matches: list[FfufResultEntry] = []
    kept_dominant = False
    filtered_match_count = 0
    for match in result.matches:
        if _login_gate_fingerprint(match) != dominant_fingerprint:
            filtered_matches.append(match)
            continue
        if not kept_dominant:
            filtered_matches.append(match)
            kept_dominant = True
            continue
        filtered_match_count += 1

    if filtered_match_count == 0:
        details["reason"] = "no_duplicate_login_gate_matches"
        return result, details

    details.update(
        {
            "applied": True,
            "filtered_match_count": filtered_match_count,
            "dominant_ratio": round(dominant_ratio, 3),
            "dominant_fingerprint": {
                "status_code": dominant_fingerprint[0],
                "length": dominant_fingerprint[1],
                "words": dominant_fingerprint[2],
                "lines": dominant_fingerprint[3],
                "redirect_target": dominant_fingerprint[4],
                "content_type": dominant_fingerprint[5],
            },
            "reason": "repeated_login_gate_fingerprint",
        }
    )
    return (
        ffuf_adapter.FfufRunResult(
            command=result.command,
            base_url=result.base_url,
            output_path=result.output_path,
            matches=filtered_matches,
            raw_output=result.raw_output,
        ),
        details,
    )


