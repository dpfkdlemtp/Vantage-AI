from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from scanner.config import parse_scope_entries, split_auth_header_fields
from scanner.runner import generate_report_summary
from scanner.state import get_run
from scanner.storage import connect


def display_run_name(target: str, created_at: datetime) -> str:
    timestamp = created_at.strftime("%Y%m%d%H%M%S")
    normalized = target.strip().lower()
    parsed = urlparse(normalized)
    if parsed.hostname:
        normalized = parsed.hostname.lower().rstrip(".")
    normalized = normalized.rstrip(".")
    slug = re.sub(r"[^a-z0-9.-]+", "-", normalized).strip("-.")
    return f"{slug or 'target'}-{timestamp}"


def format_run_target_display(workspace: Path, run_id: str, primary_target: str) -> str:
    """When scope.json lists multiple includes, show primary line plus count of additional targets."""
    scope_path = workspace / "runs" / run_id / "scope.json"
    if not scope_path.is_file():
        return primary_target
    try:
        raw = json.loads(scope_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return primary_target
    if not isinstance(raw, dict):
        return primary_target
    include = parse_scope_entries(raw.get("include"))
    if len(include) <= 1:
        return primary_target
    return f"{primary_target} 외 {len(include) - 1}건"


def get_run_view_data(
    *,
    workspace: Path,
    run_id: str,
    execution_manager: Any,
    load_tasks: Callable[[Any, str], list[dict[str, Any]]],
    task_counts: Callable[[list[dict[str, Any]]], dict[str, int]],
    load_scope_controls: Callable[[str, str], dict[str, Any]],
    build_run_progress: Callable[[list[dict[str, Any]]], dict[str, Any]],
    build_execution_plan: Callable[[list[str], list[dict[str, Any]]], dict[str, Any]],
    build_execution_notes: Callable[[list[dict[str, Any]]], dict[str, list[dict[str, Any]]]],
) -> dict[str, Any]:
    state_db_path = workspace / "runs" / run_id / "state.db"
    if not state_db_path.exists():
        raise FileNotFoundError(f"run state database not found for run_id '{run_id}'")

    connection = connect(state_db_path)
    try:
        run = get_run(connection, run_id)
        if run is None:
            raise LookupError(f"run_id '{run_id}' was not found")
        tasks = load_tasks(connection, run_id)
    finally:
        connection.close()

    report = generate_report_summary(run_id, workspace=workspace)
    run_config = run.config.model_dump(mode="json")
    run_config["auth_fields"] = split_auth_header_fields(run.config.extra_headers)
    return {
        "run": {
            "run_id": run.run_id,
            "display_name": display_run_name(run.target, run.created_at),
            "target": run.target,
            "target_display": format_run_target_display(workspace, run_id, run.target),
            "status": run.status,
            "config": run_config,
            "created_at": run.created_at.isoformat(),
            "started_at": run.started_at.isoformat() if run.started_at else None,
            "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        },
        "tasks": tasks,
        "task_counts": task_counts(tasks),
        "execution": {
            "active": execution_manager.is_active(run_id),
            "cancel_requested": execution_manager.is_cancel_requested(run_id),
        },
        "scope": load_scope_controls(run_id, run.target),
        "progress": build_run_progress(tasks),
        "execution_plan": build_execution_plan(
            [str(module) for module in run.config.enabled_phases],
            tasks,
        ),
        "execution_notes": build_execution_notes(tasks),
        "report": report,
    }
