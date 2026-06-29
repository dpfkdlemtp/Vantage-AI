from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from typing import Any

from scanner.models import RunState, ScanConfig, TaskProgress, TaskState
from scanner.storage import update_task_state


def mark_run_running(connection: sqlite3.Connection, run_id: str) -> None:
    now = _now()
    connection.execute(
        """
        UPDATE runs
        SET status = 'running',
            started_at = COALESCE(started_at, ?),
            updated_at = ?
        WHERE run_id = ? AND status NOT IN ('cancelled', 'completed')
        """,
        (now.isoformat(), now.isoformat(), run_id),
    )
    connection.commit()


def mark_run_finished(
    connection: sqlite3.Connection,
    run_id: str,
    status: str,
) -> None:
    now = _now()
    connection.execute(
        """
        UPDATE runs
        SET status = ?,
            completed_at = ?,
            updated_at = ?
        WHERE run_id = ? AND status NOT IN ('cancelled', 'completed')
        """,
        (status, now.isoformat(), now.isoformat(), run_id),
    )
    connection.commit()


def mark_task_running(
    connection: sqlite3.Connection,
    task_id: str,
    *,
    cursor_json: dict[str, Any] | None = None,
) -> None:
    current = get_task(connection, task_id)
    attempts = current.attempts + 1
    update_task_state(
        connection,
        task_id,
        "running",
        cursor_json=cursor_json if cursor_json is not None else current.cursor_json,
        attempts=attempts,
        last_error=None,
        started_at=current.started_at or _now(),
        completed_at=None,
        unless_state_in=("cancelled",),
    )


def mark_task_completed(
    connection: sqlite3.Connection,
    task_id: str,
    *,
    cursor_json: dict[str, Any] | None = None,
) -> None:
    current = get_task(connection, task_id)
    update_task_state(
        connection,
        task_id,
        "completed",
        cursor_json=cursor_json if cursor_json is not None else current.cursor_json,
        attempts=current.attempts,
        last_error=None,
        started_at=current.started_at,
        completed_at=_now(),
        unless_state_in=("cancelled",),
    )


def mark_task_failed(
    connection: sqlite3.Connection,
    task_id: str,
    error: str,
    *,
    cursor_json: dict[str, Any] | None = None,
) -> None:
    current = get_task(connection, task_id)
    update_task_state(
        connection,
        task_id,
        "failed",
        cursor_json=cursor_json if cursor_json is not None else current.cursor_json,
        attempts=current.attempts,
        last_error=error,
        started_at=current.started_at,
        completed_at=None,
        unless_state_in=("cancelled",),
    )


def mark_task_cancelled(
    connection: sqlite3.Connection,
    task_id: str,
    *,
    cursor_json: dict[str, Any] | None = None,
) -> None:
    current = get_task(connection, task_id)
    if current.state in {"completed", "cancelled"}:
        return
    payload = dict(current.cursor_json or {})
    if cursor_json:
        payload.update(cursor_json)
    payload.setdefault("stage", "cancelled")
    payload["cancelled_at"] = _now().isoformat()
    update_task_state(
        connection,
        task_id,
        "cancelled",
        cursor_json=payload,
        attempts=current.attempts,
        last_error=current.last_error,
        started_at=current.started_at,
        completed_at=_now(),
    )


def mark_run_cancelled(connection: sqlite3.Connection, run_id: str) -> None:
    now = _now()
    connection.execute(
        """
        UPDATE runs
        SET status = 'cancelled',
            completed_at = COALESCE(completed_at, ?),
            updated_at = ?
        WHERE run_id = ?
          AND status NOT IN ('completed', 'cancelled')
        """,
        (now.isoformat(), now.isoformat(), run_id),
    )
    connection.commit()


def _intish(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value == int(value):
        return int(value)
    return None


def _should_preserve_cidr_resumable_on_cancel(
    task: TaskState, cursor: dict[str, Any], run_config: ScanConfig | None
) -> bool:
    if run_config is None or not run_config.cidr_resume_enabled:
        return False
    if task.module != "port_scan" or str(task.tool) != "nmap":
        return False
    if not cursor.get("cidr_resume_in_progress"):
        return False
    o = _intish(cursor.get("cidr_next_offset"))
    t = _intish(cursor.get("cidr_total_addresses"))
    if o is None or t is None or t <= 0:
        return False
    return o < t


def cancel_run_tasks(connection: sqlite3.Connection, run_id: str) -> list[str]:
    rows = connection.execute(
        """
        SELECT task_id
        FROM tasks
        WHERE run_id = ?
          AND state IN ('pending', 'running', 'failed')
        ORDER BY created_at ASC, rowid ASC
        """,
        (run_id,),
    ).fetchall()
    run = get_run(connection, run_id)
    cfg = run.config if run is not None else None
    cancelled_task_ids: list[str] = []
    for row in rows:
        task_id = str(row["task_id"])
        current = get_task(connection, task_id)
        c = current.cursor_json or {}
        if _should_preserve_cidr_resumable_on_cancel(current, c, cfg):
            payload = {**c, "cidr_stopped": "cancel_run_request"}
            mark_task_failed(
                connection,
                task_id,
                "CIDR port scan stopped (resumable)",
                cursor_json=payload,
            )
        elif str(current.state) == "failed" and "resumable" in str(current.last_error or "").lower():
            continue
        else:
            mark_task_cancelled(connection, task_id)
        cancelled_task_ids.append(task_id)
    return cancelled_task_ids


def is_run_cancelled(connection: sqlite3.Connection, run_id: str) -> bool:
    run = get_run(connection, run_id)
    return run is not None and run.status == "cancelled"


def get_run(connection: sqlite3.Connection, run_id: str) -> RunState | None:
    row = connection.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    if row is None:
        return None
    return RunState(
        run_id=row["run_id"],
        target=row["target"],
        status=row["status"],
        config=ScanConfig.model_validate(json.loads(row["config_json"])),
        started_at=_parse_datetime(row["started_at"]),
        completed_at=_parse_datetime(row["completed_at"]),
        created_at=_parse_datetime(row["created_at"]) or _now(),
        updated_at=_parse_datetime(row["updated_at"]) or _now(),
    )


def get_task(connection: sqlite3.Connection, task_id: str) -> TaskState:
    row = connection.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
    if row is None:
        raise LookupError(f"unknown task_id: {task_id}")
    return _row_to_task(row)


def get_incomplete_tasks(connection: sqlite3.Connection, run_id: str) -> list[TaskState]:
    rows = connection.execute(
        """
        SELECT *
        FROM tasks
        WHERE run_id = ?
          AND state IN ('pending', 'running', 'failed')
        ORDER BY created_at ASC, task_id ASC
        """,
        (run_id,),
    ).fetchall()
    return [_row_to_task(row) for row in rows]


def get_tasks(connection: sqlite3.Connection, run_id: str) -> list[TaskState]:
    rows = connection.execute(
        """
        SELECT *
        FROM tasks
        WHERE run_id = ?
        ORDER BY created_at ASC, rowid ASC
        """,
        (run_id,),
    ).fetchall()
    return [_row_to_task(row) for row in rows]


def _floatish_value(value: object) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return None


def summarize_task_progress(task: TaskState) -> TaskProgress:
    cursor_json = task.cursor_json or {}
    cidr_rem = _floatish_value(cursor_json.get("cidr_estimated_remaining_min"))
    cidr_avg = _floatish_value(cursor_json.get("cidr_avg_chunk_min"))
    if cidr_avg is None:
        asec = _floatish_value(cursor_json.get("cidr_avg_chunk_duration_sec"))
        if asec is not None and asec > 0:
            cidr_avg = round(asec / 60.0, 2)
    return TaskProgress(
        task_id=task.task_id,
        module=task.module,
        state=task.state,
        current_phase=_string_value(cursor_json.get("stage")),
        total_targets=_first_int(cursor_json, "total_targets", "input_count", "target_count"),
        queued_count=_first_int(cursor_json, "queued_targets", "queued_count"),
        running_count=_first_int(cursor_json, "running_targets", "running_count"),
        completed_count=_first_int(cursor_json, "completed_targets", "completed_count"),
        processed_count=_first_int(cursor_json, "processed_count", "scan_count", "completed_count"),
        finding_count=_first_int(cursor_json, "finding_count"),
        artifact_count=_first_int(cursor_json, "artifact_count"),
        last_error=task.last_error,
        chunk_index=_first_int(cursor_json, "cidr_chunk_index", "chunk_index"),
        chunk_total=_first_int(cursor_json, "cidr_chunk_total", "chunk_total"),
        chunk_label=_string_value(cursor_json.get("cidr_chunk_label")) or _string_value(cursor_json.get("chunk_label")),
        last_checkpoint_at=_string_value(cursor_json.get("last_checkpoint_at")),
        cidr_estimated_remaining_min=cidr_rem,
        cidr_avg_chunk_min=cidr_avg,
        cidr_downstream_stage=_string_value(cursor_json.get("cidr_downstream_stage")),
    )


def _row_to_task(row: sqlite3.Row) -> TaskState:
    cursor_json = json.loads(row["cursor_json"]) if row["cursor_json"] else None
    return TaskState(
        task_id=row["task_id"],
        run_id=row["run_id"],
        module=row["module"],
        tool=row["tool"],
        scope=row["scope"],
        state=row["state"],
        cursor_json=cursor_json,
        attempts=row["attempts"],
        last_error=row["last_error"],
        started_at=_parse_datetime(row["started_at"]),
        completed_at=_parse_datetime(row["completed_at"]),
        created_at=_parse_datetime(row["created_at"]) or _now(),
        updated_at=_parse_datetime(row["updated_at"]) or _now(),
    )


def _first_int(cursor_json: dict[str, Any], *keys: str) -> int | None:
    for key in keys:
        value = cursor_json.get(key)
        if isinstance(value, int):
            return value
    return None


def _string_value(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _parse_datetime(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _now() -> datetime:
    return datetime.now(UTC)
