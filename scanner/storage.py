from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from scanner.models import ArtifactRef, Finding, RunState, TaskState


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path)
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        ensure_service_notes_table(connection)
    except Exception:
        connection.close()
        raise
    return connection


def init_db(db_path: Path) -> sqlite3.Connection:
    connection = connect(db_path)
    try:
        connection.executescript(_load_schema_sql())
        connection.commit()
    except Exception:
        connection.close()
        raise
    return connection


def create_run(connection: sqlite3.Connection, run: RunState) -> None:
    payload = (
        run.run_id,
        run.target,
        run.status,
        _json_dumps(run.config.model_dump(mode="json")),
        _isoformat(run.started_at),
        _isoformat(run.completed_at),
        _isoformat(run.created_at),
        _isoformat(run.updated_at),
    )
    connection.execute(
        """
        INSERT INTO runs (
            run_id,
            target,
            status,
            config_json,
            started_at,
            completed_at,
            created_at,
            updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        payload,
    )
    connection.commit()


def insert_task(connection: sqlite3.Connection, task: TaskState) -> None:
    payload = (
        task.task_id,
        task.run_id,
        task.module,
        task.tool,
        task.scope,
        task.state,
        _json_dumps(task.cursor_json),
        task.attempts,
        task.last_error,
        _isoformat(task.started_at),
        _isoformat(task.completed_at),
        _isoformat(task.created_at),
        _isoformat(task.updated_at),
    )
    connection.execute(
        """
        INSERT INTO tasks (
            task_id,
            run_id,
            module,
            tool,
            scope,
            state,
            cursor_json,
            attempts,
            last_error,
            started_at,
            completed_at,
            created_at,
            updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        payload,
    )
    connection.commit()


def update_task_state(
    connection: sqlite3.Connection,
    task_id: str,
    state: str,
    *,
    cursor_json: dict[str, Any] | None = None,
    attempts: int | None = None,
    last_error: str | None = None,
    started_at: datetime | None = None,
    completed_at: datetime | None = None,
    unless_state_in: tuple[str, ...] | None = None,
) -> bool:
    updated_at = _now()
    if unless_state_in:
        placeholders = ",".join("?" * len(unless_state_in))
        sql = f"""
        UPDATE tasks
        SET state = ?,
            cursor_json = ?,
            attempts = COALESCE(?, attempts),
            last_error = ?,
            started_at = COALESCE(?, started_at),
            completed_at = ?,
            updated_at = ?
        WHERE task_id = ? AND state NOT IN ({placeholders})
        """
        params: tuple[Any, ...] = (
            state,
            _json_dumps(cursor_json),
            attempts,
            last_error,
            _isoformat(started_at),
            _isoformat(completed_at),
            _isoformat(updated_at),
            task_id,
            *unless_state_in,
        )
    else:
        sql = """
        UPDATE tasks
        SET state = ?,
            cursor_json = ?,
            attempts = COALESCE(?, attempts),
            last_error = ?,
            started_at = COALESCE(?, started_at),
            completed_at = ?,
            updated_at = ?
        WHERE task_id = ?
        """
        params = (
            state,
            _json_dumps(cursor_json),
            attempts,
            last_error,
            _isoformat(started_at),
            _isoformat(completed_at),
            _isoformat(updated_at),
            task_id,
        )
    cur = connection.execute(sql, params)
    connection.commit()
    return bool(cur.rowcount)


def insert_finding(connection: sqlite3.Connection, finding: Finding) -> None:
    payload = (
        finding.finding_id,
        finding.run_id,
        finding.task_id,
        finding.module,
        finding.target,
        finding.status,
        finding.summary,
        _json_dumps(finding.evidence_json),
        _json_dumps(finding.tags) if finding.tags else None,
        _isoformat(finding.created_at),
    )
    connection.execute(
        """
        INSERT INTO findings (
            finding_id,
            run_id,
            task_id,
            module,
            target,
            status,
            summary,
            evidence_json,
            tags_json,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        payload,
    )
    connection.commit()


def insert_artifact(connection: sqlite3.Connection, artifact: ArtifactRef) -> None:
    payload = (
        artifact.artifact_id,
        artifact.run_id,
        artifact.task_id,
        artifact.phase_name,
        artifact.source_tool,
        str(artifact.path),
        artifact.sha256,
        artifact.size_bytes,
        artifact.content_type,
        _json_dumps(artifact.metadata) if artifact.metadata else None,
        _isoformat(artifact.created_at),
    )
    connection.execute(
        """
        INSERT INTO artifacts (
            artifact_id,
            run_id,
            task_id,
            module,
            tool,
            path,
            sha256,
            size_bytes,
            content_type,
            metadata_json,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        payload,
    )
    connection.commit()


def ensure_service_notes_table(connection: sqlite3.Connection) -> None:
    """Create service_notes for runs created before this table existed. Idempotent."""
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS service_notes (
            id TEXT PRIMARY KEY,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT,
            service_name TEXT,
            note TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_service_notes_host_port ON service_notes (host, port)"
    )
    connection.commit()


def _service_note_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": str(row["id"]),
        "host": str(row["host"]),
        "port": int(row["port"]),
        "protocol": row["protocol"],
        "service_name": row["service_name"],
        "note": str(row["note"]),
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
    }


def list_service_notes(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    ensure_service_notes_table(connection)
    rows = connection.execute(
        """
        SELECT id, host, port, protocol, service_name, note, created_at, updated_at
        FROM service_notes
        ORDER BY updated_at DESC, id ASC
        """
    ).fetchall()
    return [_service_note_row_to_dict(row) for row in rows]


def fetch_service_note_by_id(
    connection: sqlite3.Connection, note_id: str
) -> dict[str, Any] | None:
    ensure_service_notes_table(connection)
    row = connection.execute(
        """
        SELECT id, host, port, protocol, service_name, note, created_at, updated_at
        FROM service_notes WHERE id = ?
        """,
        (note_id,),
    ).fetchone()
    return _service_note_row_to_dict(row) if row else None


def insert_service_note(
    connection: sqlite3.Connection,
    *,
    note_id: str,
    host: str,
    port: int,
    protocol: str | None,
    service_name: str | None,
    note: str,
    created_at: str,
    updated_at: str,
) -> None:
    ensure_service_notes_table(connection)
    connection.execute(
        """
        INSERT INTO service_notes (
            id, host, port, protocol, service_name, note, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (note_id, host, port, protocol, service_name, note, created_at, updated_at),
    )
    connection.commit()


def update_service_note_text(
    connection: sqlite3.Connection, note_id: str, note: str, updated_at: str
) -> int:
    ensure_service_notes_table(connection)
    cur = connection.execute(
        "UPDATE service_notes SET note = ?, updated_at = ? WHERE id = ?",
        (note, updated_at, note_id),
    )
    connection.commit()
    return int(cur.rowcount or 0)


def delete_service_note_by_id(connection: sqlite3.Connection, note_id: str) -> int:
    ensure_service_notes_table(connection)
    cur = connection.execute("DELETE FROM service_notes WHERE id = ?", (note_id,))
    connection.commit()
    return int(cur.rowcount or 0)


def _load_schema_sql() -> str:
    schema_path = Path(__file__).resolve().parent / "sql" / "schema.sql"
    return schema_path.read_text(encoding="utf-8")


def _json_dumps(value: Any) -> str | None:
    if value is None:
        return None
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _isoformat(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat()


def _now() -> datetime:
    return datetime.now(UTC)
