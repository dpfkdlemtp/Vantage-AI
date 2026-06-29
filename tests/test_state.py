from __future__ import annotations
from datetime import UTC, datetime
from pathlib import Path

from scanner.models import ArtifactRef, Finding, RunState, ScanConfig, TaskState
from scanner.state import (
    get_incomplete_tasks,
    get_run,
    get_task,
    mark_run_finished,
    mark_run_running,
    mark_task_completed,
    mark_task_failed,
    mark_task_running,
)
from scanner.storage import create_run, init_db, insert_artifact, insert_finding, insert_task


def test_init_db_creates_required_tables(tmp_path: Path) -> None:
    db_path = tmp_path / "state.db"

    connection = init_db(db_path)
    tables = {
        row["name"]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    }

    assert {"runs", "tasks", "findings", "artifacts"}.issubset(tables)


def test_task_insert_update_and_resume_flow(tmp_path: Path) -> None:
    db_path = tmp_path / "resume.db"
    connection = init_db(db_path)
    now = datetime(2026, 4, 9, 12, 0, tzinfo=UTC)
    run = RunState(
        run_id="run-001",
        target="example.com",
        config=ScanConfig(
            target="example.com",
            output_root=tmp_path / "runs" / "run-001",
            state_db_path=db_path,
            artifacts_dir=tmp_path / "runs" / "run-001" / "artifacts",
            report_json_path=tmp_path / "reports" / "run-001.json",
        ),
        created_at=now,
        updated_at=now,
    )
    task = TaskState(
        task_id="task-001",
        run_id="run-001",
        module="subdomain_enum",
        tool="securitytrails",
        scope="example.com",
        created_at=now,
        updated_at=now,
    )

    create_run(connection, run)
    insert_task(connection, task)
    mark_run_running(connection, run.run_id)
    mark_task_running(connection, task.task_id, cursor_json={"page": 1})
    mark_task_failed(connection, task.task_id, "temporary api error", cursor_json={"page": 2})

    incomplete = get_incomplete_tasks(connection, run.run_id)
    resumed = get_task(connection, task.task_id)
    persisted_run = get_run(connection, run.run_id)

    assert persisted_run is not None
    assert persisted_run.status == "running"
    assert len(incomplete) == 1
    assert incomplete[0].task_id == task.task_id
    assert resumed.state == "failed"
    assert resumed.attempts == 1
    assert resumed.cursor_json == {"page": 2}
    assert resumed.last_error == "temporary api error"

    mark_task_running(connection, task.task_id, cursor_json={"page": 3})
    mark_task_completed(connection, task.task_id, cursor_json={"page": 3, "done": True})
    mark_run_finished(connection, run.run_id, "completed")
    completed_run = get_run(connection, run.run_id)

    assert get_incomplete_tasks(connection, run.run_id) == []
    assert get_task(connection, task.task_id).state == "completed"
    assert completed_run is not None
    assert completed_run.status == "completed"


def test_finding_and_artifact_persist_with_foreign_keys(tmp_path: Path) -> None:
    db_path = tmp_path / "artifacts.db"
    connection = init_db(db_path)
    now = datetime(2026, 4, 9, 12, 0, tzinfo=UTC)
    run = RunState(
        run_id="run-002",
        target="example.org",
        config=ScanConfig(target="example.org"),
        created_at=now,
        updated_at=now,
    )
    task = TaskState(
        task_id="task-002",
        run_id="run-002",
        module="http_probe",
        tool="httpx",
        scope="https://example.org",
        created_at=now,
        updated_at=now,
    )
    finding = Finding(
        finding_id="finding-002",
        run_id="run-002",
        task_id="task-002",
        module="http_probe",
        target="https://example.org",
        summary="Observed live HTTP service",
        evidence_json={"status_code": 200, "title": "Example"},
        created_at=now,
    )
    artifact = ArtifactRef(
        artifact_id="artifact-002",
        run_id="run-002",
        task_id="task-002",
        phase_name="http_probe",
        source_tool="httpx",
        artifact_type="raw_jsonl",
        path=tmp_path / "runs" / "run-002" / "artifacts" / "httpx.jsonl",
        sha256="def456",
        size_bytes=512,
        content_type="application/jsonl",
        created_at=now,
    )

    create_run(connection, run)
    insert_task(connection, task)
    insert_finding(connection, finding)
    insert_artifact(connection, artifact)

    finding_row = connection.execute(
        "SELECT summary, evidence_json FROM findings WHERE finding_id = ?",
        (finding.finding_id,),
    ).fetchone()
    artifact_row = connection.execute(
        "SELECT path, sha256 FROM artifacts WHERE artifact_id = ?",
        (artifact.artifact_id,),
    ).fetchone()

    assert finding_row is not None
    assert artifact_row is not None
    assert finding_row["summary"] == "Observed live HTTP service"
    assert "\"status_code\":200" in finding_row["evidence_json"]
    assert artifact_row["path"].endswith("httpx.jsonl")
    assert artifact_row["sha256"] == "def456"
