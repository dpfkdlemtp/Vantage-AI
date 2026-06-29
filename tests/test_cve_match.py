from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from scanner.execution import cve_match as cve_match_execution
from scanner.models import Finding
from scanner.runner import cancel_run, create_scan_run
from scanner.storage import connect, insert_finding


def test_match_cve_candidates_uses_signature_engine_only() -> None:
    finding = Finding(
        finding_id="f-ssh",
        run_id="r1",
        module="port_scan",
        target="example.com:22",
        status="observed",
        summary="SSH-2.0-OpenSSH_7.2p2",
        evidence_json={
            "product": "OpenSSH",
            "version": "7.2p2",
            "service": "ssh",
        },
        created_at=datetime.now(UTC),
    )

    candidates = cve_match_execution.match_cve_candidates([finding], run_id="r1", task_id="t1")

    cve_ids = [candidate.evidence_json["cve_id"] for candidate in candidates]
    assert cve_ids == ["CVE-2016-0777"]
    assert all(candidate.status == "candidate" for candidate in candidates)
    assert all(candidate.evidence_json["candidate_only"] is True for candidate in candidates)


def test_execute_cve_match_tasks_persists_candidate_only_findings(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    now = datetime(2026, 4, 11, 9, 0, tzinfo=UTC)
    created = create_scan_run("example.org", modules=["cve_match"])
    run_id = created["run_id"]
    task_id = created["tasks"][0]["task_id"]
    connection = connect(Path(created["state_db_path"]))

    try:
        insert_finding(
            connection,
            Finding(
                finding_id="finding-portscan-apache",
                run_id=run_id,
                module="port_scan",
                target="api.example.org:tcp/80",
                summary="Observed tcp/80 open on api.example.org [http]",
                evidence_json={
                    "product": "Apache httpd",
                    "version": "2.4.50",
                    "service": "http",
                },
                tags=["portscan", "open"],
                created_at=now,
            ),
        )
    finally:
        connection.close()

    summary = cve_match_execution.execute_cve_match_tasks(run_id)
    connection = connect(Path(created["state_db_path"]))
    try:
        task_row = connection.execute(
            "SELECT state, cursor_json FROM tasks WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        candidate_rows = connection.execute(
            """
            SELECT status, evidence_json
            FROM findings
            WHERE task_id = ?
            ORDER BY created_at ASC, finding_id ASC
            """,
            (task_id,),
        ).fetchall()
    finally:
        connection.close()

    assert summary["completed_task_count"] == 1
    assert summary["failed_task_count"] == 0
    assert summary["finding_count"] == 1
    assert task_row is not None
    assert task_row["state"] == "completed"
    assert json.loads(task_row["cursor_json"])["finding_count"] == 1
    assert len(candidate_rows) == 1
    assert candidate_rows[0]["status"] == "candidate"
    assert json.loads(candidate_rows[0]["evidence_json"])["candidate_only"] is True


def test_execute_cve_match_tasks_respects_cancellation(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    now = datetime(2026, 4, 11, 9, 0, tzinfo=UTC)
    created = create_scan_run("example.org", modules=["cve_match"])
    run_id = created["run_id"]
    task_id = created["tasks"][0]["task_id"]
    connection = connect(Path(created["state_db_path"]))

    try:
        insert_finding(
            connection,
            Finding(
                finding_id="finding-httpx-apache",
                run_id=run_id,
                module="http_probe",
                target="https://www.example.org/",
                summary="Observed live host www.example.org [200]",
                evidence_json={"title": "Apache httpd 2.4.49"},
                tags=["httpx", "alive", "host"],
                created_at=now,
            ),
        )
    finally:
        connection.close()

    original_matcher = cve_match_execution.match_cve_candidates

    def cancelling_matcher(*args, **kwargs):
        cancel_run(run_id)
        return original_matcher(*args, **kwargs)

    monkeypatch.setattr(cve_match_execution, "match_cve_candidates", cancelling_matcher)

    summary = cve_match_execution.execute_cve_match_tasks(run_id)
    connection = connect(Path(created["state_db_path"]))
    try:
        task_row = connection.execute(
            "SELECT state, cursor_json FROM tasks WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        run_row = connection.execute(
            "SELECT status FROM runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        candidate_count = connection.execute(
            "SELECT COUNT(*) AS count FROM findings WHERE task_id = ?",
            (task_id,),
        ).fetchone()
    finally:
        connection.close()

    assert summary["completed_task_count"] == 0
    assert summary["failed_task_count"] == 0
    assert summary["finding_count"] == 0
    assert summary["tasks"][0]["state"] == "cancelled"
    assert run_row is not None
    assert run_row["status"] == "cancelled"
    assert task_row is not None
    assert task_row["state"] == "cancelled"
    assert candidate_count is not None
    assert candidate_count["count"] == 0
