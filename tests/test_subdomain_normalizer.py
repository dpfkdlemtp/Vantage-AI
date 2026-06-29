from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from scanner.adapters.httpx_runner import HttpxProbeResult, HttpxRunResult
from scanner.adapters.securitytrails_runner import SecurityTrailsSubdomainsResult
from scanner.models import Finding
from scanner.normalizers.subdomain import (
    normalize_httpx_probe_results,
    normalize_securitytrails_subdomains,
)
from scanner.runner import create_scan_run, execute_http_probe_tasks, execute_subdomain_enum_tasks
from scanner.state import get_run, get_task
from scanner.storage import connect, insert_finding


def test_normalize_securitytrails_subdomains_output() -> None:
    observed_at = datetime(2026, 4, 9, 12, 0, tzinfo=UTC)
    result = SecurityTrailsSubdomainsResult(
        root_domain="example.com",
        endpoint="https://api.securitytrails.com/v1/domain/example.com/subdomains",
        subdomains=["api", "www.example.com", "api"],
        record_count=3,
        raw_response={"subdomains": ["api", "www.example.com", "api"], "record_count": 3},
    )

    findings = normalize_securitytrails_subdomains(
        result,
        run_id="run-123",
        task_id="task-123",
        observed_at=observed_at,
    )

    assert [finding.target for finding in findings] == ["api.example.com", "www.example.com"]
    assert findings[0].module == "subdomain_enum"
    assert findings[0].tags == ["subdomain", "passive", "securitytrails"]
    assert findings[0].evidence_json["root_domain"] == "example.com"
    assert findings[0].evidence_json["subdomain"] == "api"
    assert findings[0].created_at == observed_at


def test_normalize_httpx_probe_results_output() -> None:
    observed_at = datetime(2026, 4, 9, 12, 0, tzinfo=UTC)
    result = HttpxRunResult(
        command=["httpx", "-json"],
        targets=["api.example.com", "www.example.com"],
        raw_output="",
        entries=[
            HttpxProbeResult(
                input_target="api.example.com",
                url="https://api.example.com/",
                host="api.example.com",
                path="/",
                scheme="https",
                port=443,
                status_code=200,
                title="API",
                technologies=["nginx"],
                content_type="text/html",
                webserver="nginx",
                ip="1.2.3.4",
                cname=["api-origin.example.com"],
                probe_status="success",
                raw_entry={"url": "https://api.example.com/"},
            ),
            HttpxProbeResult(
                input_target="www.example.com",
                url="https://www.example.com/login",
                host="www.example.com",
                path="/login",
                scheme="https",
                port=443,
                status_code=302,
                title=None,
                technologies=[],
                content_type=None,
                webserver=None,
                ip=None,
                cname=[],
                probe_status="success",
                raw_entry={"url": "https://www.example.com/login"},
            ),
        ],
    )

    findings = normalize_httpx_probe_results(
        result,
        run_id="run-httpx",
        task_id="task-httpx",
        observed_at=observed_at,
    )

    assert [finding.target for finding in findings] == ["api.example.com", "https://www.example.com/login"]
    assert findings[0].tags == ["httpx", "alive", "host"]
    assert findings[0].evidence_json["status_code"] == 200
    assert findings[1].tags == ["httpx", "alive", "path"]
    assert findings[1].summary == "Observed live path https://www.example.com/login [302]"
    assert findings[1].created_at == observed_at


def test_execute_subdomain_enum_tasks_persists_artifact_and_findings(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    created = create_scan_run("example.com", modules=["subdomain_enum"])
    run_id = created["run_id"]
    task_id = created["tasks"][0]["task_id"]

    fake_result = SecurityTrailsSubdomainsResult(
        root_domain="example.com",
        endpoint="https://api.securitytrails.com/v1/domain/example.com/subdomains",
        subdomains=["api", "www"],
        record_count=2,
        raw_response={"subdomains": ["api", "www"], "record_count": 2},
    )
    monkeypatch.setattr("scanner.runner.fetch_subdomains", lambda scope, api_key_env_var: fake_result)

    summary = execute_subdomain_enum_tasks(run_id)
    connection = connect(Path(created["state_db_path"]))

    try:
        task = get_task(connection, task_id)
        run = get_run(connection, run_id)
        findings_count = connection.execute(
            "SELECT COUNT(*) AS count FROM findings WHERE run_id = ?",
            (run_id,),
        ).fetchone()["count"]
        artifact_row = connection.execute(
            "SELECT path, sha256 FROM artifacts WHERE task_id = ?",
            (task_id,),
        ).fetchone()
    finally:
        connection.close()

    artifact_path = Path(summary["tasks"][0]["artifact_path"])

    assert summary["processed_task_count"] == 1
    assert summary["completed_task_count"] == 1
    assert summary["finding_count"] == 2
    assert summary["artifact_count"] == 1
    assert task.state == "completed"
    assert run is not None
    assert run.status == "completed"
    assert findings_count == 2
    assert artifact_row is not None
    assert artifact_path.exists()
    assert json.loads(artifact_path.read_text(encoding="utf-8")) == {
        "subdomains": ["api", "www"],
        "record_count": 2,
    }


def test_execute_http_probe_tasks_uses_seeded_subdomain_findings(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    now = datetime(2026, 4, 9, 12, 0, tzinfo=UTC)
    created = create_scan_run("example.net", modules=["http_probe"])
    run_id = created["run_id"]
    task_id = created["tasks"][0]["task_id"]
    state_db_path = Path(created["state_db_path"])
    connection = connect(state_db_path)

    try:
        insert_finding(
            connection,
            Finding(
                finding_id="seed-subdomain-1",
                run_id=run_id,
                module="subdomain_enum",
                target="api.example.net",
                summary="Seeded subdomain finding",
                evidence_json={"source_tool": "securitytrails"},
                tags=["subdomain"],
                created_at=now,
            ),
        )
        insert_finding(
            connection,
            Finding(
                finding_id="seed-subdomain-2",
                run_id=run_id,
                module="subdomain_enum",
                target="www.example.net",
                summary="Seeded subdomain finding",
                evidence_json={"source_tool": "securitytrails"},
                tags=["subdomain"],
                created_at=now,
            ),
        )
    finally:
        connection.close()

    captured: dict[str, object] = {}

    def fake_run_httpx_probe(
        targets: list[str],
        *,
        httpx_bin: str,
        profile: str,
        timeout_seconds: int,
        threads: int,
        rate_limit_per_second: int | None,
    ) -> HttpxRunResult:
        captured["targets"] = targets
        captured["httpx_bin"] = httpx_bin
        captured["profile"] = profile
        return HttpxRunResult(
            command=[httpx_bin, "-json"],
            targets=targets,
            raw_output="\n".join(
                [
                    json.dumps({"input": "api.example.net", "url": "https://api.example.net/", "status_code": 200}),
                    json.dumps(
                        {
                            "input": "www.example.net",
                            "url": "https://www.example.net/login",
                            "status_code": 302,
                            "title": "Login",
                        }
                    ),
                ]
            ),
            entries=[
                HttpxProbeResult(
                    input_target="api.example.net",
                    url="https://api.example.net/",
                    host="api.example.net",
                    path="/",
                    scheme="https",
                    port=443,
                    status_code=200,
                    title=None,
                    technologies=[],
                    content_type=None,
                    webserver=None,
                    ip=None,
                    cname=[],
                    probe_status=None,
                    raw_entry={"url": "https://api.example.net/"},
                ),
                HttpxProbeResult(
                    input_target="www.example.net",
                    url="https://www.example.net/login",
                    host="www.example.net",
                    path="/login",
                    scheme="https",
                    port=443,
                    status_code=302,
                    title="Login",
                    technologies=[],
                    content_type=None,
                    webserver=None,
                    ip=None,
                    cname=[],
                    probe_status=None,
                    raw_entry={"url": "https://www.example.net/login"},
                ),
            ],
        )

    monkeypatch.setattr("scanner.runner.run_httpx_probe", fake_run_httpx_probe)

    summary = execute_http_probe_tasks(run_id)
    connection = connect(state_db_path)

    try:
        task = get_task(connection, task_id)
        run = get_run(connection, run_id)
        http_probe_findings = connection.execute(
            "SELECT target, summary FROM findings WHERE task_id = ? ORDER BY target ASC",
            (task_id,),
        ).fetchall()
        artifact_row = connection.execute(
            "SELECT path, content_type FROM artifacts WHERE task_id = ?",
            (task_id,),
        ).fetchone()
    finally:
        connection.close()

    artifact_path = Path(summary["tasks"][0]["artifact_path"])

    assert captured["targets"] == ["api.example.net", "www.example.net"]
    assert captured["httpx_bin"] == "httpx"
    assert captured["profile"] == "safe"
    assert summary["processed_task_count"] == 1
    assert summary["completed_task_count"] == 1
    assert summary["finding_count"] == 2
    assert summary["artifact_count"] == 1
    assert task.state == "completed"
    assert run is not None
    assert run.status == "completed"
    assert [row["target"] for row in http_probe_findings] == [
        "api.example.net",
        "https://www.example.net/login",
    ]
    assert artifact_row is not None
    assert artifact_row["content_type"] == "application/x-jsonlines"
    assert artifact_path.exists()
    assert len(artifact_path.read_text(encoding="utf-8").splitlines()) == 2
