from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from typer.testing import CliRunner

from scanner.cli import app
from scanner.models import ArtifactRef, Finding
from scanner.storage import connect, insert_artifact, insert_finding


def test_scan_command_creates_run(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["scan", "example.com", "--module", "subdomain_enum", "--module", "port_scan", "--profile", "fast"],
    )

    payload = json.loads(result.stdout)

    assert result.exit_code == 0
    assert payload["target"] == "example.com"
    assert payload["profile"] == "fast"
    assert payload["task_count"] == 2
    assert Path(payload["state_db_path"]).exists()


def test_resume_command_returns_incomplete_tasks(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    created = runner.invoke(app, ["scan", "example.org", "--module", "subdomain_enum"])
    run_id = json.loads(created.stdout)["run_id"]
    resumed = runner.invoke(app, ["resume", run_id])
    payload = json.loads(resumed.stdout)

    assert resumed.exit_code == 0
    assert payload["run_id"] == run_id
    assert payload["incomplete_task_count"] == 1
    assert payload["tasks"][0]["module"] == "subdomain_enum"


def test_extend_command_adds_new_modules_to_existing_run(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    created = runner.invoke(app, ["scan", "example.org", "--module", "port_scan"])
    run_id = json.loads(created.stdout)["run_id"]

    extended = runner.invoke(
        app,
        ["extend", run_id, "--module", "subdomain_enum", "--module", "dir_enum"],
    )
    payload = json.loads(extended.stdout)

    assert extended.exit_code == 0
    assert payload["run_id"] == run_id
    assert payload["added_modules"] == ["subdomain_enum", "dir_enum"]
    assert payload["added_task_count"] == 2


def test_report_command_outputs_seeded_summary(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    now = datetime(2026, 4, 9, 12, 0, tzinfo=UTC)

    created = runner.invoke(app, ["scan", "example.net", "--module", "http_probe"])
    created_payload = json.loads(created.stdout)
    run_id = created_payload["run_id"]
    task_id = created_payload["tasks"][0]["task_id"]
    connection = connect(Path(created_payload["state_db_path"]))

    try:
        insert_finding(
            connection,
            Finding(
                finding_id="finding-cli-1",
                run_id=run_id,
                task_id=task_id,
                module="http_probe",
                target="https://example.net",
                summary="Observed live HTTP endpoint",
                evidence_json={"status_code": 200, "title": "Example"},
                created_at=now,
            ),
        )
        insert_artifact(
            connection,
            ArtifactRef(
                artifact_id="artifact-cli-1",
                run_id=run_id,
                task_id=task_id,
                phase_name="http_probe",
                source_tool="httpx",
                artifact_type="raw_jsonl",
                path=tmp_path / "runs" / run_id / "artifacts" / "httpx.jsonl",
                sha256="def456",
                size_bytes=64,
                content_type="application/jsonl",
                created_at=now,
            ),
        )
    finally:
        connection.close()

    report = runner.invoke(app, ["report", run_id])
    payload = json.loads(report.stdout)

    assert report.exit_code == 0
    assert payload["run_id"] == run_id
    assert payload["findings"]["total"] == 1
    assert payload["artifacts"]["total"] == 1
    assert payload["findings"]["items"][0]["summary"] == "Observed live HTTP endpoint"


def test_report_command_writes_html_output(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    now = datetime(2026, 4, 9, 12, 0, tzinfo=UTC)
    html_path = tmp_path / "reports" / "scan.html"

    created = runner.invoke(app, ["scan", "example.io", "--module", "banner_probe"])
    created_payload = json.loads(created.stdout)
    run_id = created_payload["run_id"]
    task_id = created_payload["tasks"][0]["task_id"]
    connection = connect(Path(created_payload["state_db_path"]))

    try:
        insert_finding(
            connection,
            Finding(
                finding_id="finding-cli-banner",
                run_id=run_id,
                task_id=task_id,
                module="banner_probe",
                target="api.example.io:tcp/80",
                status="observed",
                summary="Banner observed on api.example.io:tcp/80",
                evidence_json={
                    "type": "banner",
                    "banner": "Apache/2.4.50",
                    "service": "http",
                },
                created_at=now,
            ),
        )
    finally:
        connection.close()

    report = runner.invoke(app, ["report", run_id, "--html", str(html_path)])
    payload = json.loads(report.stdout)

    assert report.exit_code == 0
    assert payload["run_id"] == run_id
    assert payload["html_report_path"] == str(html_path.resolve())
    assert html_path.exists()
    html = html_path.read_text(encoding="utf-8")
    assert "Run Summary" in html
    assert "Inferred Candidate CVEs" in html


def test_scan_help_clarifies_initialization_behavior() -> None:
    runner = CliRunner()

    result = runner.invoke(app, ["scan", "--help"])
    output = " ".join(result.stdout.split())

    assert result.exit_code == 0
    assert "enqueue pending tasks" in output
    assert "does not execute external scanners" in output
    assert "comma-separated values" in output


def test_report_help_mentions_html_output() -> None:
    runner = CliRunner()

    result = runner.invoke(app, ["report", "--help"])
    output = " ".join(result.stdout.split())

    assert result.exit_code == 0
    assert "persisted JSON report summary" in output
    assert "Optional HTML output path" in output


def test_ui_help_mentions_web_controls() -> None:
    runner = CliRunner()

    result = runner.invoke(app, ["ui", "--help"])
    output = " ".join(result.stdout.split())

    assert result.exit_code == 0
    assert "web UI" in output
    assert "execution control" in output
    assert "partial-result inspection" in output
