from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from scanner.adapters.subfinder_runner import SubfinderError, run_subfinder_discovery
from scanner.execution.subdomain import execute_subdomain_enum_tasks
from scanner.runner import create_scan_run
from scanner.state import get_task
from scanner.storage import connect


def test_run_subfinder_discovery_parses_output() -> None:
    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        assert command == ["subfinder", "-silent", "-d", "example.com"]
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="www.example.com\napi.example.com\napi.example.com\n",
            stderr="",
        )

    result = run_subfinder_discovery("Example.COM", runner=runner)

    assert result.root_domain == "example.com"
    assert result.hosts == ["api.example.com", "www.example.com"]


def test_run_subfinder_discovery_empty_output() -> None:
    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    result = run_subfinder_discovery("example.com", runner=runner)

    assert result.hosts == []
    assert result.raw_output == ""


def test_run_subfinder_discovery_failure() -> None:
    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="network unavailable")

    with pytest.raises(SubfinderError, match="network unavailable"):
        run_subfinder_discovery("example.com", runner=runner)


def test_execute_subdomain_enum_tasks_merges_and_dedupes_free_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    created = create_scan_run("example.com", modules=["subdomain_enum"])
    run_id = created["run_id"]
    task_id = created["tasks"][0]["task_id"]
    state_db_path = Path(created["state_db_path"])

    def fake_subfinder(root_domain: str) -> object:
        class Result:
            command = ["subfinder", "-silent", "-d", root_domain]
            hosts = ["www.example.com", "api.example.com", "www.example.com"]
            raw_output = "www.example.com\napi.example.com\nwww.example.com\n"

        return Result()

    def fake_assetfinder(root_domain: str) -> object:
        class Result:
            command = ["assetfinder", "--subs-only", root_domain]
            hosts = ["api.example.com", "cdn.example.com", "outside.test"]
            raw_output = "api.example.com\ncdn.example.com\noutside.test\n"

        return Result()

    monkeypatch.setattr("scanner.execution.subdomain.run_subfinder_discovery", fake_subfinder)
    monkeypatch.setattr("scanner.execution.subdomain.run_assetfinder_discovery", fake_assetfinder)
    monkeypatch.setattr(
        "scanner.execution.subdomain.run_subzy_takeover_check",
        lambda hostnames, *, config, run_id, task_id: [],
    )
    def _no_dnsx(*args, **kwargs):
        raise RuntimeError("dnsx disabled in test")
    monkeypatch.setattr("scanner.execution.subdomain._run_dnsx_source", _no_dnsx)

    summary = execute_subdomain_enum_tasks(run_id)
    connection = connect(state_db_path)

    try:
        task = get_task(connection, task_id)
        finding_rows = connection.execute(
            "SELECT target, summary, evidence_json FROM findings WHERE task_id = ? ORDER BY target ASC",
            (task_id,),
        ).fetchall()
        artifact_rows = connection.execute(
            "SELECT path, metadata_json FROM artifacts WHERE task_id = ? ORDER BY path ASC",
            (task_id,),
        ).fetchall()
    finally:
        connection.close()

    assert summary["processed_task_count"] == 1
    assert summary["completed_task_count"] == 1
    assert summary["failed_task_count"] == 0
    assert summary["finding_count"] == 3
    assert summary["artifact_count"] == 2
    assert sorted(summary["tasks"][0]["sources"]) == ["assetfinder", "subfinder"]
    assert len(summary["tasks"][0]["artifact_paths"]) == 2
    assert task is not None
    assert task.state == "completed"
    assert [row["target"] for row in finding_rows] == [
        "api.example.com",
        "cdn.example.com",
        "www.example.com",
    ]
    api_evidence = json.loads(finding_rows[0]["evidence_json"])
    assert api_evidence["source_tool"] == "multiple"
    assert api_evidence["source_tools"] == ["assetfinder", "subfinder"]
    assert len(artifact_rows) == 2
    assert [json.loads(row["metadata_json"])["source"] for row in artifact_rows] == [
        "assetfinder",
        "subfinder",
    ]
