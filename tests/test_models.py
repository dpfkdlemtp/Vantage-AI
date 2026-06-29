from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from scanner.models import ArtifactRef, Finding, RunState, ScanConfig, ScanReport, TaskState


def test_scan_config_round_trip_json() -> None:
    config = ScanConfig(
        target="example.com",
        profile="balanced",
        output_root=Path("runs/run-001"),
        state_db_path=Path("runs/run-001/state.db"),
        artifacts_dir=Path("runs/run-001/artifacts"),
        report_json_path=Path("reports/run-001.json"),
        ffuf_wordlist_path=Path("wordlists/common.txt"),
        extra_headers={"User-Agent": "web-scanner"},
    )

    restored = ScanConfig.model_validate_json(config.model_dump_json())

    assert restored == config
    assert restored.httpx_bin == "httpx"
    assert restored.enabled_phases[0] == "subdomain_enum"


def test_models_serialize_and_restore() -> None:
    now = datetime(2026, 4, 9, 12, 0, tzinfo=UTC)
    config = ScanConfig(target="example.com")
    task = TaskState(
        task_id="task-001",
        run_id="run-001",
        module="subdomain_enum",
        tool="securitytrails",
        scope="example.com",
        cursor_json={"page": 2},
        attempts=1,
        created_at=now,
        updated_at=now,
    )
    finding = Finding(
        finding_id="finding-001",
        run_id="run-001",
        task_id="task-001",
        module="subdomain_enum",
        target="api.example.com",
        summary="Observed subdomain from SecurityTrails",
        evidence_json={"source_tool": "securitytrails", "value": "api.example.com"},
        tags=["subdomain", "passive"],
        created_at=now,
    )
    artifact = ArtifactRef(
        artifact_id="artifact-001",
        run_id="run-001",
        task_id="task-001",
        phase_name="subdomain_enum",
        source_tool="securitytrails",
        artifact_type="raw_json",
        path=Path("runs/run-001/artifacts/securitytrails/subdomains.json"),
        sha256="abc123",
        size_bytes=128,
        content_type="application/json",
        created_at=now,
        metadata={"kind": "tool_output"},
    )
    run = RunState(
        run_id="run-001",
        target="example.com",
        status="running",
        current_phase="subdomain_enum",
        phase_statuses={"subdomain_enum": "running"},
        config=config,
        task_ids=["task-001"],
        artifact_ids=["artifact-001"],
        started_at=now,
        created_at=now,
        updated_at=now,
    )
    report = ScanReport(
        run_id="run-001",
        target="example.com",
        status="running",
        generated_at=now,
        config=config,
        subdomain_count=1,
        artifact_count=1,
        subdomains=[finding],
        artifacts=[artifact],
    )

    restored_run = RunState.model_validate_json(run.model_dump_json())
    restored_report = ScanReport.model_validate_json(report.model_dump_json())
    restored_task = TaskState.model_validate_json(task.model_dump_json())

    assert restored_run == run
    assert restored_report.subdomains[0] == finding
    assert restored_report.artifacts[0] == artifact
    assert restored_task.cursor_json == {"page": 2}
