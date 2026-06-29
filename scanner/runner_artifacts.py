from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

from scanner.adapters.ffuf_runner import FfufRunResult
from scanner.adapters.httpx_runner import HttpxRunResult
from scanner.adapters.nmap_runner import NmapRunResult
from scanner.adapters.securitytrails_runner import SecurityTrailsSubdomainsResult
from scanner.models import ArtifactRef, RunState, TaskState
from scanner.utils.logging import get_logger

_log = get_logger(__name__)


def _now() -> datetime:
    return datetime.now(UTC)


def _artifact_token(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()[:12]


def write_securitytrails_artifact(
    run: RunState,
    task: TaskState,
    result: SecurityTrailsSubdomainsResult,
) -> ArtifactRef:
    artifact_dir = run.config.artifacts_dir / "securitytrails"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = artifact_dir / f"{task.task_id}.json"
    raw_json = json.dumps(result.raw_response, indent=2, sort_keys=True)
    raw_bytes = raw_json.encode("utf-8")
    artifact_path.write_text(raw_json, encoding="utf-8")
    digest = sha256(raw_bytes).hexdigest()
    return ArtifactRef(
        artifact_id=f"artifact-{task.task_id}-securitytrails-raw",
        run_id=run.run_id,
        task_id=task.task_id,
        phase_name="subdomain_enum",
        source_tool="securitytrails",
        artifact_type="raw_json",
        path=artifact_path,
        sha256=digest,
        size_bytes=len(raw_bytes),
        content_type="application/json",
        created_at=_now(),
        metadata={"endpoint": result.endpoint, "record_count": result.record_count},
    )


def write_httpx_artifact(
    run: RunState,
    task: TaskState,
    result: HttpxRunResult,
) -> ArtifactRef:
    artifact_dir = run.config.artifacts_dir / "httpx"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = artifact_dir / f"{task.task_id}.jsonl"
    raw_bytes = result.raw_output.encode("utf-8")
    artifact_path.write_text(result.raw_output, encoding="utf-8")
    digest = sha256(raw_bytes).hexdigest()
    return ArtifactRef(
        artifact_id=f"artifact-{task.task_id}-httpx-raw",
        run_id=run.run_id,
        task_id=task.task_id,
        phase_name="http_probe",
        source_tool="httpx",
        artifact_type="raw_jsonl",
        path=artifact_path,
        sha256=digest,
        size_bytes=len(raw_bytes),
        content_type="application/x-jsonlines",
        created_at=_now(),
        metadata={
            "command": result.command,
            "target_count": len(result.targets),
            "probe_count": len(result.entries),
        },
    )


def write_nmap_artifact(
    run: RunState,
    task: TaskState,
    result: NmapRunResult,
    *,
    chunk_index: int | None = None,
    chunk_total: int | None = None,
    chunk_label: str | None = None,
) -> ArtifactRef:
    artifact_dir = run.config.artifacts_dir / "nmap"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    if chunk_index is not None:
        file_name = f"{task.task_id}-chunk-{int(chunk_index):03d}.xml"
        artifact_id = f"artifact-{task.task_id}-nmap-c{int(chunk_index):03d}"
    else:
        file_name = f"{task.task_id}.xml"
        artifact_id = f"artifact-{task.task_id}-nmap-raw"
    artifact_path = artifact_dir / file_name
    raw_bytes = result.raw_output.encode("utf-8")
    artifact_path.write_text(result.raw_output, encoding="utf-8")
    digest = sha256(raw_bytes).hexdigest()
    meta: dict[str, Any] = {
        "command": result.command,
        "target_count": len(result.targets),
        "host_count": len(result.hosts),
        "port_count": sum(len(host_result.ports) for host_result in result.hosts),
    }
    scan_warnings = list(getattr(result, "scan_warnings", []))
    if scan_warnings:
        meta["scan_warnings"] = scan_warnings
    if chunk_index is not None:
        meta["chunk_index"] = int(chunk_index)
    if chunk_total is not None:
        meta["chunk_total"] = int(chunk_total)
    if chunk_label:
        meta["chunk_label"] = str(chunk_label)
    return ArtifactRef(
        artifact_id=artifact_id,
        run_id=run.run_id,
        task_id=task.task_id,
        phase_name="port_scan",
        source_tool="nmap",
        artifact_type="raw_xml",
        path=artifact_path,
        sha256=digest,
        size_bytes=len(raw_bytes),
        content_type="application/xml",
        created_at=_now(),
        metadata=meta,
    )


def ffuf_output_path(run: RunState, task: TaskState, base_url: str) -> Path:
    artifact_dir = run.config.artifacts_dir / "ffuf"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    return artifact_dir / f"{task.task_id}-{_artifact_token(base_url)}.json"


def write_ffuf_artifact(
    run: RunState,
    task: TaskState,
    base_url: str,
    result: FfufRunResult,
    *,
    extensions: list[str] | None = None,
    recommended_extensions: list[str] | None = None,
    tech_evidence: list[str] | None = None,
    ffuf_extras: dict[str, Any] | None = None,
) -> ArtifactRef:
    raw_bytes = result.raw_output.encode("utf-8")
    digest = sha256(raw_bytes).hexdigest()
    meta: dict[str, Any] = {
        "command": result.command,
        "base_url": base_url,
        "match_count": len(result.matches),
        "used_extensions": extensions if extensions is not None else [],
        "recommended_extensions": recommended_extensions if recommended_extensions is not None else [],
        "tech_evidence": tech_evidence if tech_evidence is not None else [],
        "raw_results": [match.raw_entry for match in result.matches],
    }
    if ffuf_extras:
        meta.update(ffuf_extras)
    return ArtifactRef(
        artifact_id=f"artifact-{task.task_id}-ffuf-{_artifact_token(base_url)}",
        run_id=run.run_id,
        task_id=task.task_id,
        phase_name="dir_enum",
        source_tool="ffuf",
        artifact_type="raw_json",
        path=result.output_path,
        sha256=digest,
        size_bytes=len(raw_bytes),
        content_type="application/json",
        created_at=_now(),
        metadata=meta,
    )


def clear_task_outputs(connection: sqlite3.Connection, task: TaskState) -> None:
    artifact_rows = connection.execute(
        "SELECT path FROM artifacts WHERE task_id = ?",
        (task.task_id,),
    ).fetchall()
    # Delete files before removing DB entries so a crash between the two steps
    # leaves orphaned DB rows (recoverable) rather than orphaned files (disk leak).
    for row in artifact_rows:
        artifact_path = Path(row["path"])
        try:
            artifact_path.unlink()
        except FileNotFoundError:
            _log.debug("artifact already absent on cleanup: %s", artifact_path)
    connection.execute("DELETE FROM findings WHERE task_id = ?", (task.task_id,))
    connection.execute("DELETE FROM artifacts WHERE task_id = ?", (task.task_id,))
    connection.commit()
