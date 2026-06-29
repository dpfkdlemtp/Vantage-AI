from __future__ import annotations

import json
import socket
import struct
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from scanner import runner as runner_core
from scanner.config import resolve_tool
from scanner.models import Finding
from scanner.state import (
    get_incomplete_tasks,
    mark_run_finished,
    mark_run_running,
    mark_task_completed,
    mark_task_failed,
    mark_task_running,
)
from scanner.storage import insert_finding


def classify_banner(banner: bytes) -> str:
    s = bytes(banner[:512])
    if not s:
        return "unknown"
    low = s.lower()
    if low.startswith(b"ssh-"):
        return "SSH"
    if s[:4] == b"220 " and b"ftp" in low[:80]:
        return "FTP"
    if s[:4] == b"220 " and b"esmtp" in low[:200]:
        return "SMTP"
    if s[:4] == b"220 " and b"smtp" in low[:200]:
        return "SMTP"
    if s[:4] == b"220 ":
        if b"ftpd" in low or b"filezilla" in low:
            return "FTP"
        return "SMTP"
    if low.startswith(b"http/") or (b"http" in low[:10] and b"/" in s[:20]):
        return "HTTP"
    if b"\xff\xfd" in s[:10] or b"telnet" in low:
        return "unknown"
    return "unknown"


def _printable_prefix(raw: bytes, limit: int = 512) -> str:
    chunk = raw[:limit]
    out = []
    for b in chunk:
        if b in (9, 10, 13) or 32 <= b < 127:
            out.append(chr(b))
        else:
            out.append(".")
    return "".join(out).strip()


def read_tcp_banner(
    host: str,
    port: int,
    *,
    connect_timeout: float = 3.0,
    read_timeout: float = 2.0,
) -> bytes:
    addr = (host, int(port))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(connect_timeout)
    try:
        s.connect(addr)
    except OSError:
        s.close()
        return b""
    s.settimeout(read_timeout)
    try:
        data = s.recv(2048)
    except (TimeoutError, OSError, struct.error, socket.error):
        data = b""
    finally:
        s.close()
    return data or b""


def _port_needs_probe(ev: dict[str, Any]) -> bool:
    st = str(ev.get("state") or "").lower()
    if st and st != "open":
        return False
    svc = str(ev.get("service") or "").strip().lower()
    if not svc or svc in ("unknown", "tcp", "tcpwrapped", "1", "0"):
        return True
    return False


def execute_banner_probe_tasks(run_id: str, *, workspace: Path | None = None) -> dict[str, Any]:
    connection = runner_core._open_run_connection(run_id, workspace=workspace)
    try:
        tool = resolve_tool("banner_probe")
        tasks = [t for t in get_incomplete_tasks(connection, run_id) if t.module == "banner_probe" and t.tool == tool]
        if not tasks:
            return {
                "run_id": run_id,
                "processed_task_count": 0,
                "completed_task_count": 0,
                "failed_task_count": 0,
                "finding_count": 0,
                "tasks": [],
            }
        mark_run_running(connection, run_id)
        completed = 0
        failed = 0
        total_f = 0
        summaries: list[dict[str, Any]] = []
        for task in tasks:
            try:
                mark_task_running(connection, task.task_id, cursor_json={"stage": "banner_probe"})
                n = 0
                seen_key: set[str] = set()
                for row in connection.execute(
                    "SELECT evidence_json, finding_id FROM findings WHERE run_id = ? AND module = 'port_scan' ORDER BY created_at",
                    (run_id,),
                ):
                    ev = json.loads(row["evidence_json"])
                    if not isinstance(ev, dict) or not _port_needs_probe(ev):
                        continue
                    host = str(ev.get("host") or ev.get("ip") or "").strip()
                    pr = ev.get("port")
                    if not host or pr is None:
                        continue
                    try:
                        port = int(pr)
                    except (TypeError, ValueError):
                        continue
                    k = f"{host}:{port}"
                    if k in seen_key:
                        continue
                    seen_key.add(k)
                    raw = read_tcp_banner(host, port)
                    label = classify_banner(raw)
                    preview = _printable_prefix(raw)
                    if not preview and not raw:
                        continue
                    now = datetime.now(UTC)
                    insert_finding(
                        connection,
                        Finding(
                            finding_id=f"finding-banner-{uuid4().hex[:16]}",
                            run_id=run_id,
                            task_id=task.task_id,
                            module="banner_probe",
                            target=f"{host}:{port}",
                            summary=f"Banner ({label}): {preview[:80]}",
                            evidence_json={
                                "type": "banner",
                                "host": host,
                                "port": port,
                                "protocol": str(ev.get("protocol") or "tcp").lower(),
                                "guessed_service": label,
                                "banner_preview": preview,
                            },
                            tags=["banner", "port", label.lower()],
                            created_at=now,
                        ),
                    )
                    n += 1
                mark_task_completed(
                    connection,
                    task.task_id,
                    cursor_json={"stage": "banner_probe", "findings": n},
                )
                connection.commit()
                completed += 1
                total_f += n
                summaries.append({"task_id": task.task_id, "state": "completed", "finding_count": n})
            except Exception as exc:  # noqa: BLE001
                mark_task_failed(
                    connection,
                    task.task_id,
                    str(exc),
                    cursor_json={"stage": "banner_probe_failed"},
                )
                failed += 1
                summaries.append({"task_id": task.task_id, "state": "failed", "last_error": str(exc)})
        if not get_incomplete_tasks(connection, run_id):
            mark_run_finished(connection, run_id, "completed")
        return {
            "run_id": run_id,
            "processed_task_count": len(tasks),
            "completed_task_count": completed,
            "failed_task_count": failed,
            "finding_count": total_f,
            "tasks": summaries,
        }
    finally:
        connection.close()
