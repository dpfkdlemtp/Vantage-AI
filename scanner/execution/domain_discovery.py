from __future__ import annotations

import json
import re
import socket
import ssl
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
from urllib.parse import urlsplit

_TLS_HOST = re.compile(r"^[a-z0-9][a-z0-9.-]*$", re.IGNORECASE)


def reverse_dns_for_ip(
    ip: str,
    *,
    timeout_seconds: float = 3.0,
    gethostbyaddr: Any = None,
) -> str | None:
    if not _looks_like_ipv4(ip):
        return None
    fn = gethostbyaddr or socket.gethostbyaddr
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout_seconds)
        name, _a, _b = fn(ip)  # type: ignore[misc]
        n = (name or "").strip().rstrip(".")
        return n or None
    except OSError:
        return None
    finally:
        socket.setdefaulttimeout(old)


def _looks_like_ipv4(host: str) -> bool:
    parts = host.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _names_from_getpeercert(cert: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for t in cert.get("subject", ()):
        for key, val in t:
            if str(key) in ("commonName",) or key == "commonName":
                s = str(val).strip()
                if s:
                    out.append(s)
    for kind, v in cert.get("subjectAltName", ()) or ():
        if str(kind) == "DNS" and v:
            out.append(str(v).strip())
    return list(dict.fromkeys([n for n in out if n]))


def fetch_tls_san_cnames(
    host: str,
    port: int = 443,
    *,
    timeout: float = 5.0,
) -> list[str]:
    if not _TLS_HOST.match(host or ""):
        return []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return []
                return _names_from_getpeercert(cert)
    except OSError:
        return []


def parse_tls_pem_to_domains(pem_text: str) -> list[str]:
    """Test helper: best-effort DNS/CN from PEM (may be incomplete without full parse)."""
    out: list[str] = []
    for m in re.finditer(r"DNS:([A-Za-z0-9*.-]+)", pem_text):
        out.append(m.group(1).strip())
    m2 = re.search(
        r"(?:commonName|CN)\s*=\s*([A-Za-z0-9*.-]+)",
        pem_text,
        re.IGNORECASE,
    )
    if m2:
        out.append(m2.group(1).strip())
    return list(dict.fromkeys([x for x in out if x]))


def _emit(
    connection: Any,
    run_id: str,
    task_id: str,
    ip: str,
    domain: str,
    source: str,
) -> None:
    d = (domain or "").strip().rstrip(".")
    if not d or d == ip:
        return
    now = datetime.now(UTC)
    insert_finding(
        connection,
        Finding(
            finding_id=f"finding-dmap-{uuid4().hex[:16]}",
            run_id=run_id,
            task_id=task_id,
            module="domain_discovery",
            target=f"{ip} → {d}",
            summary=f"Domain mapping ({source}): {d}",
            evidence_json={"type": "domain_mapping", "ip": ip, "domain": d, "source": source},
            tags=["domain_mapping", "dns", source],
            created_at=now,
        ),
    )


def _http_hints(connection: Any, run_id: str) -> list[tuple[str, str, str | None]]:
    out: list[tuple[str, str, str | None]] = []
    rows = connection.execute(
        "SELECT evidence_json FROM findings WHERE run_id = ? AND module = 'http_probe' ORDER BY created_at",
        (run_id,),
    ).fetchall()
    for row in rows:
        ev = json.loads(row["evidence_json"])
        if not isinstance(ev, dict):
            continue
        u = str(ev.get("url") or "")
        p = urlsplit(u)
        host = p.hostname
        if not host:
            continue
        rhost = p.hostname or ""
        ip = str(ev.get("ip") or "").strip()
        if not ip and _looks_like_ipv4(rhost):
            ip = rhost
        if not ip:
            continue
        if rhost and rhost != ip:
            out.append((ip, rhost, "https" if p.scheme == "https" else "http"))
    return out


def _port_ips(connection: Any, run_id: str) -> set[str]:
    ips: set[str] = set()
    for row in connection.execute(
        "SELECT evidence_json FROM findings WHERE run_id = ? AND module = 'port_scan'",
        (run_id,),
    ):
        ev = json.loads(row["evidence_json"])
        if not isinstance(ev, dict):
            continue
        for k in ("ip", "host"):
            c = str(ev.get(k) or "").strip()
            if _looks_like_ipv4(c):
                ips.add(c)
    return ips


def execute_domain_discovery_tasks(run_id: str, *, workspace: Path | None = None) -> dict[str, Any]:
    connection = runner_core._open_run_connection(run_id, workspace=workspace)
    try:
        tool = resolve_tool("domain_discovery")
        tasks = [t for t in get_incomplete_tasks(connection, run_id) if t.module == "domain_discovery" and t.tool == tool]
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
                mark_task_running(connection, task.task_id, cursor_json={"stage": "domain_discovery"})
                seen: set[tuple[str, str, str]] = set()
                n = 0
                for ip, hname, _ in _http_hints(connection, run_id):
                    k = (ip, hname, "http")
                    if k in seen or hname == ip:
                        continue
                    seen.add(k)
                    _emit(connection, run_id, task.task_id, ip, hname, "http")
                    n += 1
                for urow in connection.execute(
                    "SELECT evidence_json FROM findings WHERE run_id = ? AND module = 'http_probe' ORDER BY created_at",
                    (run_id,),
                ):
                    ev = json.loads(urow["evidence_json"])
                    if not isinstance(ev, dict):
                        continue
                    u = str(ev.get("url") or "")
                    p = urlsplit(u)
                    if p.scheme != "https" or not p.hostname:
                        continue
                    h = p.hostname
                    uip = str(ev.get("ip") or "").strip()
                    if not _TLS_HOST.match(h):
                        continue
                    target_ip = uip
                    if not _looks_like_ipv4(target_ip or ""):
                        continue
                    for name in fetch_tls_san_cnames(h, p.port or 443):
                        kk = (target_ip, name, "tls")
                        if kk in seen or not name or name == target_ip:
                            continue
                        seen.add(kk)
                        _emit(connection, run_id, task.task_id, target_ip, name, "tls")
                        n += 1
                for ip in sorted(_port_ips(connection, run_id)):
                    ptr = reverse_dns_for_ip(ip)
                    if ptr:
                        kk = (ip, ptr, "rdns")
                        if kk not in seen and ptr != ip:
                            seen.add(kk)
                            _emit(connection, run_id, task.task_id, ip, ptr, "rdns")
                            n += 1
                mark_task_completed(
                    connection,
                    task.task_id,
                    cursor_json={"stage": "domain_discovery", "findings": n},
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
                    cursor_json={"stage": "domain_discovery_failed"},
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
