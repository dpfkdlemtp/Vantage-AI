from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from scanner.adapters.nmap_runner import NmapHostResult, NmapPortResult, NmapRunResult
from scanner.models import Finding
from scanner.normalizers.portscan import normalize_nmap_results
from scanner.runner import create_scan_run, execute_port_scan_tasks
from scanner.state import get_run, get_task
from scanner.storage import connect, insert_finding


def test_normalize_nmap_results_output() -> None:
    observed_at = datetime(2026, 4, 9, 12, 0, tzinfo=UTC)
    result = NmapRunResult(
        command=["nmap", "-oX", "-"],
        targets=["api.example.com"],
        raw_output="",
        hosts=[
            NmapHostResult(
                host="api.example.com",
                ip="203.0.113.10",
                status="up",
                hostnames=["api.example.com"],
                ports=[
                    NmapPortResult(
                        protocol="tcp",
                        port=22,
                        state="open",
                        service="ssh",
                        product="OpenSSH",
                        version="9.0",
                        extrainfo=None,
                        raw_entry={"port": 22},
                    ),
                    NmapPortResult(
                        protocol="tcp",
                        port=443,
                        state="open",
                        service="https",
                        product="nginx",
                        version="1.25.3",
                        extrainfo="Ubuntu",
                        raw_entry={"port": 443},
                    ),
                ],
                raw_host={"host": "api.example.com"},
            )
        ],
    )

    findings = normalize_nmap_results(
        result,
        run_id="run-nmap",
        task_id="task-nmap",
        observed_at=observed_at,
    )

    assert [finding.target for finding in findings] == [
        "api.example.com:tcp/22",
        "api.example.com:tcp/443",
    ]
    assert findings[0].module == "port_scan"
    assert findings[0].tags == ["portscan", "nmap", "tcp", "open", "service"]
    assert findings[0].evidence_json["service"] == "ssh"
    assert findings[1].evidence_json["product"] == "nginx"
    assert findings[1].evidence_json["version"] == "1.25.3"
    assert findings[1].summary == "Observed tcp/443 open on api.example.com [https]"
    assert findings[1].created_at == observed_at


def test_execute_port_scan_tasks_uses_seeded_discovery_targets(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    now = datetime(2026, 4, 9, 12, 0, tzinfo=UTC)
    created = create_scan_run("example.net", modules=["port_scan"])
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
                summary="Discovered subdomain api.example.net",
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
                target="blog.example.net",
                summary="Discovered subdomain blog.example.net",
                evidence_json={"source_tool": "securitytrails"},
                tags=["subdomain"],
                created_at=now,
            ),
        )
        insert_finding(
            connection,
            Finding(
                finding_id="seed-httpx-host",
                run_id=run_id,
                module="http_probe",
                target="api.example.net",
                summary="Observed live host api.example.net [200]",
                evidence_json={"host": "api.example.net", "url": "https://api.example.net/"},
                tags=["httpx", "alive", "host"],
                created_at=now,
            ),
        )
        insert_finding(
            connection,
            Finding(
                finding_id="seed-httpx-path",
                run_id=run_id,
                module="http_probe",
                target="https://www.example.net/login",
                summary="Observed live path https://www.example.net/login [302]",
                evidence_json={"url": "https://www.example.net/login"},
                tags=["httpx", "alive", "path"],
                created_at=now,
            ),
        )
    finally:
        connection.close()

    captured: dict[str, object] = {}

    def fake_run_nmap_scan(
        targets: list[str],
        *,
        nmap_bin: str,
        profile: str,
        ports: str,
        timing_template: str,
        version_detection: bool,
    ) -> NmapRunResult:
        captured["targets"] = targets
        captured["nmap_bin"] = nmap_bin
        captured["profile"] = profile
        captured["ports"] = ports
        captured["timing_template"] = timing_template
        captured["version_detection"] = version_detection
        raw_output = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" />
    <address addr="203.0.113.10" addrtype="ipv4" />
    <hostnames>
      <hostname name="api.example.net" type="user" />
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" />
        <service name="ssh" product="OpenSSH" version="9.0" />
      </port>
    </ports>
  </host>
  <host>
    <status state="up" />
    <address addr="203.0.113.11" addrtype="ipv4" />
    <hostnames>
      <hostname name="blog.example.net" type="user" />
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" />
        <service name="http" product="nginx" version="1.25.3" />
      </port>
    </ports>
  </host>
</nmaprun>
"""
        return NmapRunResult(
            command=[nmap_bin, "-oX", "-"],
            targets=targets,
            raw_output=raw_output,
            hosts=[
                NmapHostResult(
                    host="api.example.net",
                    ip="203.0.113.10",
                    status="up",
                    hostnames=["api.example.net"],
                    ports=[
                        NmapPortResult(
                            protocol="tcp",
                            port=22,
                            state="open",
                            service="ssh",
                            product="OpenSSH",
                            version="9.0",
                            extrainfo=None,
                            raw_entry={"port": 22},
                        )
                    ],
                    raw_host={"host": "api.example.net"},
                ),
                NmapHostResult(
                    host="blog.example.net",
                    ip="203.0.113.11",
                    status="up",
                    hostnames=["blog.example.net"],
                    ports=[
                        NmapPortResult(
                            protocol="tcp",
                            port=80,
                            state="open",
                            service="http",
                            product="nginx",
                            version="1.25.3",
                            extrainfo=None,
                            raw_entry={"port": 80},
                        )
                    ],
                    raw_host={"host": "blog.example.net"},
                ),
            ],
        )

    monkeypatch.setattr("scanner.runner.run_nmap_scan", fake_run_nmap_scan)

    summary = execute_port_scan_tasks(run_id)
    connection = connect(state_db_path)

    try:
        task = get_task(connection, task_id)
        run = get_run(connection, run_id)
        portscan_findings = connection.execute(
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

    assert captured["targets"] == ["api.example.net", "blog.example.net"]
    assert captured["nmap_bin"] == "nmap"
    assert captured["profile"] == "safe"
    assert captured["ports"] == "1-65535"
    assert captured["timing_template"] == "T4"
    # Updated to match actual behavior after Phase 8:
    # ScanConfig enables nmap version detection by default.
    assert captured["version_detection"] is True
    assert summary["processed_task_count"] == 1
    assert summary["completed_task_count"] == 1
    assert summary["finding_count"] == 2
    assert summary["artifact_count"] == 1
    assert task.state == "completed"
    assert run is not None
    assert run.status == "completed"
    assert [row["target"] for row in portscan_findings] == [
        "api.example.net:tcp/22",
        "blog.example.net:tcp/80",
    ]
    assert artifact_row is not None
    assert artifact_row["content_type"] == "application/xml"
    assert artifact_path.exists()
    assert "<nmaprun>" in artifact_path.read_text(encoding="utf-8")
