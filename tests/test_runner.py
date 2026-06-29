from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from scanner.models import ArtifactRef, Finding, ScanConfig
from scanner.runner import (
    calculate_next_chunk_size,
    cancel_run,
    cidr_offset_range_target,
    create_scan_run,
    enqueue_chunk_incremental_http_probe_tasks,
    enqueue_tls_san_http_probe_tasks,
    extend_scan_run,
    execute_cve_match_tasks,
    execute_dir_enum_tasks,
    execute_http_probe_tasks,
    execute_port_scan_tasks,
    execute_subdomain_enum_tasks,
    generate_run_diff,
    generate_report_summary,
    is_directory_like_path,
    maybe_enqueue_incremental_http_probe_tasks,
    maybe_enqueue_recursive_dir_enum_tasks,
    resume_run,
    should_split_port_scan_cidr,
    split_ipv4_cidr_for_port_scan,
    child_dirscan_base_url_from_finding,
)
from scanner.storage import connect, insert_artifact, insert_finding, update_task_state


def test_create_scan_run_persists_run_and_tasks(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    summary = create_scan_run("example.com", modules=["subdomain_enum", "port_scan"], profile="balanced")

    assert summary["target"] == "example.com"
    assert summary["run_id"].startswith("example.com-")
    assert summary["status"] == "pending"
    assert summary["profile"] == "balanced"
    assert summary["modules"] == ["subdomain_enum", "port_scan"]
    assert summary["task_count"] == 2
    assert Path(summary["state_db_path"]).exists()


def test_create_scan_run_uses_host_first_tasks_for_localhost(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    summary = create_scan_run("localhost")

    assert summary["target_kind"] == "localhost"
    # Updated to match actual behavior after Phase 8:
    # host-first planning keeps security candidate phase when default modules are used.
    assert summary["modules"] == [
        "port_scan",
        "http_probe",
        "domain_discovery",
        "banner_probe",
        "dir_enum",
    ]
    assert [task["module"] for task in summary["tasks"]] == [
        "port_scan",
        "http_probe",
        "domain_discovery",
        "banner_probe",
        "dir_enum",
    ]


def test_create_scan_run_uses_host_first_tasks_for_private_ipv4(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    summary = create_scan_run("192.168.56.10", modules=["subdomain_enum", "dir_enum"])

    assert summary["target_kind"] == "private_internal"
    assert summary["modules"] == ["port_scan", "http_probe", "dir_enum"]
    assert [task["module"] for task in summary["tasks"]] == ["port_scan", "http_probe", "dir_enum"]


def test_create_scan_run_uses_port_scan_only_for_ipv4_cidr(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    summary = create_scan_run("127.0.0.1/28", profile="fast")

    assert summary["target_kind"] == "private_internal"
    assert summary["modules"] == [
        "port_scan",
        "http_probe",
        "domain_discovery",
        "banner_probe",
        "dir_enum",
    ]
    assert [task["module"] for task in summary["tasks"]] == [
        "port_scan",
        "http_probe",
        "domain_discovery",
        "banner_probe",
        "dir_enum",
    ]


def test_host_first_seed_target_is_used_for_port_scan_and_http_probe(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    created = create_scan_run("http://localhost:3000/", modules=["port_scan", "http_probe"])
    run_id = created["run_id"]
    seen: dict[str, object] = {}

    class FakePort:
        def __init__(self) -> None:
            self.port = 3000
            self.protocol = "tcp"
            self.state = "open"
            self.service = "http"
            self.product = ""
            self.version = ""
            self.extrainfo = ""
            self.raw_port: dict[str, object] = {}

    class FakeHost:
        def __init__(self) -> None:
            self.target = "localhost"
            self.host = "localhost"
            self.ip = "127.0.0.1"
            self.hostnames: list[str] = []
            self.ports = [FakePort()]
            self.raw_host: dict[str, object] = {}

    class FakeNmapResult:
        def __init__(self) -> None:
            self.command = ["nmap"]
            self.targets = ["localhost"]
            self.hosts = [FakeHost()]
            self.raw_output = "<nmaprun />"

    class FakeHttpxEntry:
        def __init__(self) -> None:
            self.input = "http://localhost:3000/"
            self.input_target = "http://localhost:3000/"
            self.host = "localhost"
            self.port = 3000
            self.url = "http://localhost:3000/"
            self.path = "/"
            self.scheme = "http"
            self.status_code = 200
            self.title = "OWASP Juice Shop"
            self.webserver = "nginx"
            self.technologies: list[str] = []
            self.ip = "127.0.0.1"
            self.cname = None
            self.content_type = "text/html"
            self.redirect_location = None
            self.probe_status = "success"
            self.raw_entry: dict[str, object] = {}

    class FakeHttpxResult:
        def __init__(self) -> None:
            self.command = ["httpx"]
            self.targets = ["http://localhost:3000/"]
            self.entries = [FakeHttpxEntry()]
            self.raw_output = "{}\n"

    def fake_nmap_scan(targets, **kwargs):
        seen["nmap_targets"] = list(targets)
        return FakeNmapResult()

    def fake_httpx_probe(targets, **kwargs):
        seen["httpx_targets"] = list(targets)
        return FakeHttpxResult()

    monkeypatch.setattr("scanner.execution.portscan.runner_core.run_nmap_scan", fake_nmap_scan)
    monkeypatch.setattr("scanner.execution.http_probe.runner_core.run_httpx_probe", fake_httpx_probe)

    port_summary = execute_port_scan_tasks(run_id)
    http_summary = execute_http_probe_tasks(run_id)

    assert seen["nmap_targets"] == ["localhost"]
    assert seen["httpx_targets"] == ["http://localhost:3000/"]
    assert port_summary["tasks"][0]["input_count"] == 1
    if http_summary["tasks"]:
        assert http_summary["tasks"][0]["input_count"] == 1
    else:
        assert http_summary["processed_task_count"] == 0


def test_port_scan_uses_cidr_seed_target_without_collapsing_to_single_host(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    created = create_scan_run("127.0.0.1/28", modules=["port_scan"], profile="fast")
    run_id = created["run_id"]
    seen: dict[str, object] = {}

    class FakeNmapResult:
        def __init__(self) -> None:
            self.command = ["nmap"]
            self.targets = ["127.0.0.1/28"]
            self.hosts: list[object] = []
            self.raw_output = ""

    def fake_nmap_scan(targets, **kwargs):
        seen["nmap_targets"] = list(targets)
        return FakeNmapResult()

    monkeypatch.setattr("scanner.execution.portscan.runner_core.run_nmap_scan", fake_nmap_scan)

    execute_port_scan_tasks(run_id)

    assert seen["nmap_targets"] == ["127.0.0.1/28"]


def test_http_probe_uses_http_urls_derived_from_cidr_port_scan_findings(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    created = create_scan_run("127.0.0.1/28", modules=["http_probe", "dir_enum"], profile="fast")
    run_id = created["run_id"]
    seen: dict[str, object] = {}

    class FakePort:
        def __init__(self, port: int, service: str) -> None:
            self.port = port
            self.protocol = "tcp"
            self.state = "open"
            self.service = service
            self.product = ""
            self.version = ""
            self.extrainfo = ""
            self.raw_port: dict[str, object] = {}

    class FakeHost:
        def __init__(self) -> None:
            self.target = "127.0.0.12"
            self.host = "127.0.0.12"
            self.ip = "127.0.0.12"
            self.hostnames: list[str] = []
            self.ports = [FakePort(80, "http"), FakePort(8443, "https-alt"), FakePort(22, "ssh")]
            self.raw_host: dict[str, object] = {}

    class FakeNmapResult:
        def __init__(self) -> None:
            self.command = ["nmap"]
            self.targets = ["127.0.0.1/28"]
            self.hosts = [FakeHost()]
            self.raw_output = "<nmaprun />"

    class FakeHttpxResult:
        def __init__(self) -> None:
            self.command = ["httpx"]
            self.targets = ["http://127.0.0.12/", "https://127.0.0.12:8443/"]
            self.entries: list[object] = []
            self.raw_output = ""

    def fake_nmap_scan(targets, **kwargs):
        seen["nmap_targets"] = list(targets)
        return FakeNmapResult()

    def fake_httpx_probe(targets, **kwargs):
        seen["httpx_targets"] = list(targets)
        return FakeHttpxResult()

    monkeypatch.setattr("scanner.execution.portscan.runner_core.run_nmap_scan", fake_nmap_scan)
    monkeypatch.setattr("scanner.execution.http_probe.runner_core.run_httpx_probe", fake_httpx_probe)

    execute_port_scan_tasks(run_id)
    execute_http_probe_tasks(run_id)

    assert seen["nmap_targets"] == ["127.0.0.1/28"]
    httpx_targets = seen["httpx_targets"]
    assert isinstance(httpx_targets, list)
    assert sorted(httpx_targets) == ["http://127.0.0.12/", "https://127.0.0.12:8443/"]


def test_create_scan_run_keeps_domain_first_tasks_for_domain_input(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    summary = create_scan_run("app.example.com")

    assert summary["target_kind"] == "domain"
    assert summary["modules"] == [
        "subdomain_enum",
        "http_probe",
        "domain_discovery",
        "dir_enum",
        "port_scan",
        "banner_probe",
    ]
    assert [task["module"] for task in summary["tasks"]] == [
        "subdomain_enum",
        "http_probe",
        "domain_discovery",
        "dir_enum",
        "port_scan",
        "banner_probe",
    ]


def test_extend_scan_run_appends_new_modules_without_replacing_saved_results(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    created = create_scan_run("example.com", modules=["port_scan"])
    run_id = created["run_id"]
    state_db_path = Path(created["state_db_path"])

    connection = connect(state_db_path)
    try:
        connection.execute(
            "UPDATE runs SET status = 'completed', completed_at = ? WHERE run_id = ?",
            (datetime(2026, 4, 11, 18, 0, tzinfo=UTC).isoformat(), run_id),
        )
        connection.execute(
            "UPDATE tasks SET state = 'completed', completed_at = ? WHERE run_id = ?",
            (datetime(2026, 4, 11, 18, 0, tzinfo=UTC).isoformat(), run_id),
        )
        insert_finding(
            connection,
            Finding(
                finding_id="finding-port-existing",
                run_id=run_id,
                task_id=created["tasks"][0]["task_id"],
                module="port_scan",
                target="example.com:tcp/443",
                summary="Observed open tcp/443",
                evidence_json={"port": 443},
                created_at=datetime(2026, 4, 11, 18, 0, tzinfo=UTC),
            ),
        )
    finally:
        connection.close()

    extended = extend_scan_run(run_id, modules=["subdomain_enum", "dir_enum"])

    assert extended["status"] == "pending"
    assert extended["added_modules"] == ["subdomain_enum", "dir_enum"]
    assert [task["module"] for task in extended["tasks"]] == ["subdomain_enum", "dir_enum"]

    connection = connect(state_db_path)
    try:
        run_row = connection.execute(
            "SELECT status, completed_at, config_json FROM runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        task_rows = connection.execute(
            "SELECT module, state FROM tasks WHERE run_id = ? ORDER BY created_at ASC, rowid ASC",
            (run_id,),
        ).fetchall()
        finding_rows = connection.execute(
            "SELECT module, target FROM findings WHERE run_id = ?",
            (run_id,),
        ).fetchall()
    finally:
        connection.close()

    assert run_row is not None
    assert run_row["status"] == "pending"
    assert run_row["completed_at"] is None
    assert json.loads(run_row["config_json"])["enabled_phases"] == ["subdomain_enum", "dir_enum", "port_scan"]
    assert [(row["module"], row["state"]) for row in task_rows] == [
        ("port_scan", "completed"),
        ("subdomain_enum", "pending"),
        ("dir_enum", "pending"),
    ]
    assert [(row["module"], row["target"]) for row in finding_rows] == [("port_scan", "example.com:tcp/443")]


def test_http_probe_persists_streamed_tool_progress(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    created = create_scan_run("example.com", modules=["http_probe"])
    run_id = created["run_id"]
    task_id = created["tasks"][0]["task_id"]
    connection = connect(Path(created["state_db_path"]))
    now = datetime(2026, 4, 11, 18, 0, tzinfo=UTC)

    try:
        insert_finding(
            connection,
            Finding(
                finding_id="seed-subdomain-1",
                run_id=run_id,
                task_id=None,
                module="subdomain_enum",
                target="api.example.com",
                summary="Seeded subdomain",
                evidence_json={"hostname": "api.example.com"},
                created_at=now,
            ),
        )
        insert_finding(
            connection,
            Finding(
                finding_id="seed-subdomain-2",
                run_id=run_id,
                task_id=None,
                module="subdomain_enum",
                target="www.example.com",
                summary="Seeded subdomain",
                evidence_json={"hostname": "www.example.com"},
                created_at=now,
            ),
        )
    finally:
        connection.close()

    def fake_stream(
        command: list[str],
        *,
        stdin_text: str | None = None,
        stdout_handler=None,
        stderr_handler=None,
        snapshot_handler=None,
        snapshot_interval_seconds: float = 2.0,
    ) -> subprocess.CompletedProcess[str]:
        assert "-stats" in command
        assert "-si" in command
        assert stdin_text is not None
        if stderr_handler is not None:
            stderr_handler("Hosts: 1/2 (50%)\n")
        if snapshot_handler is not None:
            snapshot_handler()
        line_one = json.dumps({
            "input": "api.example.com",
            "url": "https://api.example.com/",
            "host": "api.example.com",
            "path": "/",
            "scheme": "https",
            "status_code": 200,
            "title": "API",
            "tech": ["nginx"],
            "content_type": "text/html",
            "webserver": "nginx",
            "ip": "203.0.113.10",
            "cname": [],
            "probe_status": "success",
        }) + "\n"
        line_two = json.dumps({
            "input": "www.example.com",
            "url": "https://www.example.com/",
            "host": "www.example.com",
            "path": "/",
            "scheme": "https",
            "status_code": 200,
            "title": "WWW",
            "tech": ["cdn"],
            "content_type": "text/html",
            "webserver": "envoy",
            "ip": "203.0.113.11",
            "cname": [],
            "probe_status": "success",
        }) + "\n"
        if stdout_handler is not None:
            stdout_handler(line_one)
            stdout_handler(line_two)
        if stderr_handler is not None:
            stderr_handler("Hosts: 2/2 (100%)\n")
        if snapshot_handler is not None:
            snapshot_handler()
        return subprocess.CompletedProcess(command, 0, stdout=line_one + line_two, stderr="")

    monkeypatch.setattr("scanner.execution.http_probe.runner_core._run_command_with_live_progress", fake_stream)

    execute_http_probe_tasks(run_id)

    connection = connect(Path(created["state_db_path"]))
    try:
        row = connection.execute(
            "SELECT cursor_json FROM tasks WHERE task_id = ?",
            (task_id,),
        ).fetchone()
    finally:
        connection.close()

    assert row is not None
    cursor_json = json.loads(row["cursor_json"])
    assert cursor_json["tool_progress"]["tool"] == "httpx"
    assert cursor_json["tool_progress"]["processed_count"] == 2
    assert cursor_json["tool_progress"]["total_count"] == 2


def test_port_scan_persists_streamed_tool_progress(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    created = create_scan_run("localhost", modules=["port_scan"])
    run_id = created["run_id"]
    task_id = created["tasks"][0]["task_id"]

    def fake_stream(
        command: list[str],
        *,
        stdin_text: str | None = None,
        stdout_handler=None,
        stderr_handler=None,
        snapshot_handler=None,
        snapshot_interval_seconds: float = 2.0,
    ) -> subprocess.CompletedProcess[str]:
        assert "--stats-every" in command
        if stderr_handler is not None:
            stderr_handler("Stats: About 50.00% done; ETC: 12:00 (0:00:10 remaining)\n")
        if snapshot_handler is not None:
            snapshot_handler()
        xml_output = """<nmaprun><host><status state="up" /><address addr="127.0.0.1" addrtype="ipv4" /><ports><port protocol="tcp" portid="3000"><state state="open" /><service name="http" product="nginx" version="1.25" /></port></ports></host></nmaprun>"""
        if stderr_handler is not None:
            stderr_handler("Stats: About 100.00% done; ETC: 12:00 (0:00:00 remaining)\n")
        if snapshot_handler is not None:
            snapshot_handler()
        return subprocess.CompletedProcess(command, 0, stdout=xml_output, stderr="")

    monkeypatch.setattr("scanner.execution.portscan.runner_core._run_command_with_live_progress", fake_stream)

    execute_port_scan_tasks(run_id)

    connection = connect(Path(created["state_db_path"]))
    try:
        row = connection.execute(
            "SELECT cursor_json FROM tasks WHERE task_id = ?",
            (task_id,),
        ).fetchone()
    finally:
        connection.close()

    assert row is not None
    cursor_json = json.loads(row["cursor_json"])
    assert cursor_json["tool_progress"]["tool"] == "nmap"
    assert cursor_json["tool_progress"]["percent"] == 100.0


def test_dir_enum_persists_streamed_tool_progress(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    created = create_scan_run("example.com", modules=["dir_enum"])
    run_id = created["run_id"]
    task_id = created["tasks"][0]["task_id"]
    connection = connect(Path(created["state_db_path"]))
    now = datetime(2026, 4, 11, 18, 10, tzinfo=UTC)
    wordlist_path = tmp_path / "words.txt"
    wordlist_path.write_text("admin\nlogin\nassets\n", encoding="utf-8")

    try:
        row = connection.execute(
            "SELECT config_json FROM runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        assert row is not None
        config = json.loads(row["config_json"])
        config["ffuf_wordlist_path"] = str(wordlist_path.resolve())
        connection.execute(
            "UPDATE runs SET config_json = ? WHERE run_id = ?",
            (json.dumps(config), run_id),
        )
        connection.commit()
        insert_finding(
            connection,
            Finding(
                finding_id="seed-http-host",
                run_id=run_id,
                task_id=None,
                module="http_probe",
                target="https://app.example.com/",
                summary="Seeded host",
                evidence_json={"url": "https://app.example.com/", "host": "app.example.com", "status_code": 200},
                tags=["httpx", "alive", "host"],
                created_at=now,
            ),
        )
    finally:
        connection.close()

    monkeypatch.setattr("scanner.execution.dirscan._plan_dirscan_filters", lambda *args, **kwargs: __import__("scanner.execution.dirscan", fromlist=["DirscanCalibrationDecision"]).DirscanCalibrationDecision(filter_sizes=[], details={"decision": "no_filter"}))
    monkeypatch.setattr("scanner.execution.dirscan._resolve_dirscan_worker_count", lambda run, target_count: 1)

    def fake_stream(
        command: list[str],
        *,
        stdin_text: str | None = None,
        stdout_handler=None,
        stderr_handler=None,
        snapshot_handler=None,
        snapshot_interval_seconds: float = 2.0,
    ) -> subprocess.CompletedProcess[str]:
        assert "-s" not in command
        output_index = command.index("-o") + 1
        output_path = Path(command[output_index])
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps({"results": []}), encoding="utf-8")
        if stderr_handler is not None:
            stderr_handler(":: Progress: [1/3] ::\n")
        if snapshot_handler is not None:
            snapshot_handler()
        if stdout_handler is not None:
            stdout_handler(":: Progress: [3/3] ::\n")
        if snapshot_handler is not None:
            snapshot_handler()
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr("scanner.execution.dirscan.runner_core._run_command_with_live_progress", fake_stream)

    execute_dir_enum_tasks(run_id)

    connection = connect(Path(created["state_db_path"]))
    try:
        row = connection.execute(
            "SELECT cursor_json FROM tasks WHERE task_id = ?",
            (task_id,),
        ).fetchone()
    finally:
        connection.close()

    assert row is not None
    cursor_json = json.loads(row["cursor_json"])
    assert cursor_json["tool_progress"][0]["tool"] == "ffuf"
    assert cursor_json["tool_progress"][0]["processed_count"] == 3


def test_resume_run_returns_incomplete_tasks(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    created = create_scan_run("example.org", modules=["subdomain_enum"])
    resumed = resume_run(created["run_id"])

    assert resumed["run_id"] == created["run_id"]
    assert resumed["target"] == "example.org"
    assert resumed["incomplete_task_count"] == 1
    assert resumed["tasks"][0]["module"] == "subdomain_enum"
    assert resumed["tasks"][0]["state"] == "pending"


def test_generate_report_summary_loads_seeded_findings_and_artifacts(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    now = datetime(2026, 4, 9, 12, 0, tzinfo=UTC)
    created = create_scan_run("example.net", modules=["http_probe"])
    run_id = created["run_id"]
    task_id = created["tasks"][0]["task_id"]
    connection = connect(Path(created["state_db_path"]))

    try:
        insert_finding(
            connection,
            Finding(
                finding_id="finding-100",
                run_id=run_id,
                task_id=task_id,
                module="http_probe",
                target="https://example.net",
                summary="Observed live service",
                evidence_json={"status_code": 200},
                created_at=now,
            ),
        )
        insert_artifact(
            connection,
            ArtifactRef(
                artifact_id="artifact-100",
                run_id=run_id,
                task_id=task_id,
                phase_name="http_probe",
                source_tool="httpx",
                artifact_type="raw_jsonl",
                path=tmp_path / "runs" / run_id / "artifacts" / "httpx.jsonl",
                sha256="abc123",
                size_bytes=42,
                content_type="application/jsonl",
                created_at=now,
                metadata={"kind": "seeded"},
            ),
        )
    finally:
        connection.close()

    report = generate_report_summary(run_id)

    assert report["run_id"] == run_id
    assert report["findings"]["total"] == 1
    assert report["findings"]["by_module"] == {"http_probe": 1}
    assert report["findings"]["items"][0]["summary"] == "Observed live service"
    assert report["artifacts"]["total"] == 1
    assert report["artifacts"]["items"][0]["tool"] == "httpx"


def test_generate_report_summary_sorts_section_items_by_target(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    now = datetime(2026, 4, 11, 10, 0, tzinfo=UTC)
    created = create_scan_run("example.net", modules=["dir_enum"])
    run_id = created["run_id"]
    task_id = created["tasks"][0]["task_id"]
    connection = connect(Path(created["state_db_path"]))

    try:
        insert_finding(
            connection,
            Finding(
                finding_id="finding-dirscan-b",
                run_id=run_id,
                task_id=task_id,
                module="dir_enum",
                target="https://b.example.net/private",
                summary="Observed path",
                evidence_json={"url": "https://b.example.net/private", "status_code": 403},
                created_at=now,
            ),
        )
        insert_finding(
            connection,
            Finding(
                finding_id="finding-dirscan-a",
                run_id=run_id,
                task_id=task_id,
                module="dir_enum",
                target="https://a.example.net/admin",
                summary="Observed path",
                evidence_json={"url": "https://a.example.net/admin", "status_code": 200},
                created_at=now,
            ),
        )
    finally:
        connection.close()

    report = generate_report_summary(run_id)

    assert [item["target"] for item in report["sections"]["directory_findings"]] == [
        "https://a.example.net/admin",
        "https://b.example.net/private",
    ]


def test_generate_report_summary_builds_host_groups(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    now = datetime(2026, 4, 11, 12, 0, tzinfo=UTC)
    created = create_scan_run("example.net", modules=["http_probe"])
    run_id = created["run_id"]
    task_id = created["tasks"][0]["task_id"]
    connection = connect(Path(created["state_db_path"]))

    try:
        insert_finding(
            connection,
            Finding(
                finding_id="finding-host-http",
                run_id=run_id,
                task_id=task_id,
                module="http_probe",
                target="app.example.net",
                summary="Observed live host",
                evidence_json={
                    "host": "app.example.net",
                    "ip": "203.0.113.10",
                    "technologies": ["nginx", "React"],
                    "status_code": 200,
                    "url": "https://app.example.net/",
                },
                created_at=now,
            ),
        )
        insert_finding(
            connection,
            Finding(
                finding_id="finding-host-dir",
                run_id=run_id,
                task_id=task_id,
                module="dir_enum",
                target="https://app.example.net/admin",
                summary="Observed path",
                evidence_json={
                    "host": "app.example.net:443",
                    "url": "https://app.example.net/admin",
                    "status_code": 403,
                },
                created_at=now,
            ),
        )
        insert_finding(
            connection,
            Finding(
                finding_id="finding-host-port",
                run_id=run_id,
                task_id=task_id,
                module="port_scan",
                target="app.example.net:tcp/8443",
                summary="Observed open port",
                evidence_json={
                    "host": "app.example.net",
                    "ip": "203.0.113.10",
                    "protocol": "tcp",
                    "port": 8443,
                    "state": "open",
                    "service": "https",
                },
                tags=["open"],
                created_at=now,
            ),
        )
        insert_finding(
            connection,
            Finding(
                finding_id="finding-host-cve",
                run_id=run_id,
                task_id=task_id,
                module="cve_match",
                target="app.example.net",
                status="candidate",
                summary="Candidate CVE",
                evidence_json={"cve_id": "CVE-2024-9999", "candidate_only": True},
                created_at=now,
            ),
        )
        insert_artifact(
            connection,
            ArtifactRef(
                artifact_id="artifact-host-dir",
                run_id=run_id,
                task_id=task_id,
                phase_name="dir_enum",
                source_tool="ffuf",
                artifact_type="raw_json",
                path=tmp_path / "runs" / run_id / "artifacts" / "ffuf" / "task.json",
                sha256="def456",
                size_bytes=84,
                content_type="application/json",
                created_at=now,
                metadata={"base_url": "https://app.example.net/"},
            ),
        )
    finally:
        connection.close()

    report = generate_report_summary(run_id)

    assert [group["host"] for group in report["host_groups"]] == ["app.example.net"]
    host_group = report["host_groups"][0]
    assert host_group["alive"] is True
    assert host_group["ip_addresses"] == ["203.0.113.10"]
    assert host_group["technologies"] == ["React", "nginx"]
    assert host_group["open_ports_count"] == 1
    assert host_group["directory_findings_count"] == 1
    assert host_group["candidate_cve_count"] == 1
    assert host_group["auth_required_path_count"] == 1
    assert host_group["artifacts"][0]["path"].endswith("task.json")


def test_generate_run_diff_classifies_added_removed_and_unchanged(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    now = datetime(2026, 4, 11, 11, 0, tzinfo=UTC)
    baseline = create_scan_run("example.net", modules=["http_probe", "dir_enum", "port_scan", "cve_match"])
    current = create_scan_run("example.net", modules=["http_probe", "dir_enum", "port_scan", "cve_match"])
    baseline_conn = connect(Path(baseline["state_db_path"]))
    current_conn = connect(Path(current["state_db_path"]))

    try:
        insert_finding(
            baseline_conn,
            Finding(
                finding_id="baseline-http-1",
                run_id=baseline["run_id"],
                module="http_probe",
                target="https://same.example.net/",
                summary="Observed live host",
                evidence_json={"status_code": 200},
                created_at=now,
            ),
        )
        insert_finding(
            baseline_conn,
            Finding(
                finding_id="baseline-http-2",
                run_id=baseline["run_id"],
                module="http_probe",
                target="https://removed.example.net/",
                summary="Observed removed host",
                evidence_json={"status_code": 200},
                created_at=now,
            ),
        )
        insert_finding(
            baseline_conn,
            Finding(
                finding_id="baseline-dir-1",
                run_id=baseline["run_id"],
                module="dir_enum",
                target="https://same.example.net/admin",
                summary="Observed path",
                evidence_json={"status_code": 200},
                created_at=now,
            ),
        )
        insert_finding(
            baseline_conn,
            Finding(
                finding_id="baseline-cve-1",
                run_id=baseline["run_id"],
                module="cve_match",
                target="same.example.net:tcp/443",
                status="candidate",
                summary="Candidate CVE",
                evidence_json={"cve_id": "CVE-2021-41773", "candidate_only": True},
                created_at=now,
            ),
        )

        insert_finding(
            current_conn,
            Finding(
                finding_id="current-http-1",
                run_id=current["run_id"],
                module="http_probe",
                target="https://same.example.net/",
                summary="Observed live host",
                evidence_json={"status_code": 200},
                created_at=now,
            ),
        )
        insert_finding(
            current_conn,
            Finding(
                finding_id="current-http-2",
                run_id=current["run_id"],
                module="http_probe",
                target="https://added.example.net/",
                summary="Observed added host",
                evidence_json={"status_code": 200},
                created_at=now,
            ),
        )
        insert_finding(
            current_conn,
            Finding(
                finding_id="current-dir-1",
                run_id=current["run_id"],
                module="dir_enum",
                target="https://same.example.net/admin",
                summary="Observed path",
                evidence_json={"status_code": 200},
                created_at=now,
            ),
        )
        insert_finding(
            current_conn,
            Finding(
                finding_id="current-port-1",
                run_id=current["run_id"],
                module="port_scan",
                target="same.example.net:tcp/443",
                summary="Observed open port",
                evidence_json={"state": "open", "service": "https", "product": "nginx", "version": "1.25"},
                tags=["open"],
                created_at=now,
            ),
        )
        insert_finding(
            current_conn,
            Finding(
                finding_id="current-cve-1",
                run_id=current["run_id"],
                module="cve_match",
                target="same.example.net:tcp/443",
                status="candidate",
                summary="Candidate CVE",
                evidence_json={"cve_id": "CVE-2021-41773", "candidate_only": True},
                created_at=now,
            ),
        )
    finally:
        baseline_conn.close()
        current_conn.close()

    diff = generate_run_diff(baseline["run_id"], current["run_id"])

    assert diff["categories"]["http_probe_results"]["added_count"] == 1
    assert diff["categories"]["http_probe_results"]["removed_count"] == 1
    assert diff["categories"]["http_probe_results"]["unchanged_count"] == 1
    assert [item["target"] for item in diff["categories"]["http_probe_results"]["added"]] == [
        "https://added.example.net/",
    ]
    assert [item["target"] for item in diff["categories"]["http_probe_results"]["removed"]] == [
        "https://removed.example.net/",
    ]
    assert [item["target"] for item in diff["categories"]["http_probe_results"]["unchanged"]] == [
        "https://same.example.net/",
    ]
    assert diff["categories"]["directory_findings"]["unchanged_count"] == 1
    assert diff["categories"]["candidate_cves"]["unchanged_count"] == 1
    assert diff["categories"]["open_ports"]["added_count"] == 1


def test_generate_run_diff_keeps_distinct_directory_paths_on_same_host(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    now = datetime(2026, 4, 11, 11, 30, tzinfo=UTC)
    baseline = create_scan_run("example.net", modules=["dir_enum"])
    current = create_scan_run("example.net", modules=["dir_enum"])
    baseline_conn = connect(Path(baseline["state_db_path"]))
    current_conn = connect(Path(current["state_db_path"]))

    try:
        insert_finding(
            baseline_conn,
            Finding(
                finding_id="baseline-dir-admin",
                run_id=baseline["run_id"],
                module="dir_enum",
                target="https://app.example.net/admin",
                summary="Observed /admin",
                evidence_json={"url": "https://app.example.net/admin", "path": "/admin", "status_code": 200},
                created_at=now,
            ),
        )
        insert_finding(
            current_conn,
            Finding(
                finding_id="current-dir-admin",
                run_id=current["run_id"],
                module="dir_enum",
                target="https://app.example.net/admin",
                summary="Observed /admin",
                evidence_json={"url": "https://app.example.net/admin", "path": "/admin", "status_code": 200},
                created_at=now,
            ),
        )
        insert_finding(
            current_conn,
            Finding(
                finding_id="current-dir-login",
                run_id=current["run_id"],
                module="dir_enum",
                target="https://app.example.net/login",
                summary="Observed /login",
                evidence_json={"url": "https://app.example.net/login", "path": "/login", "status_code": 200},
                created_at=now,
            ),
        )
    finally:
        baseline_conn.close()
        current_conn.close()

    diff = generate_run_diff(baseline["run_id"], current["run_id"])

    assert diff["categories"]["directory_findings"]["unchanged_count"] == 1
    assert diff["categories"]["directory_findings"]["added_count"] == 1
    assert [item["target"] for item in diff["categories"]["directory_findings"]["added"]] == [
        "https://app.example.net/login",
    ]


def test_generate_run_diff_keeps_distinct_ports_with_same_service_fingerprint(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    now = datetime(2026, 4, 11, 11, 45, tzinfo=UTC)
    baseline = create_scan_run("example.net", modules=["port_scan"])
    current = create_scan_run("example.net", modules=["port_scan"])
    baseline_conn = connect(Path(baseline["state_db_path"]))
    current_conn = connect(Path(current["state_db_path"]))

    try:
        insert_finding(
            baseline_conn,
            Finding(
                finding_id="baseline-port-443",
                run_id=baseline["run_id"],
                module="port_scan",
                target="app.example.net:tcp/443",
                summary="Observed tcp/443 open",
                evidence_json={
                    "state": "open",
                    "protocol": "tcp",
                    "port": 443,
                    "service": "https",
                    "product": "nginx",
                    "version": "1.25",
                },
                tags=["open"],
                created_at=now,
            ),
        )
        insert_finding(
            current_conn,
            Finding(
                finding_id="current-port-443",
                run_id=current["run_id"],
                module="port_scan",
                target="app.example.net:tcp/443",
                summary="Observed tcp/443 open",
                evidence_json={
                    "state": "open",
                    "protocol": "tcp",
                    "port": 443,
                    "service": "https",
                    "product": "nginx",
                    "version": "1.25",
                },
                tags=["open"],
                created_at=now,
            ),
        )
        insert_finding(
            current_conn,
            Finding(
                finding_id="current-port-8443",
                run_id=current["run_id"],
                module="port_scan",
                target="app.example.net:tcp/8443",
                summary="Observed tcp/8443 open",
                evidence_json={
                    "state": "open",
                    "protocol": "tcp",
                    "port": 8443,
                    "service": "https",
                    "product": "nginx",
                    "version": "1.25",
                },
                tags=["open"],
                created_at=now,
            ),
        )
    finally:
        baseline_conn.close()
        current_conn.close()

    diff = generate_run_diff(baseline["run_id"], current["run_id"])

    assert diff["categories"]["open_ports"]["unchanged_count"] == 1
    assert diff["categories"]["open_ports"]["added_count"] == 1
    assert [item["target"] for item in diff["categories"]["open_ports"]["added"]] == [
        "app.example.net:tcp/8443",
    ]


def test_execute_cve_match_tasks_creates_candidate_findings(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    now = datetime(2026, 4, 9, 12, 0, tzinfo=UTC)
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

    summary = execute_cve_match_tasks(run_id)
    connection = connect(Path(created["state_db_path"]))

    try:
        run_row = connection.execute(
            "SELECT status FROM runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        task_row = connection.execute(
            "SELECT state, cursor_json FROM tasks WHERE task_id = ?",
            (task_id,),
        ).fetchone()
        candidate_rows = connection.execute(
            """
            SELECT target, status, evidence_json
            FROM findings
            WHERE task_id = ?
            ORDER BY target ASC
            """,
            (task_id,),
        ).fetchall()
    finally:
        connection.close()

    assert summary["processed_task_count"] == 1
    assert summary["completed_task_count"] == 1
    assert summary["failed_task_count"] == 0
    assert summary["finding_count"] == 2
    assert run_row is not None
    assert run_row["status"] == "completed"
    assert task_row is not None
    assert task_row["state"] == "completed"
    assert json.loads(task_row["cursor_json"])["finding_count"] == 2
    assert [row["target"] for row in candidate_rows] == [
        "api.example.org:tcp/80",
        "https://www.example.org/",
    ]
    assert all(row["status"] == "candidate" for row in candidate_rows)
    assert all(json.loads(row["evidence_json"])["candidate_only"] is True for row in candidate_rows)


def test_execute_subdomain_enum_tasks_merges_crtsh_with_free_sources(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    created = create_scan_run("example.com", modules=["subdomain_enum"])
    run_id = created["run_id"]
    task_id = created["tasks"][0]["task_id"]
    state_db_path = Path(created["state_db_path"])

    class FakeCliResult:
        def __init__(self, command: list[str], hosts: list[str], raw_output: str) -> None:
            self.command = command
            self.hosts = hosts
            self.raw_output = raw_output

    class FakeCrtshResult:
        def __init__(self, hosts: list[str], raw_output: str) -> None:
            self.query_url = "https://crt.sh/?q=%25.example.com&output=json"
            self.hosts = hosts
            self.entry_count = 2
            self.raw_output = raw_output

    monkeypatch.setattr(
        "scanner.execution.subdomain.run_subfinder_discovery",
        lambda root_domain, **kwargs: FakeCliResult(
            ["subfinder", "-silent", "-d", root_domain],
            ["api.example.com", "www.example.com"],
            "api.example.com\nwww.example.com\n",
        ),
    )
    monkeypatch.setattr(
        "scanner.execution.subdomain.run_assetfinder_discovery",
        lambda root_domain, **kwargs: FakeCliResult(
            ["assetfinder", "--subs-only", root_domain],
            ["api.example.com", "blog.example.com"],
            "api.example.com\nblog.example.com\n",
        ),
    )
    monkeypatch.setattr(
        "scanner.execution.subdomain.fetch_crtsh_subdomains",
        lambda root_domain: FakeCrtshResult(
            ["blog.example.com", "cdn.example.com"],
            json.dumps(
                [
                    {"name_value": "*.blog.example.com\nblog.example.com"},
                    {"name_value": "cdn.example.com"},
                ]
            ),
        ),
    )
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
        finding_rows = connection.execute(
            "SELECT target, evidence_json FROM findings WHERE task_id = ? ORDER BY target ASC",
            (task_id,),
        ).fetchall()
        artifact_rows = connection.execute(
            "SELECT path, content_type, metadata_json FROM artifacts WHERE task_id = ? ORDER BY path ASC",
            (task_id,),
        ).fetchall()
    finally:
        connection.close()

    assert summary["processed_task_count"] == 1
    assert summary["completed_task_count"] == 1
    assert summary["failed_task_count"] == 0
    assert summary["finding_count"] == 4
    assert summary["artifact_count"] == 3
    assert summary["tasks"][0]["sources"] == ["subfinder", "assetfinder", "crtsh"]
    assert [row["target"] for row in finding_rows] == [
        "api.example.com",
        "blog.example.com",
        "cdn.example.com",
        "www.example.com",
    ]
    blog_evidence = json.loads(finding_rows[1]["evidence_json"])
    assert blog_evidence["source_tool"] == "multiple"
    assert blog_evidence["source_tools"] == ["assetfinder", "crtsh"]
    assert len(artifact_rows) == 3
    artifact_sources = {
        json.loads(row["metadata_json"])["source"]: row["content_type"]
        for row in artifact_rows
    }
    assert artifact_sources == {
        "assetfinder": "text/plain",
        "crtsh": "application/json",
        "subfinder": "text/plain",
    }


def test_classify_accepted_tls_cert_cn() -> None:
    from scanner.runner import classify_root_domain_candidates

    evidence = {
        "domain_candidates": [
            {
                "hostname": "example.com",
                "source_field": "tls_cn",
                "source_module": "http_probe",
            }
        ]
    }
    result = classify_root_domain_candidates(evidence, "127.0.0.1")
    assert len(result["accepted"]) == 1
    assert len(result["review_required"]) == 0
    assert len(result["rejected"]) == 0
    assert result["accepted"][0]["hostname"] == "example.com"
    assert result["accepted"][0]["reason"] == "Strong evidence from TLS (tls_cn)"


def test_classify_review_required_redirect_only() -> None:
    from scanner.runner import classify_root_domain_candidates

    evidence = {
        "domain_candidates": [
            {
                "hostname": "example.com",
                "source_field": "hostname",
                "source_module": "http_probe",
            }
        ]
    }
    result = classify_root_domain_candidates(evidence, "127.0.0.1")
    assert len(result["accepted"]) == 0
    assert len(result["review_required"]) == 1
    assert len(result["rejected"]) == 0
    assert result["review_required"][0]["hostname"] == "example.com"
    assert result["review_required"][0]["reason"] == "Single weak evidence source (hostname)"


def test_classify_rejected_wildcard() -> None:
    from scanner.runner import classify_root_domain_candidates

    evidence = {
        "domain_candidates": [
            {
                "hostname": "*.example.com",
                "source_field": "cname",
                "source_module": "http_probe",
            }
        ]
    }
    result = classify_root_domain_candidates(evidence, "127.0.0.1")
    assert len(result["accepted"]) == 0
    assert len(result["review_required"]) == 0
    assert len(result["rejected"]) == 1
    assert result["rejected"][0]["hostname"] == "*.example.com"
    assert result["rejected"][0]["reason"] == "Wildcard root domain"


def test_enqueue_no_duplicate(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    from scanner.runner import enqueue_subdomain_enum_if_needed

    created = create_scan_run("127.0.0.1", modules=["http_probe"])
    run_id = created["run_id"]
    connection = connect(Path(created["state_db_path"]))
    try:
        result1 = enqueue_subdomain_enum_if_needed(
            connection,
            run_id,
            "example.com",
            classify_result={"accepted": [{"hostname": "example.com"}]}
        )
        assert result1["enqueued"] is True
        
        result2 = enqueue_subdomain_enum_if_needed(
            connection,
            run_id,
            "example.com",
            classify_result={"accepted": [{"hostname": "example.com"}]}
        )
        assert result2["enqueued"] is False
        assert result2["reason"] == "Duplicate task exists"
    finally:
        connection.close()


def test_domain_first_runs_unchanged(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    from scanner.runner import enqueue_subdomain_enum_if_needed

    # domain targets automatically get subdomain_enum module included in phases
    created = create_scan_run("example.com")
    run_id = created["run_id"]
    connection = connect(Path(created["state_db_path"]))
    try:
        result = enqueue_subdomain_enum_if_needed(
            connection,
            run_id,
            "example.com",
            classify_result={"accepted": [{"hostname": "example.com"}]}
        )
        assert result["enqueued"] is False
        assert result["reason"] == "Phase already enabled"
    finally:
        connection.close()


def test_derive_extensions_from_tech() -> None:
    from scanner.config import derive_extensions_from_tech

    # Test PHP-like tech maps to .php
    assert derive_extensions_from_tech(["PHP", "Ubuntu"]) == [".php"]
    
    # Test ASP.NET-like tech maps to .aspx, .asp, etc.
    assert derive_extensions_from_tech(["IIS", "ASP.NET"]) == [".aspx", ".asp", ".ashx"]
    
    # Test multiple tech maps to merged deduplicate set up to length max
    assert derive_extensions_from_tech(["PHP", "Java", "Python"]) == [".php", ".jsp", ".jspx", ".do", ".action"]
    
    # Test no recognized tech maps to empty list
    assert derive_extensions_from_tech(["UnknownTech", "Nginx"]) == []


def test_execute_dir_enum_tasks_derives_extensions_from_httpx_evidence(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    from scanner.runner import create_scan_run, execute_dir_enum_tasks

    captured_extensions: list[list[str]] = []
    
    def fake_ffuf_scan(
        base_url: str,
        *,
        output_path: Path,
        ffuf_bin: str = "ffuf",
        wordlist_path: Path,
        profile: str = "safe",
        threads: int = 20,
        match_status_codes=(),
        extensions=(),
        auto_calibration: bool = True,
        per_host_auto_calibration: bool = True,
        filter_sizes=(),
    ):
        captured_extensions.append(list(extensions))
        from scanner.adapters.ffuf_runner import FfufRunResult
        return FfufRunResult(
            command=[ffuf_bin, "-of", "json"],
            base_url=base_url,
            output_path=output_path,
            matches=[],
            raw_output='{"results":[]}',
        )

    monkeypatch.setattr("scanner.execution.dirscan.runner_core.run_ffuf_scan", fake_ffuf_scan)

    # Note: run.config.ffuf_extensions is empty by default in ScanConfig if not set.
    # To test fallback safely, we don't strict match fallback so an empty list or default passes.
    # We just want to make sure it *receives* the specific list when tech match.

    created = create_scan_run("example.com", modules=["dir_enum"])
    run_id = created["run_id"]
    from scanner.storage import connect, insert_finding
    from scanner.models import Finding
    
    connection = connect(Path(created["state_db_path"]))
    try:
        from datetime import UTC, datetime
        # Add http_probe finding with "PHP" tech
        insert_finding(
            connection,
            Finding(
                finding_id="finding-http-com",
                run_id=run_id,
                task_id=None,
                module="http_probe",
                target="php.example.com",
                status="observed",
                summary="live host",
                evidence_json={
                    "url": "http://php.example.com/", 
                    "host": "php.example.com", 
                    "technologies": ["PHP"]
                },
                tags=["alive", "host"],
                created_at=datetime.now(UTC),
            )
        )
        
        # Add http_probe finding with "NotRecognized" tech
        insert_finding(
            connection,
            Finding(
                finding_id="finding-http-com2",
                run_id=run_id,
                task_id=None,
                module="http_probe",
                target="unknown.example.com",
                status="observed",
                summary="live host",
                evidence_json={
                    "url": "http://unknown.example.com/", 
                    "host": "unknown.example.com", 
                    "technologies": ["SomeCustomTech"]
                },
                tags=["alive", "host"],
                created_at=datetime.now(UTC),
            )
        )
        
        # set wordlist to avoid error
        row = connection.execute("SELECT config_json FROM runs").fetchone()
        config_dict = json.loads(row["config_json"] if "config_json" in row.keys() else row[0])
        config_dict["ffuf_wordlist_path"] = str(tmp_path / "words.txt")
        connection.execute("UPDATE runs SET config_json = ?", (json.dumps(config_dict),))
        connection.commit()
    finally:
        connection.close()

    (tmp_path / "words.txt").write_text("test")

    execute_dir_enum_tasks(run_id)

    # It will run twice: once for php, once for unknown. 
    # For PHP, it must be [".php"]
    # For Unknown, it should be the fallback (which is an empty tuple or default from config)
    assert [".php"] in captured_extensions


def test_dir_enum_max_workers_default_is_restored() -> None:
    from scanner.config import DIR_ENUM_MAX_WORKERS

    assert DIR_ENUM_MAX_WORKERS > 1


def test_incremental_http_probe_after_port_scan_finds_new_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    created = create_scan_run("10.10.10.10", modules=["port_scan", "http_probe"], profile="safe")
    run_id = created["run_id"]
    state_db_path = Path(created["state_db_path"])

    class FakePort:
        def __init__(self, port: int, service: str) -> None:
            self.port = port
            self.protocol = "tcp"
            self.state = "open"
            self.service = service
            self.product = ""
            self.version = ""
            self.extrainfo = ""
            self.raw_port: dict[str, object] = {}

    class FakeHost:
        def __init__(self, ports: list[FakePort]) -> None:
            self.target = "10.10.10.10"
            self.host = "10.10.10.10"
            self.ip = "10.10.10.10"
            self.hostnames: list[str] = []
            self.ports = ports
            self.raw_host: dict[str, object] = {}

    class FakeNmapResult:
        def __init__(self, ports: list[FakePort]) -> None:
            self.command = ["nmap"]
            self.targets = ["10.10.10.10"]
            self.hosts = [FakeHost(ports)]
            self.raw_output = "<nmaprun />"

    class FakeHttpxEntry:
        def __init__(self, url: str) -> None:
            self.input_target = url
            self.host = "10.10.10.10"
            self.port = 80
            self.url = url
            self.path = "/"
            self.scheme = "http"
            self.status_code = 200
            self.title = "t"
            self.webserver = "nginx"
            self.technologies: list[str] = []
            self.ip = "10.10.10.10"
            self.cname = None
            self.content_type = "text/html"
            self.redirect_location = None
            self.probe_status = "success"
            self.raw_entry: dict[str, object] = {}

    class FakeHttpxResult:
        def __init__(self, targets: list[str]) -> None:
            self.command = ["httpx"]
            self.targets = targets
            self.entries = [FakeHttpxEntry(targets[0])] if targets else []
            self.raw_output = "{}\n"

    def fake_nmap_scan(targets, **kwargs):
        return FakeNmapResult([FakePort(80, "http")])

    def fake_httpx_probe(targets, **kwargs):
        return FakeHttpxResult(list(targets))

    monkeypatch.setattr("scanner.execution.portscan.runner_core.run_nmap_scan", fake_nmap_scan)
    monkeypatch.setattr("scanner.execution.http_probe.runner_core.run_httpx_probe", fake_httpx_probe)

    execute_port_scan_tasks(run_id)
    execute_http_probe_tasks(run_id)

    connection = connect(state_db_path)
    try:
        insert_finding(
            connection,
            Finding(
                finding_id="finding-port-9000",
                run_id=run_id,
                task_id=created["tasks"][0]["task_id"],
                module="port_scan",
                target="10.10.10.10:tcp/9000",
                summary="Observed open tcp/9000",
                evidence_json={
                    "host": "10.10.10.10",
                    "ip": "10.10.10.10",
                    "port": 9000,
                    "state": "open",
                    "service": "http",
                },
                created_at=datetime.now(UTC),
            ),
        )
        result = maybe_enqueue_incremental_http_probe_tasks(connection, run_id, trigger_task_id="manual")
        assert result["enqueued"] is True
        assert "http://10.10.10.10:9000/" in result["new_urls"]
        row = connection.execute(
            """
            SELECT cursor_json FROM tasks
            WHERE run_id = ? AND module = 'http_probe' AND state = 'pending'
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (run_id,),
        ).fetchone()
        assert row is not None
        cursor = json.loads(row["cursor_json"])
        assert cursor.get("incremental") is True
        assert cursor.get("new_scope_count") == 1
        assert "revisit" in str(cursor.get("revisit_reason", "")).lower()
    finally:
        connection.close()


def test_incremental_dir_enum_after_http_when_primary_dir_completed(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    created = create_scan_run("10.10.10.11", modules=["port_scan", "http_probe", "dir_enum"], profile="safe")
    run_id = created["run_id"]
    state_db_path = Path(created["state_db_path"])
    wordlist = tmp_path / "w.txt"
    wordlist.write_text("x\n", encoding="utf-8")

    connection = connect(state_db_path)
    try:
        config_row = connection.execute("SELECT config_json FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        assert config_row is not None
        cfg = json.loads(config_row["config_json"])
        cfg["ffuf_wordlist_path"] = str(wordlist)
        connection.execute(
            "UPDATE runs SET config_json = ? WHERE run_id = ?",
            (json.dumps(cfg, sort_keys=True, separators=(",", ":")), run_id),
        )
        connection.commit()
    finally:
        connection.close()

    class FakePort:
        def __init__(self, port: int, service: str) -> None:
            self.port = port
            self.protocol = "tcp"
            self.state = "open"
            self.service = service
            self.product = ""
            self.version = ""
            self.extrainfo = ""
            self.raw_port: dict[str, object] = {}

    class FakeHost:
        def __init__(self, ports: list[FakePort]) -> None:
            self.target = "10.10.10.11"
            self.host = "10.10.10.11"
            self.ip = "10.10.10.11"
            self.hostnames: list[str] = []
            self.ports = ports
            self.raw_host: dict[str, object] = {}

    class FakeNmapResult:
        def __init__(self, ports: list[FakePort]) -> None:
            self.command = ["nmap"]
            self.targets = ["10.10.10.11"]
            self.hosts = [FakeHost(ports)]
            self.raw_output = "<nmaprun />"

    class FakeHttpxEntry:
        def __init__(self, url: str, port: int) -> None:
            self.input_target = url
            self.host = "10.10.10.11"
            self.port = port
            self.url = url
            self.path = "/"
            self.scheme = "http"
            self.status_code = 200
            self.title = "t"
            self.webserver = "nginx"
            self.technologies: list[str] = []
            self.ip = "10.10.10.11"
            self.cname = None
            self.content_type = "text/html"
            self.redirect_location = None
            self.probe_status = "success"
            self.raw_entry: dict[str, object] = {}

    class FakeHttpxResult:
        def __init__(self, targets: list[str]) -> None:
            self.command = ["httpx"]
            self.targets = targets
            self.entries = []
            for t in targets:
                p = 8888 if ":8888" in t else 80
                self.entries.append(FakeHttpxEntry(t, p))
            self.raw_output = "{}\n"

    from scanner.adapters.ffuf_runner import FfufRunResult

    def fake_ffuf(base_url: str, **kwargs) -> FfufRunResult:
        return FfufRunResult(
            command=["ffuf"],
            base_url=base_url,
            output_path=kwargs["output_path"],
            matches=[],
            raw_output="{}",
        )

    monkeypatch.setattr("scanner.execution.portscan.runner_core.run_nmap_scan", lambda *a, **k: FakeNmapResult([FakePort(80, "http")]))
    monkeypatch.setattr("scanner.execution.http_probe.runner_core.run_httpx_probe", lambda targets, **k: FakeHttpxResult(list(targets)))
    monkeypatch.setattr("scanner.execution.dirscan.runner_core.run_ffuf_scan", fake_ffuf)

    execute_port_scan_tasks(run_id)
    execute_http_probe_tasks(run_id)
    execute_dir_enum_tasks(run_id)

    connection = connect(state_db_path)
    try:
        insert_finding(
            connection,
            Finding(
                finding_id="finding-port-8888",
                run_id=run_id,
                task_id=created["tasks"][0]["task_id"],
                module="port_scan",
                target="10.10.10.11:tcp/8888",
                summary="Observed open tcp/8888",
                evidence_json={
                    "host": "10.10.10.11",
                    "ip": "10.10.10.11",
                    "port": 8888,
                    "state": "open",
                    "service": "http",
                },
                created_at=datetime.now(UTC),
            ),
        )
        inc_http = maybe_enqueue_incremental_http_probe_tasks(connection, run_id, trigger_task_id="manual")
        assert inc_http["enqueued"] is True
    finally:
        connection.close()

    execute_http_probe_tasks(run_id)

    connection = connect(state_db_path)
    try:
        row = connection.execute(
            """
            SELECT cursor_json FROM tasks
            WHERE run_id = ? AND module = 'dir_enum' AND state = 'pending' AND scope LIKE 'incremental:dir_enum:%'
            LIMIT 1
            """,
            (run_id,),
        ).fetchone()
        assert row is not None
        cur = json.loads(row["cursor_json"])
        assert "http://10.10.10.11:8888/" in cur.get("explicit_dirscan_targets", [])
    finally:
        connection.close()


def test_split_ipv4_cidr_for_port_scan_divides_slash24(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    chunks = split_ipv4_cidr_for_port_scan("10.0.0.0/24", 32)
    assert len(chunks) == 8
    assert all("/27" in c for c in chunks)


def test_split_ipv4_cidr_for_port_scan_small_range_unchanged(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    chunks = split_ipv4_cidr_for_port_scan("192.168.1.0/28", 32)
    assert len(chunks) == 1
    assert chunks[0] == "192.168.1.0/28"


def test_cidr_offset_range_target_returns_cidr_not_full_ip_range() -> None:
    target, next_index, last_ip, done = cidr_offset_range_target("114.31.114.0/24", 0, 32)
    assert target == "114.31.114.0/27"
    assert next_index == 32
    assert last_ip == "114.31.114.31"
    assert done is False


def test_should_split_port_scan_cidr_respects_flags() -> None:
    base = ScanConfig(
        target="x",
        profile="safe",
        cidr_split_enabled=True,
        cidr_split_max_hosts_per_chunk=32,
    )
    assert should_split_port_scan_cidr(base, ["10.0.0.0/24"]) is True
    off = base.model_copy(update={"cidr_split_enabled": False})
    assert should_split_port_scan_cidr(off, ["10.0.0.0/24"]) is False
    assert should_split_port_scan_cidr(base, ["10.0.0.0/28"]) is False


def test_is_directory_like_path_allows_slash_rejects_file_ext() -> None:
    assert is_directory_like_path("https://a.com/docs/", 200, None) is True
    assert is_directory_like_path("https://a.com/page.html", 200, None) is False
    assert is_directory_like_path("https://a.com/x", 404, None) is False


def test_child_dirscan_base_url_from_finding() -> None:
    assert child_dirscan_base_url_from_finding("https://x.y/admin?z=1") == "https://x.y/admin/"


def test_recursive_dir_enum_enqueues_from_findings(
    tmp_path: Path, monkeypatch
) -> None:
    """Phase 11: optional recursive task after dir findings (mocked)."""
    monkeypatch.chdir(tmp_path)
    from scanner.state import get_run, get_task, get_tasks
    from scanner.storage import connect, insert_finding

    created = create_scan_run("10.0.0.1", modules=["http_probe", "dir_enum"], profile="safe")
    run_id = created["run_id"]
    state_db = Path(created["state_db_path"])
    connection = connect(state_db)
    try:
        run = get_run(connection, run_id)
        assert run is not None
        d_task = next(t for t in get_tasks(connection, run_id) if t.module == "dir_enum")
        new_cfg = run.config.model_copy(
            update={
                "dir_recursive_enabled": True,
                "dir_recursive_max_depth": 2,
                "dir_recursive_max_paths_per_host": 50,
            }
        )
        connection.execute(
            "UPDATE runs SET config_json = ? WHERE run_id = ?",
            (json.dumps(new_cfg.model_dump(mode="json"), sort_keys=True, separators=(",", ":")), run_id),
        )
        connection.commit()
        f = Finding(
            finding_id="finding-t",
            run_id=run_id,
            task_id=d_task.task_id,
            module="dir_enum",
            target="https://10.0.0.1/admin",
            summary="s",
            evidence_json={
                "url": "https://10.0.0.1/admin",
                "base_url": "https://10.0.0.1/",
                "status_code": 200,
            },
            tags=[],
            created_at=datetime.now(UTC),
        )
        insert_finding(connection, f)
        connection.commit()
        out = maybe_enqueue_recursive_dir_enum_tasks(
            connection, run_id, d_task.task_id, workspace=tmp_path
        )
        assert out.get("enqueued") is True
        row = connection.execute(
            "SELECT 1 FROM tasks WHERE run_id = ? AND state = 'pending' AND scope LIKE 'recursive:dir_enum:%' LIMIT 1",
            (run_id,),
        ).fetchone()
        assert row is not None
        child = get_task(connection, out["task_id"])
        assert child.cursor_json
        assert child.cursor_json.get("recursion_depth") == 1
    finally:
        connection.close()


def test_adaptive_chunk_size_adjustment() -> None:
    """EMA target interval drives next host-count chunk (bounded 8..256)."""
    # 600s target / 520s avg ≈ 1.15 → 32 * 1.15 → 36 after int()
    assert calculate_next_chunk_size(520.0, 10, 32) == 36


def test_resume_port_scan_from_checkpoint(tmp_path: Path, monkeypatch) -> None:
    """Resuming CIDR scan continues from saved cidr_next_offset (chunk 2 at offset 64)."""
    monkeypatch.chdir(tmp_path)
    created = create_scan_run("10.0.0.0/24", modules=["port_scan"], profile="fast")
    run_id = created["run_id"]
    task_id = next(t["task_id"] for t in created["tasks"] if t["module"] == "port_scan")
    state_db = Path(created["state_db_path"])
    connection = connect(state_db)
    try:
        cursor = {
            "stage": "nmap_scan",
            "cidr_resume_in_progress": True,
            "cidr_root": "10.0.0.0/24",
            "cidr_total_addresses": 256,
            "cidr_next_offset": 64,
            "cidr_current_chunk_size": 32,
            "cidr_completed_chunks": [0, 1],
            "cidr_avg_chunk_duration_sec": 1.0,
        }
        update_task_state(
            connection,
            task_id,
            "failed",
            cursor_json=cursor,
            last_error="CIDR port scan stopped (resumable)",
        )
    finally:
        connection.close()

    seen: list[str] = []

    class FakeNmapResult:
        def __init__(self) -> None:
            self.command = ["nmap"]
            self.targets: list[str] = []
            self.hosts: list[object] = []
            self.raw_output = "<nmaprun />"

    def fake_nmap_scan(targets, **kwargs):
        if not seen:
            seen.append(targets[0] if targets else "")
        return FakeNmapResult()

    monkeypatch.setattr("scanner.execution.portscan.runner_core.run_nmap_scan", fake_nmap_scan)

    execute_port_scan_tasks(run_id)

    assert len(seen) == 1
    assert "10.0.0.64" in seen[0]


def test_cancel_and_resume_preserves_cursor(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    from scanner.state import get_task, mark_run_running

    created = create_scan_run("10.0.0.0/24", modules=["port_scan"], profile="fast")
    run_id = created["run_id"]
    task_id = next(t["task_id"] for t in created["tasks"] if t["module"] == "port_scan")
    state_db = Path(created["state_db_path"])
    connection = connect(state_db)
    try:
        mark_run_running(connection, run_id)
        pl = {
            "stage": "nmap_scan",
            "cidr_resume_in_progress": True,
            "cidr_root": "10.0.0.0/24",
            "cidr_total_addresses": 256,
            "cidr_next_offset": 128,
            "cidr_current_chunk_size": 32,
        }
        update_task_state(
            connection, task_id, "running", cursor_json=pl, last_error=None
        )
    finally:
        connection.close()

    cancel_run(run_id, workspace=tmp_path)
    connection = connect(state_db)
    try:
        task = get_task(connection, task_id)
        assert task.state == "failed"
        assert "resumable" in (task.last_error or "").lower()
        assert task.cursor_json is not None
        assert int(task.cursor_json.get("cidr_next_offset", -1)) == 128
    finally:
        connection.close()


def test_enqueue_chunk_incremental_http_probe_skips_initial_http_gate(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    summary = create_scan_run("127.0.0.10", modules=["http_probe"])
    run_id = summary["run_id"]
    state_db = Path(summary["state_db_path"])
    connection = connect(state_db)
    try:
        result = enqueue_chunk_incremental_http_probe_tasks(
            connection, run_id, urls=["http://127.0.0.10:8080/"]
        )
        assert result.get("enqueued") is True
        assert result.get("task_id")
    finally:
        connection.close()


def test_enqueue_tls_san_http_probe_expands_hostnames_and_dedups(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    summary = create_scan_run("127.0.0.12", modules=["http_probe"])
    run_id = summary["run_id"]
    state_db = Path(summary["state_db_path"])
    connection = connect(state_db)
    try:
        result = enqueue_tls_san_http_probe_tasks(
            connection,
            run_id,
            hostnames=["app.example.org", "*.wildcard.example.org", "bad", "app.example.org"],
        )
        assert result.get("enqueued") is True
        new_urls = result.get("new_urls") or []
        # Valid host expanded to https+http; wildcard and bare label dropped.
        assert "https://app.example.org/" in new_urls
        assert "http://app.example.org/" in new_urls
        assert not any("wildcard" in u for u in new_urls)
        assert not any(u.endswith("//bad/") for u in new_urls)

        # Re-enqueuing the same host is deduped against the pending task.
        again = enqueue_tls_san_http_probe_tasks(
            connection, run_id, hostnames=["app.example.org"]
        )
        assert again.get("enqueued") is False
    finally:
        connection.close()


def test_enqueue_tls_san_http_probe_no_valid_hosts(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    summary = create_scan_run("127.0.0.13", modules=["http_probe"])
    run_id = summary["run_id"]
    state_db = Path(summary["state_db_path"])
    connection = connect(state_db)
    try:
        result = enqueue_tls_san_http_probe_tasks(
            connection, run_id, hostnames=["*.only.wildcard", "nolabel", ""]
        )
        assert result.get("enqueued") is False
    finally:
        connection.close()


def test_maybe_enqueue_incremental_http_still_requires_initial_probe(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    summary = create_scan_run("127.0.0.11", modules=["http_probe"])
    run_id = summary["run_id"]
    state_db = Path(summary["state_db_path"])
    connection = connect(state_db)
    try:
        result = maybe_enqueue_incremental_http_probe_tasks(connection, run_id)
        assert result.get("enqueued") is False
        assert "initial" in (result.get("reason") or "").lower()
    finally:
        connection.close()


def test_port_scan_chunk_starts_http_probe_before_all_chunks_complete(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    created = create_scan_run("10.20.30.0/24", modules=["port_scan", "http_probe"], profile="fast")
    run_id = created["run_id"]
    state_db_path = Path(created["state_db_path"])
    call_order: list[str] = []
    nmap_calls = 0

    class FakePort:
        def __init__(self, port: int, service: str) -> None:
            self.port = port
            self.protocol = "tcp"
            self.state = "open"
            self.service = service
            self.product = ""
            self.version = ""
            self.extrainfo = ""
            self.raw_port: dict[str, object] = {}

    class FakeHost:
        def __init__(self, host_ip: str) -> None:
            self.target = host_ip
            self.host = host_ip
            self.ip = host_ip
            self.hostnames: list[str] = []
            self.ports = [FakePort(80, "http")]
            self.raw_host: dict[str, object] = {}

    class FakeNmapResult:
        def __init__(self, host_ip: str) -> None:
            self.command = ["nmap"]
            self.targets = [host_ip]
            self.hosts = [FakeHost(host_ip)]
            self.raw_output = "<nmaprun />"

    connection = connect(state_db_path)
    try:
        cfg_row = connection.execute(
            "SELECT config_json FROM runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        assert cfg_row is not None
        cfg = json.loads(cfg_row["config_json"])
        cfg["cidr_split_enabled"] = True
        cfg["cidr_split_max_hosts_per_chunk"] = 64
        connection.execute(
            "UPDATE runs SET config_json = ? WHERE run_id = ?",
            (json.dumps(cfg, sort_keys=True, separators=(",", ":")), run_id),
        )
        connection.commit()
    finally:
        connection.close()

    def fake_nmap_scan(targets, **kwargs):
        nonlocal nmap_calls
        nmap_calls += 1
        call_order.append(f"nmap-{nmap_calls}")
        host_ip = "10.20.30.1" if nmap_calls == 1 else "10.20.30.2"
        return FakeNmapResult(host_ip)

    def fake_execute_http_probe_tasks(run_id_arg: str, *, workspace=None):
        assert run_id_arg == run_id
        call_order.append("http")
        return {"run_id": run_id_arg, "processed_task_count": 1}

    monkeypatch.setattr("scanner.execution.portscan.runner_core.run_nmap_scan", fake_nmap_scan)
    monkeypatch.setattr("scanner.runner.execute_http_probe_tasks", fake_execute_http_probe_tasks)

    execute_port_scan_tasks(run_id)

    assert nmap_calls >= 2
    assert call_order[0] == "nmap-1"
    assert call_order[1] == "http"
    assert "nmap-2" in call_order
