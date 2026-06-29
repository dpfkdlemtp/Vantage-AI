from __future__ import annotations

import json
import sqlite3
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

import pytest
import scanner.web as web_module
import scanner.web_utils as web_utils_module
from scanner.adapters.assetfinder_runner import AssetfinderRunResult
from scanner.adapters.ffuf_runner import FfufResultEntry, FfufRunResult
from scanner.adapters.httpx_runner import HttpxProbeResult, HttpxRunResult
from scanner.adapters.nmap_runner import NmapRunResult
from scanner.adapters.subfinder_runner import SubfinderRunResult
from scanner.execution.dirscan import execute_dir_enum_tasks
from scanner.execution.http_probe import execute_http_probe_tasks
from scanner.models import ArtifactRef, Finding
from scanner.storage import connect, insert_artifact, insert_finding
from scanner.web import start_ui_server


def _request_json(base_url: str, path: str, *, method: str = "GET", payload: dict[str, object] | None = None) -> dict[str, Any]:
    body = None
    headers = {}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = Request(f"{base_url}{path}", data=body, method=method, headers=headers)
    with urlopen(request, timeout=10) as response:  # noqa: S310
        return json.loads(response.read().decode("utf-8"))


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def _request_without_redirects(base_url: str, path: str) -> tuple[int, dict[str, str], str]:
    opener = build_opener(_NoRedirectHandler)
    request = Request(f"{base_url}{path}", method="GET")
    try:
        http_response = opener.open(request, timeout=10)  # noqa: S310
    except HTTPError as error_response:
        body = error_response.read().decode("utf-8")
        return error_response.code, dict(error_response.headers.items()), body
    with http_response:
        body = http_response.read().decode("utf-8")
        return http_response.status, dict(http_response.headers.items()), body


def _assert_redirect(base_url: str, source: str, location: str) -> None:
    status, headers, body = _request_without_redirects(base_url, source)
    assert status == 302
    assert headers["Location"] == location
    assert headers["Content-Length"] == "0"
    assert headers["Cache-Control"] == "no-store, max-age=0"
    assert body == ""


def _assert_react_shell(base_url: str, path: str) -> None:
    status, headers, html = _request_without_redirects(base_url, path)
    assert status == 200
    assert headers["Content-Type"] == "text/html; charset=utf-8"
    assert '<div id="root"></div>' in html
    assert "ReactDOM.createRoot" in html
    assert "function AppShell" in html
    assert "function LoadingState" in html
    assert "function ErrorState" in html
    assert "function RunsDashboard" in html
    assert "Re-run" in html
    assert "Re-run scan" in html
    assert "Edit Config" in html
    assert "Editing pending scan" in html
    assert "Config changes apply to upcoming tasks only" in html
    assert "Live tuning" in html
    assert "Delete" in html
    assert "data-delete-run-confirm" in html
    assert "function NewScanModal" in html
    assert "const SPEED_LEVELS = [" in html
    assert "speed_level: speedLevel" in html
    assert "speed_config: speedConfig" in html
    assert "function ExecutionPage" in html
    assert 'data-execution-page="vantage"' in html
    assert "function RunSummaryPage" in html
    assert "Scan Quality" in html
    assert "function SummaryCards" in html
    assert "function RecentHostsTable" in html
    assert 'data-run-summary-page="vantage"' in html
    assert "function FindingsPage" in html
    assert "function FindingsHostNavigator" in html
    assert "function FindingsServicePanel" in html
    assert "function FindingsResultPanel" in html
    assert "Auto Recommendation:" in html
    assert "function GlobalSummaryPanel" in html
    assert "Change Alerts" in html
    assert "Recommended Actions" in html
    assert "Priority Queue" in html
    assert "Run ffuf" in html
    assert "All Open Ports" in html
    assert "All Directories" in html
    assert "Discovered URLs" in html
    assert "Global Discovered URLs" in html
    assert "function mergeCheckpointTaskLogs" in html
    assert "Recursive directory scan" in html
    assert 'data-smart-scan-mode="vantage"' in html
    assert "function formatScanModeLabel" in html
    assert "Apply speed plan ffuf threads" in html
    assert "ffuf-extension-catalog" in html
    assert "Chunk ${progress.chunk_index}" in html
    assert 'data-findings-page="vantage"' in html
    assert "Add note" in html
    assert "Notes" in html
    assert "data-service-notes-section" in html
    assert "Notes Summary" in html
    assert "data-global-notes-summary" in html
    assert "📝" in html
    assert "Possible web admin panel exposure" in html
    assert "Re-run with notes context" in html
    assert "Edit & Re-run" in html
    assert "Source run:" in html
    assert "Notes:" in html
    assert "Recent changes" in html
    assert "View detailed changes" in html
    assert "compare=" in html
    assert "[nmap stats]" in html
    assert "Port Scan Progress" in html
    assert "Speed:" in html
    assert "ETA:" in html
    assert "Raw stats fallback:" in html
    assert "Recommended: /24 -> 16 hosts, /26 -> 8 hosts" in html
    assert 'data-cidr-chunk-slider="vantage"' in html
    assert "FFUF replay proxy (ip:port)" in html
    assert "SOCKS mode expects socks5://IP:PORT" in html
    assert "Proxy URL status:" in html
    assert "Bulk target mode completed" in html
    assert "Open runs" in html
    assert "Auto-triggered from http_probe web response" in html
    assert "Auto dirscan triggers" in html
    assert "Selection Delta Preview" in html
    assert "Mode Δ FAST: nmap ports => top1000" in html
    assert "Profile Δ SAFE: httpx threads <= 10, default rate 25" in html
    assert 'data-execution-options="vantage"' in html
    assert "function ExecutionOptionsCard" in html
    assert "Scan Options" in html
    assert "Run ffuf" in html
    assert "Inspect + Run ffuf" in html
    assert "Add note" in html
    assert "Open" in html
    assert 'data-directory-actions="vantage"' in html
    assert "Open browser" in html
    assert "Re-scan deeper" in html
    assert "Port removed with note context" in html
    assert 'data-sidebar-toggle="vantage"' in html
    assert 'data-sidebar-collapsed={sidebarCollapsed ? "yes" : "no"}' in html
    assert "function Dashboard" in html


def _wait_for_execution(base_url: str, run_id: str) -> dict[str, Any]:
    for _ in range(40):
        view = _request_json(base_url, f"/api/runs/{run_id}")
        if not view["execution"]["active"]:
            return _request_json(base_url, f"/api/runs/{run_id}")
        time.sleep(0.05)
    raise AssertionError("execution did not finish in time")


def test_web_ui_lists_and_creates_runs(tmp_path: Path) -> None:
    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"

    try:
        initial = _request_json(base_url, "/api/runs")
        assert initial["runs"] == []

        wordlist_path = tmp_path / "words.txt"
        wordlist_path.write_text("admin\n", encoding="utf-8")
        created = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={
                "target": "example.com",
                "modules": ["http_probe", "dir_enum"],
                "profile": "balanced",
                "ffuf_wordlist_path": str(wordlist_path),
                "nmap_ports": "80,443",
                "auto_start": False,
            },
        )

        assert created["run"]["target"] == "example.com"
        assert created["run"]["display_name"].startswith("example.com-")
        assert created["run"]["config"]["profile"] == "balanced"
        assert created["run"]["config"]["ffuf_wordlist_path"] == str(wordlist_path.resolve())
        assert created["run"]["config"]["nmap_ports"] == "80,443"
        assert [task["module"] for task in created["tasks"]] == ["http_probe", "dir_enum"]

        listed = _request_json(base_url, "/api/runs")
        assert len(listed["runs"]) == 1
        assert listed["runs"][0]["target"] == "example.com"
        assert listed["runs"][0]["display_name"].startswith("example.com-")
    finally:
        handle.close()


def test_display_run_name_uses_target_and_timestamp() -> None:
    created_at = datetime(2026, 4, 25, 12, 34, 56, tzinfo=UTC)

    assert web_module._display_run_name("http://LOCALHOST:3000/", created_at) == "localhost-20260425123456"
    assert web_module._display_run_name("127.0.0.1/28", created_at) == "127.0.0.1-28-20260425123456"


def test_web_ui_creates_run_with_default_wordlist_if_empty_in_payload(tmp_path: Path) -> None:
    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"

    try:
        # Create a run with an empty ffuf_wordlist_path in the payload
        created = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={
                "target": "example.com",
                "modules": ["dir_enum"],
                "profile": "safe",
                "ffuf_wordlist_path": "",
                "auto_start": False,
            },
        )

        # The config should NOT have None for ffuf_wordlist_path; it should have the default
        config = created["run"]["config"]
        assert config["ffuf_wordlist_path"] is not None
        assert Path(config["ffuf_wordlist_path"]).name == "test.txt"
        assert Path(config["ffuf_wordlist_path"]).parent.name == "wordlists"

        run_id = created["run"]["run_id"]

        # Verify that patching it with empty string also preserves it
        patched = _request_json(
            base_url,
            f"/api/runs/{run_id}/config",
            method="POST",
            payload={
                "ffuf_wordlist_path": "",
            },
        )
        assert patched["run"]["config"]["ffuf_wordlist_path"] is not None
        assert Path(patched["run"]["config"]["ffuf_wordlist_path"]).name == "test.txt"
        assert Path(patched["run"]["config"]["ffuf_wordlist_path"]).parent.name == "wordlists"

    finally:
        handle.close()


def test_web_ui_create_run_uses_local_tool_paths_as_default_bins(tmp_path: Path, monkeypatch) -> None:
    local_appdata = tmp_path / "localappdata"
    tool_paths = {
        "subfinder_bin": local_appdata / "web-scanner-tools" / "bin" / "subfinder.exe",
        "assetfinder_bin": local_appdata / "web-scanner-tools" / "bin" / "assetfinder.exe",
        "httpx_bin": local_appdata / "web-scanner-tools" / "bin" / "httpx.exe",
        "ffuf_bin": local_appdata / "web-scanner-tools" / "bin" / "ffuf.exe",
        "nmap_bin": local_appdata / "web-scanner-tools" / "nmap" / "nmap.exe",
    }
    for path in tool_paths.values():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")
    monkeypatch.setenv("LOCALAPPDATA", str(local_appdata))
    monkeypatch.setattr(web_utils_module.platform, "system", lambda: "Windows")

    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"
    try:
        created = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={
                "target": "127.0.0.1/28",
                "modules": ["port_scan", "http_probe", "dir_enum"],
                "profile": "fast",
                "auto_start": False,
            },
        )

        config = created["run"]["config"]
        assert config["subfinder_bin"] == str(tool_paths["subfinder_bin"])
        assert config["assetfinder_bin"] == str(tool_paths["assetfinder_bin"])
        assert config["httpx_bin"] == str(tool_paths["httpx_bin"])
        assert config["ffuf_bin"] == str(tool_paths["ffuf_bin"])
        assert config["nmap_bin"] == str(tool_paths["nmap_bin"])
    finally:
        handle.close()


def test_web_ui_create_run_uses_intel_mac_tool_paths_as_default_bins(tmp_path: Path, monkeypatch) -> None:
    home_dir = tmp_path / "home"
    tool_paths = {
        "subfinder_bin": home_dir / "go" / "bin" / "subfinder",
        "assetfinder_bin": home_dir / "go" / "bin" / "assetfinder",
        "httpx_bin": home_dir / "go" / "bin" / "httpx",
        "ffuf_bin": Path("/usr/local/bin/ffuf"),
        "nmap_bin": Path("/usr/local/bin/nmap"),
    }
    for key, path in tool_paths.items():
        if path.is_absolute() and str(path).startswith("/usr/local/bin"):
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")

    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setattr(web_module.platform, "system", lambda: "Darwin")

    def fake_exists(self: Path) -> bool:
        if self == Path("/usr/local/bin/ffuf") or self == Path("/usr/local/bin/nmap"):
            return True
        return Path.is_file(self)

    monkeypatch.setattr(web_module.Path, "exists", fake_exists)
    monkeypatch.setattr(web_module.shutil, "which", lambda _: None)

    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"
    try:
        created = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={
                "target": "scan.example",
                "modules": ["http_probe", "dir_enum", "port_scan"],
                "profile": "balanced",
                "auto_start": False,
            },
        )

        config = created["run"]["config"]
        assert config["subfinder_bin"] == str(tool_paths["subfinder_bin"])
        assert config["assetfinder_bin"] == str(tool_paths["assetfinder_bin"])
        assert config["httpx_bin"] == str(tool_paths["httpx_bin"])
        assert config["ffuf_bin"] == str(tool_paths["ffuf_bin"])
        assert config["nmap_bin"] == str(tool_paths["nmap_bin"])
    finally:
        handle.close()


def test_web_ui_clone_config_returns_source_run_settings(tmp_path: Path) -> None:
    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"

    try:
        # 1. Create a source run with specific settings
        wordlist_path = tmp_path / "words.txt"
        wordlist_path.write_text("admin\n", encoding="utf-8")
        created = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={
                "target": "source.example",
                "modules": ["http_probe"],
                "profile": "balanced",
                "scan_mode": "deep",
                "ffuf_wordlist_path": str(wordlist_path),
                "nmap_ports": "80,443,8080",
                "auto_start": False,
            },
        )
        run_id = created["run"]["run_id"]

        # 2. Call clone-config API
        clone_config = _request_json(base_url, f"/api/runs/{run_id}/clone-config")

        # 3. Verify settings are correctly mapped for the New Run form
        assert clone_config["source_run_id"] == run_id
        assert clone_config["target"] == "source.example"
        assert clone_config["profile"] == "balanced"
        assert clone_config["modules"] == ["http_probe"]
        assert clone_config["ffuf_wordlist_path"] == str(wordlist_path.resolve())
        assert clone_config["nmap_ports"] == "80,443,8080"
        assert clone_config["scan_mode"] == "deep"
    finally:
        handle.close()


def test_web_api_delete_run_removes_directory(tmp_path: Path) -> None:
    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"
    try:
        created = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={
                "target": "del.example",
                "modules": ["http_probe"],
                "profile": "safe",
                "auto_start": False,
            },
        )
        run_id = str(created["run"]["run_id"])
        assert (tmp_path / "runs" / run_id / "state.db").is_file()
        result = _request_json(base_url, f"/api/runs/{run_id}", method="DELETE")
        assert result.get("success") is True
        assert not (tmp_path / "runs" / run_id).exists()
    finally:
        handle.close()


def test_web_api_ffuf_extension_catalog_and_recommendations(tmp_path: Path) -> None:
    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"
    try:
        cat = _request_json(base_url, "/api/ffuf-extension-catalog")
        assert "catalog" in cat
        assert ".php" in cat["catalog"]
        assert "recommendation_map" in cat
        rec = _request_json(
            base_url,
            "/api/recommended-extensions?service=http&tech=nginx/1.2",
        )
        assert ".php" in rec["extensions"]
        assert ".html" in rec["extensions"]
    finally:
        handle.close()


def test_web_api_delete_run_rejects_active_execution(tmp_path: Path, monkeypatch) -> None:
    from scanner.web_execution import WebExecutionManager

    sim_active: set[str] = set()

    def fake_is_active(self: WebExecutionManager, run_id: str) -> bool:  # noqa: ARG001
        return str(run_id) in sim_active

    monkeypatch.setattr(WebExecutionManager, "is_active", fake_is_active)
    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"
    try:
        created = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={"target": "active.example", "modules": ["http_probe"], "profile": "safe", "auto_start": False},
        )
        run_id = str(created["run"]["run_id"])
        sim_active.add(run_id)
        request = Request(f"{base_url}/api/runs/{run_id}", method="DELETE")
        with pytest.raises(HTTPError) as exc:
            urlopen(request, timeout=10)  # noqa: S310
        assert exc.value.code == 409
        sim_active.clear()
        out = _request_json(base_url, f"/api/runs/{run_id}", method="DELETE")
        assert out.get("success") is True
        assert not (tmp_path / "runs" / run_id).exists()
    finally:
        handle.close()


def test_web_ui_can_start_phase_execution_and_show_progress(tmp_path: Path, monkeypatch) -> None:
    calls: list[str] = []

    def fake_http_probe(run_id: str, *, workspace: Path | None = None) -> dict[str, Any]:
        calls.append(f"http_probe:{run_id}:{workspace}")
        return {"run_id": run_id, "processed_task_count": 1}

    monkeypatch.setattr("scanner.web.execute_http_probe_tasks", fake_http_probe)
    monkeypatch.setitem(web_module.MODULE_EXECUTORS, "http_probe", fake_http_probe)

    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"
    try:
        created = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={
                "target": "example.org",
                "modules": ["http_probe"],
                "profile": "safe",
                "auto_start": False,
            },
        )
        run_id = str(created["run"]["run_id"])

        started = _request_json(
            base_url,
            f"/api/runs/{run_id}/execute",
            method="POST",
            payload={"module": "http_probe"},
        )
        assert started["run"]["run_id"] == run_id

        for _ in range(20):
            view = _request_json(base_url, f"/api/runs/{run_id}")
            if not view["execution"]["active"]:
                break
        else:
            raise AssertionError("execution did not finish in time")

        assert calls == [f"http_probe:{run_id}:{tmp_path.resolve()}"]
        logs = _request_json(base_url, f"/api/runs/{run_id}/logs")
        messages = [item["message"] for item in logs["items"]]
        assert "Execution requested" in messages
        assert "Module execution started" in messages
        assert "Module execution finished" in messages
    finally:
        handle.close()


def test_web_ui_runs_cidr_modules_in_enabled_phase_order(tmp_path: Path, monkeypatch) -> None:
    calls: list[str] = []

    def fake_port_scan(run_id: str, *, workspace: Path | None = None) -> dict[str, Any]:
        calls.append("port_scan")
        return {"run_id": run_id, "processed_task_count": 1}

    def fake_http_probe(run_id: str, *, workspace: Path | None = None) -> dict[str, Any]:
        calls.append("http_probe")
        return {"run_id": run_id, "processed_task_count": 1}

    def fake_dir_enum(run_id: str, *, workspace: Path | None = None) -> dict[str, Any]:
        calls.append("dir_enum")
        return {"run_id": run_id, "processed_task_count": 1}

    monkeypatch.setattr("scanner.web.execute_port_scan_tasks", fake_port_scan)
    monkeypatch.setattr("scanner.web.execute_http_probe_tasks", fake_http_probe)
    monkeypatch.setattr("scanner.web.execute_dir_enum_tasks", fake_dir_enum)
    monkeypatch.setitem(web_module.MODULE_EXECUTORS, "port_scan", fake_port_scan)
    monkeypatch.setitem(web_module.MODULE_EXECUTORS, "http_probe", fake_http_probe)
    monkeypatch.setitem(web_module.MODULE_EXECUTORS, "dir_enum", fake_dir_enum)

    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"
    try:
        created = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={
                "target": "127.0.0.1/28",
                "modules": ["port_scan", "http_probe", "dir_enum"],
                "profile": "fast",
                "auto_start": False,
            },
        )
        run_id = str(created["run"]["run_id"])

        _request_json(
            base_url,
            f"/api/runs/{run_id}/execute",
            method="POST",
            payload={},
        )
        _wait_for_execution(base_url, run_id)

        assert calls == ["port_scan", "http_probe", "dir_enum"]
    finally:
        handle.close()


def test_web_ui_marks_downstream_completed_phases_as_revisit_in_execution_plan(tmp_path: Path) -> None:
    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"
    try:
        created = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={
                "target": "127.0.0.1/28",
                "modules": ["port_scan", "http_probe", "dir_enum"],
                "profile": "fast",
                "auto_start": False,
            },
        )
        run_id = str(created["run"]["run_id"])
        state_db_path = tmp_path / "runs" / run_id / "state.db"
        connection = connect(state_db_path)
        try:
            connection.execute(
                "UPDATE runs SET status = 'running' WHERE run_id = ?",
                (run_id,),
            )
            connection.execute(
                "UPDATE tasks SET state = 'running' WHERE run_id = ? AND module = 'port_scan'",
                (run_id,),
            )
            connection.execute(
                "UPDATE tasks SET state = 'completed' WHERE run_id = ? AND module IN ('http_probe', 'dir_enum')",
                (run_id,),
            )
            connection.commit()
        finally:
            connection.close()

        view = _request_json(base_url, f"/api/runs/{run_id}")
        plan_items = {item["module"]: item for item in view["execution_plan"]["items"]}

        assert plan_items["port_scan"]["display_state"] == "current"
        assert plan_items["http_probe"]["display_state"] == "revisit"
        assert plan_items["dir_enum"]["display_state"] == "revisit"
    finally:
        handle.close()


def test_web_ui_rejects_extend_modules_for_completed_run(tmp_path: Path) -> None:
    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"

    try:
        created = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={
                "target": "example.org",
                "modules": ["port_scan"],
                "profile": "safe",
                "auto_start": False,
            },
        )
        run_id = str(created["run"]["run_id"])

        connection = connect(tmp_path / "runs" / run_id / "state.db")
        try:
            connection.execute("UPDATE runs SET status = 'completed' WHERE run_id = ?", (run_id,))
            connection.execute("UPDATE tasks SET state = 'completed' WHERE run_id = ?", (run_id,))
            connection.commit()
        finally:
            connection.close()

        with pytest.raises(HTTPError) as err:
            _request_json(
                base_url,
                f"/api/runs/{run_id}/config",
                method="POST",
                payload={"modules": ["subdomain_enum", "dir_enum"]},
            )
        assert err.value.code == 400
    finally:
        handle.close()


def test_web_ui_routes_root_and_legacy_entries_to_runs(tmp_path: Path) -> None:
    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"

    try:
        _assert_redirect(base_url, "/", "/runs")
        _assert_redirect(base_url, "/dashboard", "/runs")
        _assert_redirect(base_url, "/execution", "/runs?newScan=1")
        _assert_redirect(base_url, "/progress", "/runs")
        _assert_redirect(base_url, "/results", "/runs")
        _assert_redirect(base_url, "/runs/new", "/runs?newScan=1")
    finally:
        handle.close()


def test_web_ui_serves_react_dashboard_shell_for_runs(tmp_path: Path) -> None:
    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"

    try:
        _assert_react_shell(base_url, "/runs")
        _assert_react_shell(base_url, "/runs?newScan=1")
    finally:
        handle.close()


def test_web_ui_redirects_legacy_run_pages_to_spa_routes(tmp_path: Path) -> None:
    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"

    try:
        created = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={
                "target": "results.example",
                "modules": ["http_probe"],
                "profile": "safe",
                "auto_start": False,
            },
        )
        run_id = str(created["run"]["run_id"])
        _assert_redirect(base_url, f"/progress/{run_id}", f"/runs/{run_id}/execution")
        _assert_redirect(base_url, f"/results/{run_id}", f"/runs/{run_id}/summary")
    finally:
        handle.close()


def test_web_ui_serves_react_shell_for_run_spa_routes(tmp_path: Path) -> None:
    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"

    try:
        created = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={
                "target": "nav.example",
                "modules": ["http_probe"],
                "profile": "safe",
                "auto_start": False,
            },
        )
        run_id = str(created["run"]["run_id"])
        _assert_react_shell(base_url, f"/runs/{run_id}/execution")
        _assert_react_shell(base_url, f"/runs/{run_id}/summary")
        _assert_react_shell(base_url, f"/runs/{run_id}/findings")
        _assert_react_shell(base_url, f"/runs/{run_id}/findings?tab=directories")
        _assert_react_shell(base_url, f"/runs/{run_id}/findings?host=example")
    finally:
        handle.close()


def test_web_ui_exposes_run_diff_api_and_report_html(tmp_path: Path) -> None:
    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"
    now = datetime(2026, 4, 11, 12, 0, tzinfo=UTC)

    try:
        baseline = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={"target": "example.net", "modules": ["http_probe"], "profile": "safe", "auto_start": False},
        )
        current = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={
                "target": "current.example.net",
                "modules": ["http_probe"],
                "profile": "safe",
                "auto_start": False,
            },
        )
        baseline_run_id = str(baseline["run"]["run_id"])
        current_run_id = str(current["run"]["run_id"])
        baseline_task_id = str(baseline["tasks"][0]["task_id"])
        current_task_id = str(current["tasks"][0]["task_id"])

        baseline_db = tmp_path / "runs" / baseline_run_id / "state.db"
        current_db = tmp_path / "runs" / current_run_id / "state.db"
        baseline_conn = connect(baseline_db)
        current_conn = connect(current_db)
        try:
            insert_finding(
                baseline_conn,
                Finding(
                    finding_id="baseline-http-removed",
                    run_id=baseline_run_id,
                    task_id=baseline_task_id,
                    module="http_probe",
                    target="https://removed.example.net/",
                    summary="Removed host",
                    evidence_json={"status_code": 200},
                    created_at=now,
                ),
            )
            insert_finding(
                baseline_conn,
                Finding(
                    finding_id="baseline-http-same",
                    run_id=baseline_run_id,
                    task_id=baseline_task_id,
                    module="http_probe",
                    target="https://same.example.net/",
                    summary="Same host",
                    evidence_json={"status_code": 200},
                    created_at=now,
                ),
            )
            insert_finding(
                current_conn,
                Finding(
                    finding_id="current-http-added",
                    run_id=current_run_id,
                    task_id=current_task_id,
                    module="http_probe",
                    target="https://added.example.net/",
                    summary="Added host",
                    evidence_json={"status_code": 200},
                    created_at=now,
                ),
            )
            insert_finding(
                current_conn,
                Finding(
                    finding_id="current-http-same",
                    run_id=current_run_id,
                    task_id=current_task_id,
                    module="http_probe",
                    target="https://same.example.net/",
                    summary="Same host",
                    evidence_json={"status_code": 200},
                    created_at=now,
                ),
            )
        finally:
            baseline_conn.close()
            current_conn.close()

        diff = _request_json(
            base_url,
            f"/api/runs/{current_run_id}/diff?baseline={baseline_run_id}",
        )
        assert diff["categories"]["http_probe_results"]["added_count"] == 1
        assert diff["categories"]["http_probe_results"]["removed_count"] == 1
        assert diff["categories"]["http_probe_results"]["unchanged_count"] == 1

        with urlopen(
            f"{base_url}/api/runs/{current_run_id}/report.html?baseline={baseline_run_id}",
            timeout=10,
        ) as response:  # noqa: S310
            html = response.read().decode("utf-8")
        assert "Run Diff Summary" in html
        assert baseline_run_id in html
        assert current_run_id in html
    finally:
        handle.close()


def test_web_ui_run_diff_api_keeps_distinct_paths_and_ports(tmp_path: Path) -> None:
    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"
    now = datetime(2026, 4, 11, 12, 15, tzinfo=UTC)

    try:
        baseline = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={"target": "example.net", "modules": ["dir_enum", "port_scan"], "profile": "safe", "auto_start": False},
        )
        current = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={
                "target": "current.example.net",
                "modules": ["dir_enum", "port_scan"],
                "profile": "safe",
                "auto_start": False,
            },
        )
        baseline_run_id = str(baseline["run"]["run_id"])
        current_run_id = str(current["run"]["run_id"])

        baseline_conn = connect(tmp_path / "runs" / baseline_run_id / "state.db")
        current_conn = connect(tmp_path / "runs" / current_run_id / "state.db")
        try:
            insert_finding(
                baseline_conn,
                Finding(
                    finding_id="baseline-dir-admin",
                    run_id=baseline_run_id,
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
                    run_id=current_run_id,
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
                    run_id=current_run_id,
                    module="dir_enum",
                    target="https://app.example.net/login",
                    summary="Observed /login",
                    evidence_json={"url": "https://app.example.net/login", "path": "/login", "status_code": 200},
                    created_at=now,
                ),
            )
            insert_finding(
                baseline_conn,
                Finding(
                    finding_id="baseline-port-443",
                    run_id=baseline_run_id,
                    module="port_scan",
                    target="app.example.net:tcp/443",
                    summary="Observed tcp/443 open",
                    evidence_json={"state": "open", "protocol": "tcp", "port": 443, "service": "https", "product": "nginx", "version": "1.25"},
                    tags=["open"],
                    created_at=now,
                ),
            )
            insert_finding(
                current_conn,
                Finding(
                    finding_id="current-port-443",
                    run_id=current_run_id,
                    module="port_scan",
                    target="app.example.net:tcp/443",
                    summary="Observed tcp/443 open",
                    evidence_json={"state": "open", "protocol": "tcp", "port": 443, "service": "https", "product": "nginx", "version": "1.25"},
                    tags=["open"],
                    created_at=now,
                ),
            )
            insert_finding(
                current_conn,
                Finding(
                    finding_id="current-port-8443",
                    run_id=current_run_id,
                    module="port_scan",
                    target="app.example.net:tcp/8443",
                    summary="Observed tcp/8443 open",
                    evidence_json={"state": "open", "protocol": "tcp", "port": 8443, "service": "https", "product": "nginx", "version": "1.25"},
                    tags=["open"],
                    created_at=now,
                ),
            )
        finally:
            baseline_conn.close()
            current_conn.close()

        diff = _request_json(
            base_url,
            f"/api/runs/{current_run_id}/diff?baseline={baseline_run_id}",
        )

        assert diff["categories"]["directory_findings"]["added_count"] == 1
        assert [item["target"] for item in diff["categories"]["directory_findings"]["added"]] == [
            "https://app.example.net/login",
        ]
        assert diff["categories"]["open_ports"]["added_count"] == 1
        assert [item["target"] for item in diff["categories"]["open_ports"]["added"]] == [
            "app.example.net:tcp/8443",
        ]
    finally:
        handle.close()


def test_web_ui_exposes_presets_and_scope_controls(tmp_path: Path) -> None:
    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"

    try:
        presets = _request_json(base_url, "/api/presets")
        assert set(presets["presets"]) == {"quick", "web", "full", "ai"}
        created = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={
                "target": "scope.example",
                "preset": "quick",
                "scope_include": "api.scope.example\nadmin.scope.example",
                "scope_exclude": "dev.scope.example,old.scope.example",
                "auto_start": False,
            },
        )
        assert created["run"]["config"]["profile"] == "safe"
        assert created["run"]["config"]["enabled_phases"] == ["subdomain_enum", "http_probe"]
        assert created["scope"]["include"] == ["api.scope.example", "admin.scope.example"]
        assert created["scope"]["exclude"] == ["dev.scope.example", "old.scope.example"]
        assert created["scope"]["effective_targets"] == ["api.scope.example", "admin.scope.example"]
    finally:
        handle.close()


def test_web_ui_updates_run_config(tmp_path: Path) -> None:
    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"

    try:
        created = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={
                "target": "example.edu",
                "modules": ["http_probe", "dir_enum"],
                "profile": "safe",
                "auto_start": False,
            },
        )
        run_id = str(created["run"]["run_id"])
        wordlist_path = tmp_path / "wordlists.txt"
        wordlist_path.write_text("admin\nlogin\n", encoding="utf-8")

        updated = _request_json(
            base_url,
            f"/api/runs/{run_id}/config",
            method="POST",
            payload={
                "profile": "fast",
                "ffuf_wordlist_path": str(wordlist_path),
                "nmap_ports": "80,443,3000",
                "httpx_bin": "/usr/local/bin/httpx",
                "ffuf_bin": "/usr/local/bin/ffuf",
                "nmap_bin": "/usr/local/bin/nmap",
                "httpx_threads": 24,
                "httpx_timeout_seconds": 15,
                "ffuf_threads": 50,
                "ffuf_replay_proxy": "127.0.0.1:8080",
                "extra_headers_text": "X-Test-Header: enabled",
                "cookies": "session=abc123",
                "bearer_token": "secret-token",
                "host_header": "virtual.example.edu",
                "auto_recommendation_enabled": False,
            },
        )

        assert updated["run"]["config"]["profile"] == "fast"
        assert updated["run"]["config"]["ffuf_wordlist_path"] == str(wordlist_path.resolve())
        assert updated["run"]["config"]["nmap_ports"] == "80,443,3000"
        assert updated["run"]["config"]["httpx_bin"] == "/usr/local/bin/httpx"
        assert updated["run"]["config"]["ffuf_bin"] == "/usr/local/bin/ffuf"
        assert updated["run"]["config"]["nmap_bin"] == "/usr/local/bin/nmap"
        assert updated["run"]["config"]["httpx_threads"] == 24
        assert updated["run"]["config"]["httpx_timeout_seconds"] == 15
        assert updated["run"]["config"]["ffuf_threads"] == 50
        assert updated["run"]["config"]["ffuf_replay_proxy"] == "127.0.0.1:8080"
        assert updated["run"]["config"]["extra_headers"] == {
            "X-Test-Header": "enabled",
            "Cookie": "session=abc123",
            "Authorization": "Bearer secret-token",
            "Host": "virtual.example.edu",
        }
        assert updated["run"]["config"]["auth_fields"]["cookies"] == "session=abc123"
        assert updated["run"]["config"]["auth_fields"]["bearer_token"] == "secret-token"
        assert updated["run"]["config"]["auth_fields"]["host_header"] == "virtual.example.edu"
        assert "X-Test-Header: enabled" in updated["run"]["config"]["auth_fields"]["extra_headers_text"]
        assert updated["run"]["config"]["auto_recommendation_enabled"] is False
    finally:
        handle.close()


def test_edit_pending_run_config_via_patch_success(tmp_path: Path) -> None:
    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"
    try:
        created = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={"target": "example.org", "modules": ["http_probe"], "profile": "safe", "auto_start": False},
        )
        run_id = str(created["run"]["run_id"])
        patched = _request_json(
            base_url,
            f"/api/runs/{run_id}/config",
            method="PATCH",
            payload={"profile": "fast", "ffuf_concurrency": 55},
        )
        assert patched["run"]["status"] == "pending"
        assert patched["run"]["config"]["profile"] == "fast"
        assert patched["run"]["config"]["ffuf_concurrency"] == 55
        logs = _request_json(base_url, f"/api/runs/{run_id}/logs")
        assert any("Config updated" in str(item.get("message") or "") for item in logs.get("items", []))
    finally:
        handle.close()


def test_edit_running_run_allows_safe_fields_only(tmp_path: Path) -> None:
    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"
    try:
        created = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={"target": "example.org", "modules": ["http_probe"], "profile": "safe", "auto_start": False},
        )
        run_id = str(created["run"]["run_id"])
        db = connect(tmp_path / "runs" / run_id / "state.db")
        try:
            db.execute("UPDATE runs SET status = 'running' WHERE run_id = ?", (run_id,))
            db.execute("UPDATE tasks SET state = 'running' WHERE run_id = ?", (run_id,))
            db.commit()
        finally:
            db.close()

        patched = _request_json(
            base_url,
            f"/api/runs/{run_id}/config",
            method="PATCH",
            payload={"ffuf_concurrency": 70, "ffuf_extensions": [".php", ".bak"]},
        )
        assert patched["run"]["config"]["ffuf_concurrency"] == 70
        assert patched["run"]["config"]["ffuf_extensions"] == [".php", ".bak"]
        logs = _request_json(base_url, f"/api/runs/{run_id}/logs")
        messages = [str(item.get("message") or "") for item in logs.get("items", [])]
        assert any("Config updated" in message for message in messages)
        assert any("upcoming tasks only" in message for message in messages)

        with pytest.raises(HTTPError) as err:
            _request_json(
                base_url,
                f"/api/runs/{run_id}/config",
                method="PATCH",
                payload={"nmap_ports": "1-65535"},
            )
        assert err.value.code == 400
    finally:
        handle.close()


def test_edit_completed_run_config_rejected(tmp_path: Path) -> None:
    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"
    try:
        created = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={"target": "example.org", "modules": ["http_probe"], "profile": "safe", "auto_start": False},
        )
        run_id = str(created["run"]["run_id"])
        db = connect(tmp_path / "runs" / run_id / "state.db")
        try:
            db.execute("UPDATE runs SET status = 'completed' WHERE run_id = ?", (run_id,))
            db.commit()
        finally:
            db.close()
        with pytest.raises(HTTPError) as err:
            _request_json(
                base_url,
                f"/api/runs/{run_id}/config",
                method="PATCH",
                payload={"ffuf_concurrency": 42},
            )
        assert err.value.code == 400
    finally:
        handle.close()


def test_http_probe_injects_browser_headers_and_records_auth_detection(tmp_path: Path, monkeypatch) -> None:
    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"
    captured_commands: list[list[str]] = []

    def fake_httpx_runner(command: list[str], stdin_text: str) -> subprocess.CompletedProcess[str]:
        captured_commands.append(command)
        assert "app.example" in stdin_text
        payload = {
            "input": "app.example",
            "url": "https://app.example/login",
            "host": "app.example",
            "path": "/login",
            "scheme": "https",
            "port": 443,
            "status_code": 401,
            "title": "Sign in",
            "content_type": "text/html",
            "tech": ["nginx"],
            "webserver": "nginx",
            "probe_status": "success",
        }
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(payload) + "\n", stderr="")

    monkeypatch.setattr("scanner.adapters.httpx_runner._default_runner", fake_httpx_runner)
    monkeypatch.setattr("scanner.execution.http_probe.detect_technologies", lambda url, timeout_seconds=3.0: ["wordpress", "php"])

    try:
        created = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={
                "target": "example.com",
                "modules": ["http_probe"],
                "profile": "safe",
                "extra_headers_text": "X-Test-Header: enabled",
                "cookies": "session=abc123",
                "host_header": "virtual.example",
                "auto_start": False,
            },
        )
        run_id = str(created["run"]["run_id"])
        connection = connect(tmp_path / "runs" / run_id / "state.db")
        try:
            insert_finding(
                connection,
                Finding(
                    finding_id="seed-subdomain-app-example",
                    run_id=run_id,
                    task_id=None,
                    module="subdomain_enum",
                    target="app.example",
                    summary="Seed host for probing",
                    evidence_json={"hostname": "app.example"},
                    tags=["subdomain"],
                    created_at=datetime.now(UTC),
                ),
            )
        finally:
            connection.close()

        result = execute_http_probe_tasks(run_id, workspace=tmp_path)
        assert result["completed_task_count"] == 1
        assert any(part == "-H" for part in captured_commands[-1])
        assert any("User-Agent:" in part for part in captured_commands[-1])
        assert any("X-Test-Header: enabled" == part for part in captured_commands[-1])
        assert any("Cookie: session=abc123" == part for part in captured_commands[-1])
        assert any("Host: virtual.example" == part for part in captured_commands[-1])

        view = _request_json(base_url, f"/api/runs/{run_id}")
        finding = view["report"]["sections"]["http_probe_results"][0]
        assert finding["evidence"]["type"] == "http_probe"
        assert finding["evidence"]["technologies"] == ["nginx", "php", "wordpress"]
        assert finding["evidence"]["metadata_json"]["technologies"] == ["nginx", "php", "wordpress"]
        assert finding["evidence"]["metadata_json"]["technology_source"] == "httpx+wappalyzer"
        assert finding["evidence"]["auth_detection"]["auth_state"] == "auth_required"
        assert finding["evidence"]["auth_detection"]["likely_auth_required"] is True
        assert finding["evidence"]["request_headers"]["has_cookie"] is True
        assert "auth-required" in finding["tags"]
    finally:
        handle.close()


def test_dirscan_reduces_repeated_login_gate_results_and_tracks_strategy(tmp_path: Path, monkeypatch) -> None:
    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"
    captured_commands: list[list[str]] = []

    def fake_ffuf_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        captured_commands.append(command)
        output_path = Path(command[command.index("-o") + 1])
        wordlist_path = Path(command[command.index("-w") + 1])
        if wordlist_path.name == "canary.txt":
            results = [
                {
                    "url": f"http://app.example/{index}",
                    "status": 200,
                    "length": 5120,
                    "words": 400,
                    "lines": 80,
                    "content-type": "text/html",
                    "input": {"FUZZ": f"canary-{index}"},
                }
                for index in range(20)
            ]
        else:
            results = [
                {
                    "url": f"http://app.example/path-{index}",
                    "status": 200,
                    "length": 4096,
                    "words": 300,
                    "lines": 60,
                    "content-type": "text/html",
                    "input": {"FUZZ": f"path-{index}"},
                }
                for index in range(5)
            ]
        output_path.write_text(json.dumps({"results": results}), encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr("scanner.adapters.ffuf_runner._default_runner", fake_ffuf_runner)

    try:
        wordlist_path = tmp_path / "test.txt"
        wordlist_path.write_text("admin\nlogin\nportal\n", encoding="utf-8")
        created = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={
                "target": "example.com",
                "modules": ["dir_enum"],
                "profile": "safe",
                "ffuf_wordlist_path": str(wordlist_path),
                "ffuf_replay_proxy": "127.0.0.1:8080",
                "extra_headers_text": "X-Test-Header: enabled",
                "auto_start": False,
            },
        )
        run_id = str(created["run"]["run_id"])
        connection = connect(tmp_path / "runs" / run_id / "state.db")
        try:
            insert_finding(
                connection,
                Finding(
                    finding_id="seed-http-probe-app-example",
                    run_id=run_id,
                    task_id=None,
                    module="http_probe",
                    target="app.example",
                    summary="Auth-gated host",
                    evidence_json={
                        "url": "http://app.example/",
                        "host": "app.example",
                        "path": "/",
                        "status_code": 401,
                        "auth_detection": {
                            "auth_state": "auth_required",
                            "likely_auth_required": True,
                            "signals": ["http_401"],
                        },
                    },
                    tags=["httpx", "alive", "host"],
                    created_at=datetime.now(UTC),
                ),
            )
        finally:
            connection.close()

        result = execute_dir_enum_tasks(run_id, workspace=tmp_path)
        assert result["completed_task_count"] == 1
        assert any(part == "-replay-proxy" for part in captured_commands[-1])
        assert any("http://127.0.0.1:8080" == part for part in captured_commands[-1])
        assert any(part == "-H" for part in captured_commands[-1])
        assert any("X-Test-Header: enabled" == part for part in captured_commands[-1])
        assert not any("Chrome/145.0.0.0" in part for part in captured_commands[-1])

        view = _request_json(base_url, f"/api/runs/{run_id}")
        dirscan_findings = view["report"]["sections"]["directory_findings"]
        assert len(dirscan_findings) == 5
        calibration = view["tasks"][0]["cursor_json"]["calibrations"][0]
        assert calibration["dirscan_strategy"] == "auth-limited"
        assert calibration["login_gate_filter"]["applied"] is True
        assert calibration["login_gate_filter"]["filtered_match_count"] == 4
    finally:
        handle.close()


def test_web_ui_exposes_artifacts_and_execution_notes(tmp_path: Path) -> None:
    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"
    now = datetime(2026, 4, 10, 10, 0, tzinfo=UTC)

    try:
        created = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={
                "target": "example.internal",
                "modules": ["dir_enum"],
                "profile": "safe",
                "auto_start": False,
            },
        )
        run_id = str(created["run"]["run_id"])
        task_id = str(created["tasks"][0]["task_id"])
        state_db_path = tmp_path / "runs" / run_id / "state.db"
        connection = connect(state_db_path)
        try:
            connection.execute(
                """
                UPDATE tasks
                SET cursor_json = ?
                WHERE task_id = ?
                """,
                (
                    json.dumps(
                        {
                            "calibrations": [
                                {
                                    "base_url": "http://127.0.0.1:3000",
                                    "filter_sizes": [75002],
                                    "decision": "auto_filter",
                                }
                            ],
                            "confirmation_required_targets": [
                                {
                                    "base_url": "http://127.0.0.1:3001",
                                    "decision": "confirmation_required",
                                }
                            ],
                            "stage": "ffuf_scan",
                            "input_count": 3,
                            "scan_count": 1,
                        }
                    ),
                    task_id,
                ),
            )
            insert_finding(
                connection,
                Finding(
                    finding_id="finding-web-1",
                    run_id=run_id,
                    task_id=task_id,
                    module="cve_match",
                    target="example.internal:tcp/80",
                    status="candidate",
                    summary="Candidate CVE rendered in web view",
                    evidence_json={"cve_id": "CVE-2021-1234", "candidate_only": True},
                    tags=["candidate", "cve"],
                    created_at=now,
                ),
            )
            insert_artifact(
                connection,
                ArtifactRef(
                    artifact_id="artifact-web-1",
                    run_id=run_id,
                    task_id=task_id,
                    phase_name="dir_enum",
                    source_tool="ffuf",
                    artifact_type="raw_json",
                    path=tmp_path / "runs" / run_id / "artifacts" / "ffuf" / "task.json",
                    sha256="abc123",
                    size_bytes=42,
                    content_type="application/json",
                    created_at=now,
                    metadata={"base_url": "http://127.0.0.1:3000"},
                ),
            )
            connection.commit()
        finally:
            connection.close()

        view = _request_json(base_url, f"/api/runs/{run_id}")
        assert view["execution_notes"]["confirmation_required_targets"][0]["base_url"] == "http://127.0.0.1:3001"
        assert view["execution_notes"]["calibrations"][0]["filter_sizes"] == [75002]
        assert view["report"]["artifacts"]["total"] == 1
        assert view["report"]["sections"]["candidate_cves"][0]["summary"] == "Candidate CVE rendered in web view"
        host_groups = {item["host"]: item for item in view["report"]["host_groups"]}
        assert host_groups["example.internal"]["candidate_cve_count"] == 1
        assert host_groups["127.0.0.1"]["artifacts"][0]["tool"] == "ffuf"
        assert view["progress"]["tasks"][0]["current_phase"] == "ffuf_scan"
        assert view["progress"]["tasks"][0]["total_targets"] == 3
        assert view["progress"]["tasks"][0]["processed_count"] == 1
    finally:
        handle.close()


def test_web_ui_sorts_execution_notes_for_stable_display(tmp_path: Path) -> None:
    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"

    try:
        created = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={
                "target": "notes.example",
                "modules": ["dir_enum"],
                "profile": "safe",
                "auto_start": False,
            },
        )
        run_id = str(created["run"]["run_id"])
        task_id = str(created["tasks"][0]["task_id"])
        db_path = tmp_path / "runs" / run_id / "state.db"
        connection = sqlite3.connect(db_path)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute(
                """
                UPDATE tasks
                SET cursor_json = ?
                WHERE task_id = ?
                """,
                (
                    json.dumps(
                        {
                            "calibrations": [
                                {"base_url": "https://z.example/", "filter_sizes": [10]},
                                {"base_url": "https://a.example/", "filter_sizes": [20]},
                            ],
                            "confirmation_required_targets": [
                                {"base_url": "https://y.example/", "reason": "ambiguous"},
                                {"base_url": "https://b.example/", "reason": "ambiguous"},
                            ],
                        }
                    ),
                    task_id,
                ),
            )
            connection.commit()
        finally:
            connection.close()

        view = _request_json(base_url, f"/api/runs/{run_id}")

        assert [item["base_url"] for item in view["execution_notes"]["calibrations"]] == [
            "https://a.example/",
            "https://z.example/",
        ]
        assert [
            item["base_url"] for item in view["execution_notes"]["confirmation_required_targets"]
        ] == [
            "https://b.example/",
            "https://y.example/",
        ]
    finally:
        handle.close()


def test_web_ui_can_cancel_running_execution(tmp_path: Path, monkeypatch) -> None:
    calls: list[str] = []

    def fake_http_probe(run_id: str, *, workspace: Path | None = None) -> dict[str, Any]:
        calls.append(run_id)
        time.sleep(0.3)
        return {"run_id": run_id, "processed_task_count": 1}

    monkeypatch.setattr("scanner.web.execute_http_probe_tasks", fake_http_probe)
    monkeypatch.setitem(web_module.MODULE_EXECUTORS, "http_probe", fake_http_probe)

    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"
    try:
        created = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={
                "target": "example.cancel",
                "modules": ["http_probe"],
                "profile": "safe",
                "auto_start": False,
            },
        )
        run_id = str(created["run"]["run_id"])

        _request_json(
            base_url,
            f"/api/runs/{run_id}/execute",
            method="POST",
            payload={"module": "http_probe"},
        )
        cancelled = _request_json(
            base_url,
            f"/api/runs/{run_id}/cancel",
            method="POST",
            payload={},
        )

        assert cancelled["cancel"]["status"] == "cancelled"
        assert cancelled["cancel"]["cancelled_task_count"] == 1

        for _ in range(20):
            view = _request_json(base_url, f"/api/runs/{run_id}")
            if not view["execution"]["active"]:
                break
            time.sleep(0.05)
        else:
            raise AssertionError("execution did not stop in time")

        final_view = _request_json(base_url, f"/api/runs/{run_id}")
        assert final_view["run"]["status"] == "cancelled"
        assert final_view["task_counts"]["cancelled"] == 1
        logs = _request_json(base_url, f"/api/runs/{run_id}/logs")
        messages = [item["message"] for item in logs["items"]]
        assert "Cancellation requested" in messages
        assert calls == [run_id]
    finally:
        handle.close()


def test_web_ui_can_handle_missing_wordlist(tmp_path: Path) -> None:
    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"

    try:
        # Saving a missing wordlist should now be allowed (manual fallback)
        missing_path = tmp_path / "missing.txt"
        _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={
                "target": "example.net",
                "modules": ["http_probe"],
                "profile": "safe",
                "ffuf_wordlist_path": str(missing_path),
                "auto_start": False,
            },
        )
    finally:
        handle.close()




def test_web_ui_scope_filters_subdomain_results(tmp_path: Path, monkeypatch) -> None:
    def fake_subfinder(root_domain: str, *, subfinder_bin: str = "subfinder", runner=None) -> SubfinderRunResult:
        return SubfinderRunResult(
            command=[subfinder_bin, "-silent", "-d", root_domain],
            root_domain=root_domain,
            hosts=["www.example.com", "dev.example.com", "api.dev.example.com"],
            raw_output="www.example.com\ndev.example.com\napi.dev.example.com\n",
        )

    def fake_assetfinder(root_domain: str, *, assetfinder_bin: str = "assetfinder", runner=None) -> AssetfinderRunResult:
        return AssetfinderRunResult(
            command=[assetfinder_bin, "--subs-only", root_domain],
            root_domain=root_domain,
            hosts=[],
            raw_output="",
        )

    monkeypatch.setattr("scanner.execution.subdomain.run_subfinder_discovery", fake_subfinder)
    monkeypatch.setattr("scanner.execution.subdomain.run_assetfinder_discovery", fake_assetfinder)
    monkeypatch.setattr(
        "scanner.execution.subdomain.run_subzy_takeover_check",
        lambda hostnames, *, config, run_id, task_id: [],
    )
    def _no_dnsx(*args, **kwargs):
        raise RuntimeError("dnsx disabled in test")
    monkeypatch.setattr("scanner.execution.subdomain._run_dnsx_source", _no_dnsx)

    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"
    try:
        created = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={
                "target": "example.com",
                "modules": ["subdomain_enum"],
                "profile": "safe",
                "scope_exclude": "dev.example.com",
                "auto_start": False,
            },
        )
        run_id = str(created["run"]["run_id"])

        _request_json(
            base_url,
            f"/api/runs/{run_id}/execute",
            method="POST",
            payload={"module": "subdomain_enum"},
        )
        view = _wait_for_execution(base_url, run_id)

        subdomains = [item["target"] for item in view["report"]["sections"]["subdomains"]]
        assert subdomains == ["www.example.com"]
        cursor_json = view["tasks"][0]["cursor_json"]
        assert cursor_json["scope_skipped_targets"] == ["api.dev.example.com", "dev.example.com"]
        assert cursor_json["scope_allowed_count"] == 1
        assert cursor_json["scope_input_count"] == 3
    finally:
        handle.close()


def test_web_ui_scope_filters_http_probe_inputs(tmp_path: Path, monkeypatch) -> None:
    captured_targets: list[list[str]] = []

    def fake_httpx_probe(
        targets: list[str],
        *,
        httpx_bin: str = "httpx",
        profile: str = "safe",
        timeout_seconds: int = 10,
        threads: int = 10,
        rate_limit_per_second: int | None = None,
    ) -> HttpxRunResult:
        captured_targets.append(list(targets))
        return HttpxRunResult(
            command=[httpx_bin, "-json"],
            targets=list(targets),
            entries=[
                HttpxProbeResult(
                    input_target="app.example.com",
                    url="https://app.example.com/",
                    host="app.example.com",
                    path="/",
                    scheme="https",
                    port=443,
                    status_code=200,
                    title="App",
                    technologies=["nginx"],
                    content_type="text/html",
                    webserver="nginx",
                    ip="203.0.113.10",
                    cname=[],
                    probe_status="success",
                    raw_entry={"url": "https://app.example.com/"},
                )
            ],
            raw_output='{"input":"app.example.com","url":"https://app.example.com/"}\n',
        )

    monkeypatch.setattr("scanner.execution.http_probe.runner_core.run_httpx_probe", fake_httpx_probe)

    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"
    try:
        created = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={
                "target": "example.com",
                "modules": ["http_probe"],
                "profile": "safe",
                "scope_include": "app.example.com",
                "auto_start": False,
            },
        )
        run_id = str(created["run"]["run_id"])
        connection = connect(tmp_path / "runs" / run_id / "state.db")
        try:
            insert_finding(
                connection,
                Finding(
                    finding_id="finding-subdomain-app",
                    run_id=run_id,
                    task_id=None,
                    module="subdomain_enum",
                    target="app.example.com",
                    status="observed",
                    summary="app subdomain",
                    evidence_json={"hostname": "app.example.com"},
                    tags=["subdomain"],
                    created_at=datetime.now(UTC),
                ),
            )
            insert_finding(
                connection,
                Finding(
                    finding_id="finding-subdomain-admin",
                    run_id=run_id,
                    task_id=None,
                    module="subdomain_enum",
                    target="admin.example.com",
                    status="observed",
                    summary="admin subdomain",
                    evidence_json={"hostname": "admin.example.com"},
                    tags=["subdomain"],
                    created_at=datetime.now(UTC),
                ),
            )
        finally:
            connection.close()

        _request_json(
            base_url,
            f"/api/runs/{run_id}/execute",
            method="POST",
            payload={"module": "http_probe"},
        )
        view = _wait_for_execution(base_url, run_id)

        assert captured_targets == [["app.example.com"]]
        cursor_json = view["tasks"][0]["cursor_json"]
        assert cursor_json["scope_input_count"] == 2
        assert cursor_json["scope_allowed_count"] == 1
        assert cursor_json["scope_skipped_targets"] == ["admin.example.com"]
        assert view["progress"]["tasks"][0]["total_targets"] == 1
    finally:
        handle.close()


def test_web_ui_scope_preserves_host_port_for_http_probe(tmp_path: Path, monkeypatch) -> None:
    captured_targets: list[list[str]] = []

    def fake_httpx_probe(
        targets: list[str],
        *,
        httpx_bin: str = "httpx",
        profile: str = "safe",
        timeout_seconds: int = 10,
        threads: int = 10,
        rate_limit_per_second: int | None = None,
    ) -> HttpxRunResult:
        captured_targets.append(list(targets))
        return HttpxRunResult(
            command=[httpx_bin, "-json"],
            targets=list(targets),
            entries=[
                HttpxProbeResult(
                    input_target="127.0.0.1:3000",
                    url="http://127.0.0.1:3000/",
                    host="127.0.0.1",
                    path="/",
                    scheme="http",
                    port=3000,
                    status_code=200,
                    title="OWASP Juice Shop",
                    technologies=["Angular"],
                    content_type="text/html",
                    webserver=None,
                    ip="127.0.0.1",
                    cname=[],
                    probe_status="success",
                    raw_entry={"url": "http://127.0.0.1:3000/"},
                )
            ],
            raw_output='{"input":"127.0.0.1:3000","url":"http://127.0.0.1:3000/"}\n',
        )

    monkeypatch.setattr("scanner.execution.http_probe.runner_core.run_httpx_probe", fake_httpx_probe)

    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"
    try:
        created = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={
                "target": "local-lab",
                "modules": ["http_probe"],
                "profile": "safe",
                "scope_include": "127.0.0.1",
                "auto_start": False,
            },
        )
        run_id = str(created["run"]["run_id"])
        connection = connect(tmp_path / "runs" / run_id / "state.db")
        try:
            insert_finding(
                connection,
                Finding(
                    finding_id="finding-subdomain-local-port",
                    run_id=run_id,
                    task_id=None,
                    module="subdomain_enum",
                    target="127.0.0.1:3000",
                    status="observed",
                    summary="local lab with explicit port",
                    evidence_json={"hostname": "127.0.0.1", "url": "http://127.0.0.1:3000/"},
                    tags=["subdomain", "seed"],
                    created_at=datetime.now(UTC),
                ),
            )
        finally:
            connection.close()

        _request_json(
            base_url,
            f"/api/runs/{run_id}/execute",
            method="POST",
            payload={"module": "http_probe"},
        )
        view = _wait_for_execution(base_url, run_id)

        assert captured_targets == [["127.0.0.1:3000"]]
        cursor_json = view["tasks"][0]["cursor_json"]
        assert cursor_json["scope_input_count"] == 1
        assert cursor_json["scope_allowed_count"] == 1
        assert cursor_json["scope_skipped_targets"] == []
    finally:
        handle.close()


def test_web_ui_scope_filters_dirscan_and_records_skipped_targets(tmp_path: Path, monkeypatch) -> None:
    ffuf_calls: list[str] = []

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
    ) -> FfufRunResult:
        ffuf_calls.append(base_url)
        if not auto_calibration:
            matches = [
                FfufResultEntry(
                    url=f"{base_url.rstrip('/')}/__canary__{index}",
                    status_code=200,
                    length=75002,
                    words=1200,
                    lines=500,
                    content_type="text/html",
                    redirect_target=None,
                    host="keep.example.com",
                    input_value=f"__canary__{index}",
                    position=index,
                    raw_entry={},
                )
                for index in range(20)
            ]
            return FfufRunResult(
                command=[ffuf_bin, "-of", "json"],
                base_url=base_url,
                output_path=output_path,
                matches=matches,
                raw_output='{"results":[]}',
            )
        return FfufRunResult(
            command=[ffuf_bin, "-of", "json"],
            base_url=base_url,
            output_path=output_path,
            matches=[],
            raw_output='{"results":[]}',
        )

    monkeypatch.setattr("scanner.execution.dirscan.runner_core.run_ffuf_scan", fake_ffuf_scan)

    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"
    try:
        wordlist_path = tmp_path / "words.txt"
        wordlist_path.write_text("admin\n", encoding="utf-8")
        created = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={
                "target": "example.com",
                "modules": ["dir_enum"],
                "profile": "safe",
                "ffuf_wordlist_path": str(wordlist_path),
                "scope_exclude": "skip.example.com",
                "auto_start": False,
            },
        )
        run_id = str(created["run"]["run_id"])
        connection = connect(tmp_path / "runs" / run_id / "state.db")
        try:
            for host in ("keep.example.com", "skip.example.com"):
                insert_finding(
                    connection,
                    Finding(
                        finding_id=f"finding-http-{host}",
                        run_id=run_id,
                        task_id=None,
                        module="http_probe",
                        target=host,
                        status="observed",
                        summary=f"live host {host}",
                        evidence_json={"url": f"http://{host}/", "host": host, "source_tool": "httpx"},
                        tags=["httpx", "alive", "host"],
                        created_at=datetime.now(UTC),
                    ),
                )
        finally:
            connection.close()

        _request_json(
            base_url,
            f"/api/runs/{run_id}/execute",
            method="POST",
            payload={"module": "dir_enum"},
        )
        view = _wait_for_execution(base_url, run_id)

        assert all("skip.example.com" not in call for call in ffuf_calls)
        assert any("keep.example.com" in call for call in ffuf_calls)
        cursor_json = view["tasks"][0]["cursor_json"]
        assert cursor_json["scope_skipped_targets"] == ["http://skip.example.com/"]
        assert cursor_json["scope_allowed_count"] == 1
    finally:
        handle.close()


def test_web_ui_scope_filters_port_scan_inputs(tmp_path: Path, monkeypatch) -> None:
    captured_targets: list[list[str]] = []

    def fake_nmap_scan(
        targets: list[str],
        *,
        nmap_bin: str = "nmap",
        profile: str = "safe",
        ports: str = "1-1024",
        timing_template: str = "T3",
        version_detection: bool = True,
    ) -> NmapRunResult:
        captured_targets.append(list(targets))
        return NmapRunResult(
            command=[nmap_bin, "-oX", "-"],
            targets=list(targets),
            hosts=[],
            raw_output="<nmaprun />",
        )

    monkeypatch.setattr("scanner.execution.portscan.runner_core.run_nmap_scan", fake_nmap_scan)

    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"
    try:
        created = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={
                "target": "keep.example.com",
                "modules": ["port_scan"],
                "profile": "safe",
                "scope_include": "keep.example.com",
                "auto_start": False,
            },
        )
        run_id = str(created["run"]["run_id"])
        connection = connect(tmp_path / "runs" / run_id / "state.db")
        try:
            insert_finding(
                connection,
                Finding(
                    finding_id="finding-subdomain-keep-port",
                    run_id=run_id,
                    task_id=None,
                    module="subdomain_enum",
                    target="keep.example.com:8443",
                    status="observed",
                    summary="subdomain keep.example.com:8443",
                    evidence_json={"hostname": "keep.example.com"},
                    tags=["subdomain"],
                    created_at=datetime.now(UTC),
                ),
            )
            insert_finding(
                connection,
                Finding(
                    finding_id="finding-http-keep",
                    run_id=run_id,
                    task_id=None,
                    module="http_probe",
                    target="keep.example.com",
                    status="observed",
                    summary="live host keep.example.com",
                    evidence_json={"host": "keep.example.com", "url": "https://keep.example.com/"},
                    tags=["httpx", "alive", "host"],
                    created_at=datetime.now(UTC),
                ),
            )
            insert_finding(
                connection,
                Finding(
                    finding_id="finding-subdomain-skip",
                    run_id=run_id,
                    task_id=None,
                    module="subdomain_enum",
                    target="skip.example.com",
                    status="observed",
                    summary="subdomain skip.example.com",
                    evidence_json={"hostname": "skip.example.com"},
                    tags=["subdomain"],
                    created_at=datetime.now(UTC),
                ),
            )
        finally:
            connection.close()

        _request_json(
            base_url,
            f"/api/runs/{run_id}/execute",
            method="POST",
            payload={"module": "port_scan"},
        )
        view = _wait_for_execution(base_url, run_id)

        assert captured_targets == [["keep.example.com"]]
        cursor_json = view["tasks"][0]["cursor_json"]
        assert cursor_json["scope_input_count"] == 3
        assert cursor_json["scope_allowed_count"] == 1
        assert cursor_json["scope_skipped_targets"] == ["skip.example.com"]
    finally:
        handle.close()


def test_web_ui_shows_tech_aware_execution_notes(tmp_path: Path) -> None:
    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"

    try:
        created = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={
                "target": "tech.example",
                "modules": ["dir_enum"],
                "profile": "safe",
                "auto_start": False,
            },
        )
        run_id = str(created["run"]["run_id"])
        task_id = str(created["tasks"][0]["task_id"])
        state_db_path = tmp_path / "runs" / run_id / "state.db"
        connection = connect(state_db_path)
        try:
            connection.execute(
                """
                UPDATE tasks
                SET cursor_json = ?
                WHERE task_id = ?
                """,
                (
                    json.dumps(
                        {
                            "calibrations": [
                                {
                                    "base_url": "http://php.tech.example/",
                                    "derived_extensions": [".php"],
                                    "tech_evidence": ["PHP"],
                                    "using_default_extensions": False,
                                }
                            ],
                            "stage": "completed",
                        }
                    ),
                    task_id,
                ),
            )
            connection.commit()
        finally:
            connection.close()

        view = _request_json(base_url, f"/api/runs/{run_id}")
        notes = view["execution_notes"]["calibrations"][0]
        assert notes["base_url"] == "http://php.tech.example/"
        assert notes["derived_extensions"] == [".php"]
        assert notes["tech_evidence"] == ["PHP"]

        # Verify HTML report contains the notes
        with urlopen(f"{base_url}/api/runs/{run_id}/report.html", timeout=10) as response:  # noqa: S310
            report_html = response.read().decode("utf-8")
        assert "Scanning Intelligence / Tech Notes" in report_html
        assert "extensions:" in report_html.lower()
        assert ".php" in report_html.lower()
        assert "based on tech:" in report_html.lower()
        assert "php" in report_html.lower()
    finally:
        handle.close()


def test_web_ui_shows_tech_aware_parallel_progress(tmp_path: Path) -> None:
    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"
    try:
        created = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={
                "target": "parallel.example",
                "modules": ["dir_enum"],
                "profile": "safe",
                "auto_start": False,
            },
        )
        run_id = str(created["run"]["run_id"])
        task_id = str(created["tasks"][0]["task_id"])

        # Manually set some execution notes with target counts
        db_path = tmp_path / "runs" / run_id / "state.db"
        connection = sqlite3.connect(db_path)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute(
                """
                UPDATE tasks
                SET cursor_json = ?
                WHERE task_id = ?
                """,
                (
                    json.dumps(
                        {
                            "total_targets": 10,
                            "queued_targets": 5,
                            "running_targets": 2,
                            "completed_targets": 3,
                            "stage": "ffuf_scan",
                        }
                    ),
                    task_id,
                ),
            )
            connection.commit()
        finally:
            connection.close()

        view = _request_json(base_url, f"/api/runs/{run_id}")
        # Find the dir_enum task in the view
        dir_task = next(t for t in view["tasks"] if t["module"] == "dir_enum")
        progress = dir_task["progress"]
        
        assert progress["total_targets"] == 10
        assert progress["queued_count"] == 5
        assert progress["running_count"] == 2
        assert progress["completed_count"] == 3
    finally:
        handle.close()


def test_web_api_enhanced_wordlists(tmp_path: Path) -> None:
    wordlists_dir = tmp_path / "wordlists"
    wordlists_dir.mkdir()
    
    # 1. Nested paths and extension filtering
    sub_dir = wordlists_dir / "sub"
    sub_dir.mkdir()
    (sub_dir / "list.lst").write_text("a\n", encoding="utf-8")
    (wordlists_dir / "top.txt").write_text("b\n", encoding="utf-8")
    (wordlists_dir / "README.md").write_text("skip", encoding="utf-8")
    seclists_nested = wordlists_dir / "SecLists-master" / "Discovery" / "Web-Content"
    seclists_nested.mkdir(parents=True)
    (seclists_nested / "raft-small-directories.txt").write_text("c\n", encoding="utf-8")

    handle = web_module.start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"
    try:
        # Check API discovery
        # (Assuming the list is sorted by name in list_wordlists already, but we sort here to be safe)
        data = _request_json(base_url, "/api/wordlists")
        # our glob uses sorted() so it should be deterministic
        # rglob handles nesting
        raft_rel = Path("SecLists-master") / "Discovery" / "Web-Content" / "raft-small-directories.txt"
        assert sorted(data["wordlists"]) == sorted(
            [
                f"wordlists/{Path('sub/list.lst').as_posix()}",
                "wordlists/top.txt",
                f"wordlists/{raft_rel.as_posix()}",
            ]
        )
        assert len(data["wordlist_entries"]) == 3
        by_path = {e["path"]: e["label"] for e in data["wordlist_entries"]}
        assert set(by_path) == set(data["wordlists"])
        for p, lbl in by_path.items():
            norm = p.replace("\\", "/")
            if "SecLists-master" in norm:
                assert lbl == "Discovery/Web-Content/raft-small-directories.txt"
            else:
                assert norm.startswith("wordlists/")
                assert lbl == norm[len("wordlists/") :]
        for e in data["wordlist_entries"]:
            assert "size_bytes" in e
            assert "size_human" in e
            assert "line_count" in e
            assert "lines_human" in e
            assert e["line_count"] >= 1
        assert isinstance(data.get("wordlist_bundle"), list)
        assert data["wordlist_bundle"] == []
        assert isinstance(data.get("recommended_presets"), list)
        assert "default_extra_headers_text" in data
        assert "User-Agent:" in data["default_extra_headers_text"]

        # 2. Missing wordlist persistence (API level)
        missing_path = "wordlists/NON_EXISTENT.txt"
        created = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={
                "target": "example.com",
                "modules": ["http_probe"],
                "ffuf_wordlist_path": missing_path,
                "auto_start": False,
            },
        )
        assert created["run"]["config"]["ffuf_wordlist_path"] == str((tmp_path / missing_path).resolve())
        
        # Verify it stays in the view
        view = _request_json(base_url, f"/api/runs/{created['run']['run_id']}")
        assert view["run"]["config"]["ffuf_wordlist_path"] == str((tmp_path / missing_path).resolve())
    finally:
        handle.close()


def test_web_api_workspace_settings_profiles_tools_and_wordlist_edit(tmp_path: Path) -> None:
    wordlists_dir = tmp_path / "wordlists"
    wordlists_dir.mkdir()
    (wordlists_dir / "zzz.txt").write_text("z\n", encoding="utf-8")
    (wordlists_dir / "small.txt").write_text("small-one\nsmall-two\n", encoding="utf-8")
    (wordlists_dir / "test.txt").write_text("test-one\ntest-two\ntest-three\n", encoding="utf-8")

    handle = web_module.start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"
    try:
        wordlists = _request_json(base_url, "/api/wordlists")
        assert wordlists["wordlists"][:2] == ["wordlists/test.txt", "wordlists/small.txt"]
        top_entries = wordlists["wordlist_entries"][:2]
        assert [entry["line_count"] for entry in top_entries] == [3, 2]
        assert all(entry["editable"] for entry in top_entries)

        file_payload = _request_json(base_url, "/api/wordlists/file?path=wordlists/test.txt")
        assert file_payload["content"] == "test-one\ntest-two\ntest-three\n"
        updated_file = _request_json(
            base_url,
            "/api/wordlists/file",
            method="PATCH",
            payload={"path": "wordlists/test.txt", "content": "alpha\nbeta\n"},
        )
        assert updated_file["line_count"] == 2
        assert (wordlists_dir / "test.txt").read_text(encoding="utf-8") == "alpha\nbeta\n"

        configured_nmap = "C:/custom-tools/nmap.exe"
        settings = _request_json(
            base_url,
            "/api/settings",
            method="PATCH",
            payload={
                "defaults": {
                    "scan_mode": "fast",
                    "nmap_ports": "80,443",
                    "ffuf_wordlist_path": "wordlists/small.txt",
                },
                "tool_paths": {"nmap": configured_nmap},
            },
        )
        assert settings["settings"]["defaults"]["nmap_ports"] == "80,443"
        assert settings["settings"]["tool_paths"]["nmap"] == configured_nmap
        nmap_tool = next(tool for tool in settings["tools"] if tool["name"] == "nmap")
        assert nmap_tool["configured_path"] == configured_nmap
        assert nmap_tool["custom"] is True

        created = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={"target": "127.0.0.1", "modules": ["port_scan"], "auto_start": False},
        )
        created_config = created["run"]["config"]
        assert created_config["scan_mode"] == "fast"
        assert created_config["nmap_ports"] == "80,443"
        assert created_config["nmap_bin"] == configured_nmap
        assert created_config["ffuf_wordlist_path"] == str((wordlists_dir / "small.txt").resolve())

        profile_result = _request_json(
            base_url,
            "/api/profiles",
            method="POST",
            payload={
                "key": "personal_web",
                "label": "Personal Web",
                "description": "Custom web profile",
                "modules": ["http_probe", "dir_enum"],
                "profile": "balanced",
                "defaults": {"ffuf_threads": 7, "nmap_ports": "443"},
            },
        )
        assert profile_result["presets"]["personal_web"]["custom"] is True

        created_from_profile = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={"target": "example.com", "preset": "personal_web", "auto_start": False},
        )
        assert [task["module"] for task in created_from_profile["tasks"]] == ["http_probe", "dir_enum"]
        assert created_from_profile["run"]["config"]["ffuf_threads"] == 7
        assert created_from_profile["run"]["config"]["nmap_ports"] == "443"

        deleted = _request_json(base_url, "/api/profiles/personal_web", method="DELETE")
        assert "personal_web" not in deleted["presets"]
    finally:
        handle.close()

def test_web_api_empty_wordlists(tmp_path: Path) -> None:
    (tmp_path / "wordlists").mkdir(exist_ok=True)
    handle = web_module.start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"
    try:
        data = _request_json(base_url, "/api/wordlists")
        assert data["wordlists"] == []
        assert data["wordlist_entries"] == []
        assert data["wordlist_bundle"] == []
        assert data.get("recommended_presets") == []
    finally:
        handle.close()

def test_web_ui_host_view_groups_findings(tmp_path: Path) -> None:
    # This tests the backend data availability for host-centric grouping
    # Since the grouping happens in JS, we verify the backend still provides flat findings with target fields
    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"

    try:
        created = _request_json(base_url, "/api/runs", method="POST", payload={"target": "example.com", "modules": ["port_scan"]})
        run_id = created["run"]["run_id"]
        
        # Inject some findings for different hosts
        db_path = tmp_path / "runs" / run_id / "state.db"
        import sqlite3
        import json
        with sqlite3.connect(db_path) as conn:
            conn.execute("INSERT INTO findings (finding_id, run_id, module, target, status, summary, evidence_json) VALUES (?,?,?,?,?,?,?)",
                         ("f1", run_id, "port_scan", "1.2.3.4:80", "observed", "port 80 open", json.dumps({"state": "open"})))
            conn.execute("INSERT INTO findings (finding_id, run_id, module, target, status, summary, evidence_json) VALUES (?,?,?,?,?,?,?)",
                         ("f2", run_id, "port_scan", "1.2.3.5:443", "observed", "port 443 open", json.dumps({"state": "open"})))
            conn.execute("INSERT INTO findings (finding_id, run_id, module, target, status, summary, evidence_json) VALUES (?,?,?,?,?,?,?)",
                         ("f3", run_id, "http_probe", "http://1.2.3.4", "observed", "HTTP 200", json.dumps({"technologies": ["Nginx"]})))

        detail = _request_json(base_url, f"/api/runs/{run_id}")
        sections = detail["report"]["sections"]
        
        # Verify flat data structure is preserved for JS consumer
        assert len(sections["open_ports"]) == 2
        assert len(sections["http_probe_results"]) == 1
        
        # Verify we can find the targets to group on
        targets = [f["target"] for f in sections["open_ports"]]
        assert "1.2.3.4:80" in targets
        assert "1.2.3.5:443" in targets
        
    finally:
        handle.close()


def test_web_api_dir_enum_followup_rejects_unknown_run_id(tmp_path: Path) -> None:
    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"
    try:
        request = Request(
            f"{base_url}/api/runs/missing-run/dir-enum",
            data=json.dumps({"targets": [{"host": "127.0.0.1", "port": 80, "scheme": "http"}]}).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with pytest.raises(HTTPError) as exc:
            urlopen(request, timeout=10)  # noqa: S310
        assert exc.value.code == 404
    finally:
        handle.close()


def test_web_api_dir_enum_followup_rejects_non_web_target(tmp_path: Path) -> None:
    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"
    try:
        created = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={"target": "10.0.0.10", "modules": ["port_scan", "dir_enum"], "profile": "safe", "auto_start": False},
        )
        run_id = str(created["run"]["run_id"])
        task_id = next(t["task_id"] for t in created["tasks"] if t["module"] == "port_scan")
        connection = connect(tmp_path / "runs" / run_id / "state.db")
        try:
            insert_finding(
                connection,
                Finding(
                    finding_id="finding-port-ssh",
                    run_id=run_id,
                    task_id=task_id,
                    module="port_scan",
                    target="10.0.0.10:tcp/22",
                    summary="ssh open",
                    evidence_json={"host": "10.0.0.10", "port": 22, "protocol": "tcp", "service": "ssh", "state": "open"},
                    created_at=datetime.now(UTC),
                ),
            )
        finally:
            connection.close()
        request = Request(
            f"{base_url}/api/runs/{run_id}/dir-enum",
            data=json.dumps({"targets": [{"host": "10.0.0.10", "port": 22, "scheme": "http"}]}).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with pytest.raises(HTTPError) as exc:
            urlopen(request, timeout=10)  # noqa: S310
        assert exc.value.code == 400
        payload = json.loads(exc.value.read().decode("utf-8"))
        assert "Directory scan is only available for web services" in payload["error"]
    finally:
        handle.close()


def test_web_api_dir_enum_followup_queues_web_service_and_dedupes(tmp_path: Path) -> None:
    handle = start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    base_url = f"http://{handle.host}:{handle.port}"
    try:
        created = _request_json(
            base_url,
            "/api/runs",
            method="POST",
            payload={"target": "10.0.0.20", "modules": ["port_scan", "dir_enum"], "profile": "safe", "auto_start": False},
        )
        run_id = str(created["run"]["run_id"])
        task_id = next(t["task_id"] for t in created["tasks"] if t["module"] == "port_scan")
        connection = connect(tmp_path / "runs" / run_id / "state.db")
        try:
            insert_finding(
                connection,
                Finding(
                    finding_id="finding-port-http",
                    run_id=run_id,
                    task_id=task_id,
                    module="port_scan",
                    target="10.0.0.20:tcp/80",
                    summary="http open",
                    evidence_json={"host": "10.0.0.20", "port": 80, "protocol": "tcp", "service": "http", "state": "open"},
                    created_at=datetime.now(UTC),
                ),
            )
        finally:
            connection.close()

        first = _request_json(
            base_url,
            f"/api/runs/{run_id}/dir-enum",
            method="POST",
            payload={"targets": [{"host": "10.0.0.20", "port": 80, "scheme": "http", "base_url": "http://10.0.0.20/"}]},
        )
        assert first["queued"] == 1
        assert first["skipped"] == 0

        second = _request_json(
            base_url,
            f"/api/runs/{run_id}/dir-enum",
            method="POST",
            payload={"targets": [{"host": "10.0.0.20", "port": 80, "scheme": "http", "base_url": "http://10.0.0.20/"}]},
        )
        assert second["queued"] == 0
        assert second["skipped"] >= 1
        skipped = second["skipped_targets"]
        assert isinstance(skipped, list)
        assert skipped[0]["host"] == "10.0.0.20"
        assert int(skipped[0]["port"]) == 80
        assert skipped[0]["reason"] in {"already_scanned", "duplicate_pending"}
    finally:
        handle.close()
