"""
Live integration checks against a local HTTP server and real httpx / ffuf / nmap binaries.

Skips individual tests when the required tool is missing from PATH.
"""

from __future__ import annotations

import json
import shutil
import sys
import threading
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Generator

import pytest

from scanner.web import WebUIApp


def _which(name: str) -> str | None:
    return shutil.which(name)


def _prepare_workspace(base: Path) -> tuple[Path, Path]:
    wl = base / "wordlists"
    wl.mkdir(parents=True, exist_ok=True)
    (wl / "test.txt").write_text("admin\nindex\n", encoding="utf-8")
    www = base / "www"
    www.mkdir(parents=True, exist_ok=True)
    (www / "index.html").write_text("<html><body>ok</body></html>", encoding="utf-8")
    return wl / "test.txt", www


def _start_http_server(www: Path) -> tuple[ThreadingHTTPServer, int]:
    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, directory=str(www), **kwargs)

        def log_message(self, *_args: Any) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


def _wait_run_execution(app: WebUIApp, run_id: str, *, timeout: float = 180.0) -> dict[str, Any]:
    """Wait until the UI worker finishes and the run row reaches a terminal status."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        view = app.get_run_view(run_id)
        st = str(view["run"]["status"])
        if st in {"completed", "failed", "cancelled"}:
            return view
        if not app.execution_manager.is_active(run_id):
            time.sleep(0.35)
            view = app.get_run_view(run_id)
            st = str(view["run"]["status"])
            if st in {"completed", "failed", "cancelled"}:
                return view
            return view
        time.sleep(0.25)
    raise AssertionError(f"execution timeout for run_id={run_id!r}")


def _assert_no_failed_tasks(view: dict[str, Any]) -> None:
    tasks = view.get("tasks") or []
    failed = [t for t in tasks if str(t.get("state")) == "failed"]
    assert not failed, json.dumps(failed, indent=2, ensure_ascii=False)


@pytest.fixture
def local_http_url(tmp_path: Path) -> Generator[Callable[[], str], None, None]:
    _, www = _prepare_workspace(tmp_path)
    server, port = _start_http_server(www)

    # localtest.me resolves to 127.0.0.1 but classifies as domain so plan_enabled_phases
    # does not inject port_scan when only http_probe/dir_enum are requested.
    def url() -> str:
        return f"http://localtest.me:{port}/"

    yield url

    server.shutdown()
    server.server_close()


def test_live_http_probe_and_dir_enum_safe_balanced(tmp_path: Path, local_http_url: Callable[[], str]) -> None:
    if not _which("httpx") or not _which("ffuf"):
        pytest.skip("httpx and ffuf required on PATH")

    wl_path, _www = _prepare_workspace(tmp_path)
    base_url = local_http_url()

    app = WebUIApp(workspace=tmp_path)
    created = app.create_run(
        {
            "target": base_url,
            "modules": ["http_probe", "dir_enum"],
            "profile": "safe",
            "scan_mode": "balanced",
            "auto_start": True,
            "ffuf_wordlist_path": str(wl_path.resolve()),
            "nmap_ports": "80",
        }
    )
    rid = str(created["run"]["run_id"])
    view = _wait_run_execution(app, rid)
    assert str(view["run"]["status"]) == "completed"
    _assert_no_failed_tasks(view)


@pytest.mark.parametrize(
    "profile,scan_mode",
    [
        ("safe", "balanced"),
        ("balanced", "fast"),
        ("fast", "deep"),
    ],
)
def test_live_profile_scan_mode_combo(
    tmp_path: Path,
    local_http_url: Callable[[], str],
    profile: str,
    scan_mode: str,
) -> None:
    if not _which("httpx"):
        pytest.skip("httpx required on PATH")

    _, _www = _prepare_workspace(tmp_path)
    base_url = local_http_url()

    app = WebUIApp(workspace=tmp_path)
    created = app.create_run(
        {
            "target": base_url,
            "modules": ["http_probe"],
            "profile": profile,
            "scan_mode": scan_mode,
            "auto_start": True,
            "nmap_ports": "80",
        }
    )
    rid = str(created["run"]["run_id"])
    view = _wait_run_execution(app, rid)
    assert str(view["run"]["status"]) == "completed"
    _assert_no_failed_tasks(view)


def test_live_bulk_url_domain_and_cidr(tmp_path: Path, local_http_url: Callable[[], str]) -> None:
    """Multiple lines: HTTP seed + dummy domain label + /32 CIDR (scope merge)."""
    if sys.platform == "win32":
        pytest.skip("nmap default SYN scan needs raw sockets; skip mixed CIDR port_scan on Windows")
    if not _which("httpx") or not _which("nmap"):
        pytest.skip("httpx and nmap required on PATH")

    _, _www = _prepare_workspace(tmp_path)
    seed_url = local_http_url().rstrip("/")
    target_block = "\n".join([seed_url, "example.com", "127.0.0.1/32"])

    app = WebUIApp(workspace=tmp_path)
    created = app.create_run(
        {
            "target": target_block,
            "modules": ["http_probe", "port_scan"],
            "profile": "safe",
            "scan_mode": "balanced",
            "auto_start": True,
            "nmap_ports": "80",
        }
    )
    rid = str(created["run"]["run_id"])
    view = _wait_run_execution(app, rid)
    assert str(view["run"]["status"]) == "completed"
    _assert_no_failed_tasks(view)


def test_live_scope_exclude_blocks_localhost(tmp_path: Path, local_http_url: Callable[[], str]) -> None:
    if not _which("httpx"):
        pytest.skip("httpx required on PATH")

    _, _www = _prepare_workspace(tmp_path)
    base_url = local_http_url()

    app = WebUIApp(workspace=tmp_path)
    created = app.create_run(
        {
            "target": base_url,
            "modules": ["http_probe"],
            "profile": "safe",
            "scan_mode": "balanced",
            "scope_exclude": "localtest.me",
            "auto_start": True,
        }
    )
    rid = str(created["run"]["run_id"])
    view = _wait_run_execution(app, rid)
    assert str(view["run"]["status"]) == "completed"
    _assert_no_failed_tasks(view)
    http_tasks = [t for t in (view.get("tasks") or []) if str(t.get("module")) == "http_probe"]
    assert http_tasks
    cur = http_tasks[0].get("cursor_json") or {}
    assert int(cur.get("scope_skipped_count") or 0) >= 1


def test_live_ffuf_toggle_via_pending_config_patch(tmp_path: Path, local_http_url: Callable[[], str]) -> None:
    """Pending run: strip ffuf extensions then execute http_probe + dir_enum."""
    if not _which("httpx") or not _which("ffuf"):
        pytest.skip("httpx and ffuf required on PATH")

    wl_path, _www = _prepare_workspace(tmp_path)
    base_url = local_http_url()

    app = WebUIApp(workspace=tmp_path)
    created = app.create_run(
        {
            "target": base_url,
            "modules": ["http_probe", "dir_enum"],
            "profile": "balanced",
            "scan_mode": "balanced",
            "auto_start": False,
            "ffuf_wordlist_path": str(wl_path.resolve()),
            "ffuf_extensions": [".bak", ".old"],
        }
    )
    rid = str(created["run"]["run_id"])

    patched = app.update_run_config(rid, {"ffuf_extensions": []})
    assert patched["run"]["config"]["ffuf_extensions"] == []

    app.start_execution(rid, None)
    view = _wait_run_execution(app, rid)
    assert str(view["run"]["status"]) == "completed"
    _assert_no_failed_tasks(view)


def test_live_api_http_stack(tmp_path: Path, local_http_url: Callable[[], str]) -> None:
    """Same flow via Threading HTTP UI server + urllib JSON (production path)."""
    if not _which("httpx"):
        pytest.skip("httpx required on PATH")

    import scanner.web as web_module

    _, _www = _prepare_workspace(tmp_path)
    base_url_fn = local_http_url

    handle = web_module.start_ui_server(host="127.0.0.1", port=0, workspace=tmp_path)
    api = f"http://{handle.host}:{handle.port}"
    try:
        from urllib.request import Request, urlopen

        body = json.dumps(
            {
                "target": base_url_fn(),
                "modules": ["http_probe"],
                "profile": "fast",
                "scan_mode": "fast",
                "auto_start": True,
                "nmap_timing_template": "T4",
                "nmap_ports": "80",
            }
        ).encode()
        req = Request(f"{api}/api/runs", data=body, method="POST", headers={"Content-Type": "application/json"})
        with urlopen(req, timeout=30) as resp:
            created = json.loads(resp.read().decode())
        rid = str(created["run"]["run_id"])

        deadline = time.monotonic() + 120.0
        status = ""
        while time.monotonic() < deadline:
            req_g = Request(f"{api}/api/runs/{rid}")
            with urlopen(req_g, timeout=15) as resp:
                view = json.loads(resp.read().decode())
            status = str(view["run"]["status"])
            if status in {"completed", "failed"}:
                break
            time.sleep(0.35)
        assert status == "completed"
        tasks = view.get("tasks") or []
        assert not any(str(t.get("state")) == "failed" for t in tasks)
    finally:
        handle.close()
