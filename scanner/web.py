from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4
import json
import logging
import platform  # noqa: F401 - kept for test monkeypatch compatibility
import re
import sqlite3
import shutil  # noqa: F401 - kept for test monkeypatch compatibility
import subprocess
import threading
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from socketserver import TCPServer
from collections.abc import Sequence
from typing import Any, Protocol, cast
from urllib.parse import parse_qs, urlparse, urlsplit, urlunsplit

_log = logging.getLogger(__name__)

from scanner.config import (
    BROWSER_HEADER_DEFAULTS,
    classify_bulk_line,
    get_ui_run_presets,
    normalize_bulk_target_lines,
    parse_header_lines,
    parse_scope_entries,
    resolve_scope_controls_path,
    split_auth_header_fields,
)
from scanner.extension_recommendations import (
    EXTENSION_MAP,
    FFUF_EXTENSION_CATALOG,
    getRecommendedExtensions,
)
from scanner.utils.process import run_text_capture
from scanner.runner import (
    cancel_run,
    create_scan_run,
    enqueue_manual_dir_enum_targets,
    extend_scan_run,
    execute_ai_triage_tasks,
    execute_banner_probe_tasks,
    execute_dir_enum_tasks,
    execute_domain_discovery_tasks,
    execute_http_probe_tasks,
    execute_port_scan_tasks,
    execute_subdomain_enum_tasks,
    generate_run_diff,
    generate_report_summary,
    summarize_execution_notes,
    try_revive_resumable_cidr_port_scan,
)
from scanner.models import PhaseName, ScanConfig, TaskState
from scanner.web_responses import (
    write_html_response,
    write_json_response,
    write_redirect_response,
    write_text_response,
)
from scanner.state import get_run, get_tasks, mark_run_finished, summarize_task_progress
from scanner.storage import (
    connect,
    delete_service_note_by_id,
    fetch_service_note_by_id,
    insert_service_note,
    list_service_notes,
    update_service_note_text,
)
from scanner.scan_mode import apply_scan_mode_defaults, apply_scan_mode_to_modules, normalize_scan_mode
from scanner.web_assets import DASHBOARD_HTML
from scanner.web_execution import WebExecutionManager
from scanner.web_utils import resolve_default_binary_path
from scanner.web_views import display_run_name, format_run_target_display, get_run_view_data


def _parse_service_note_port(value: object) -> int:
    if isinstance(value, bool):
        raise ValueError("port must be an integer between 1 and 65535")
    try:
        port = int(cast(Any, value))
    except (TypeError, ValueError):
        raise ValueError("port must be an integer between 1 and 65535")
    if not 1 <= port <= 65535:
        raise ValueError("port must be an integer between 1 and 65535")
    return port


def _optional_clean_str(value: object) -> str | None:
    if value is None:
        return None
    s = str(value).strip()
    return s if s else None

MODULE_ORDER: tuple[str, ...] = (
    "subdomain_enum",
    "http_probe",
    "domain_discovery",
    "dir_enum",
    "port_scan",
    "banner_probe",
    "ai_triage",
)
PATCHABLE_CONFIG_FIELDS: tuple[str, ...] = (
    "profile",
    "ffuf_wordlist_path",
    "nmap_ports",
    "nmap_timing_template",
    "nmap_version_detection",
    "httpx_bin",
    "ffuf_bin",
    "nmap_bin",
    "subfinder_bin",
    "assetfinder_bin",
    "httpx_threads",
    "httpx_timeout_seconds",
    "http_probe_all_open_ports",
    "ffuf_threads",
    "ffuf_concurrency",
    "ffuf_parallel_enabled",
    "ffuf_max_parallel_tasks",
    "ffuf_replay_proxy",
    "ffuf_extensions",
    "auto_recommendation_enabled",
    "extra_headers",
    "dir_recursive_enabled",
    "dir_recursive_max_depth",
    "dir_recursive_max_paths_per_host",
    "dir_recursive_same_host_only",
    "cidr_split_enabled",
    "cidr_split_max_hosts_per_chunk",
    "cidr_split_target_interval_minutes",
    "cidr_split_min_prefix",
    "cidr_split_strategy",
    "cidr_split_adaptive_enabled",
    "cidr_resume_enabled",
    "scan_mode",
    "proxy_mode",
    "proxy_url",
    "masscan_enabled",
    "masscan_bin",
    "masscan_rate",
    "masscan_retries",
    "naabu_enabled",
    "naabu_bin",
    "naabu_rate",
    "naabu_retries",
    "naabu_scan_type",
    "dnsx_bin",
    "subdomain_bruteforce_enabled",
    "portscan_ip_dedup_enabled",
    "portscan_alive_filter_enabled",
    "portscan_alive_ping_ports",
    "portscan_dead_host_cache_enabled",
    "portscan_adaptive_rate_enabled",
    "nmap_nse_scripts_enabled",
    "nmap_nse_scripts",
    "nmap_host_timeout",
    "subzy_bin",
    "subzy_enabled",
    "gau_bin",
    "gau_enabled",
    "gau_max_urls_per_host",
    "tls_san_discovery_enabled",
    "udp_scan_enabled",
    "udp_scan_ports",
    "udp_scan_host_timeout_seconds",
    "js_render_enabled",
    "js_render_timeout_seconds",
    "js_render_max_hosts",
    "spa_crawl_enabled",
    "spa_crawl_max_depth",
    "spa_crawl_max_pages",
    "spa_crawl_same_origin_only",
    "auth_login_enabled",
    "auth_login_url",
    "auth_username",
    "auth_password",
    "auth_username_field_hints",
    "auth_password_field_hints",
    "auth_login_success_keyword",
    "access_control_test_enabled",
    "access_control_max_endpoints",
    "access_control_request_timeout_seconds",
)
RUNNING_SAFE_PATCH_FIELDS: frozenset[str] = frozenset(
    {
        "ffuf_concurrency",
        "ffuf_max_parallel_tasks",
        "ffuf_wordlist_path",
        "ffuf_extensions",
    }
)
SCOPE_CONTROL_FIELDS: tuple[str, ...] = ("scope_include", "scope_exclude")
TOOL_BINARY_FIELDS: tuple[tuple[str, str], ...] = (
    ("subfinder_bin", "subfinder"),
    ("assetfinder_bin", "assetfinder"),
    ("httpx_bin", "httpx"),
    ("ffuf_bin", "ffuf"),
    ("nmap_bin", "nmap"),
    ("masscan_bin", "masscan"),
    ("naabu_bin", "naabu"),
    ("dnsx_bin", "dnsx"),
    ("subzy_bin", "subzy"),
    ("gau_bin", "gau"),
)
TOOL_VERSION_ARGS: dict[str, tuple[str, ...]] = {
    "subfinder": ("-version",),
    "assetfinder": ("--help",),
    "httpx": ("-version",),
    "ffuf": ("-V",),
    "nmap": ("--version",),
    "masscan": ("--version",),
    "naabu": ("-version",),
    "dnsx": ("-version",),
    "subzy": ("--help",),
    "gau": ("--version",),
}
ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
WORKSPACE_SETTINGS_FILENAME = ".vantage-settings.json"
CUSTOM_PROFILE_KEY_RE = re.compile(r"^[a-zA-Z0-9_-]{1,48}$")
WORDLIST_EDITABLE_SUFFIXES = {".txt", ".lst"}


def _display_run_name(target: str, created_at: datetime) -> str:
    return display_run_name(target, created_at)


class PhaseExecutor(Protocol):
    def __call__(self, run_id: str, *, workspace: Path | None = None) -> dict[str, Any]: ...


class LocalThreadingHTTPServer(ThreadingHTTPServer):
    def server_bind(self) -> None:
        TCPServer.server_bind(self)
        self.server_name = str(self.server_address[0])
        self.server_port = int(self.server_address[1])


MODULE_EXECUTORS: dict[str, PhaseExecutor] = {
    "subdomain_enum": execute_subdomain_enum_tasks,
    "http_probe": execute_http_probe_tasks,
    "domain_discovery": execute_domain_discovery_tasks,
    "dir_enum": execute_dir_enum_tasks,
    "port_scan": execute_port_scan_tasks,
    "banner_probe": execute_banner_probe_tasks,
    "ai_triage": execute_ai_triage_tasks,
}


@dataclass(frozen=True)
class UIServerHandle:
    httpd: ThreadingHTTPServer
    thread: threading.Thread
    host: str
    port: int

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


class WebUIApp:
    def __init__(self, *, workspace: Path | None = None) -> None:
        self.workspace = (workspace or Path.cwd()).resolve()
        self.execution_manager = WebExecutionManager()

    def build_handler(self) -> type[BaseHTTPRequestHandler]:
        app = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                app.handle_request(self)

            def do_POST(self) -> None:  # noqa: N802
                app.handle_request(self)

            def do_DELETE(self) -> None:  # noqa: N802
                app.handle_request(self)

            def do_PATCH(self) -> None:  # noqa: N802
                app.handle_request(self)

            def log_message(self, format: str, *args: object) -> None:
                return

        return Handler

    def handle_request(self, handler: BaseHTTPRequestHandler) -> None:
        try:
            parsed = urlparse(handler.path)
            path_parts = [part for part in parsed.path.split("/") if part]
            if handler.command == "GET" and parsed.path == "/":
                self._redirect_response(handler, "/runs")
                return
            if handler.command == "GET" and parsed.path == "/execution":
                self._redirect_response(handler, "/runs?newScan=1")
                return
            if handler.command == "GET" and parsed.path == "/progress":
                self._redirect_response(handler, "/runs")
                return
            if handler.command == "GET" and parsed.path == "/results":
                self._redirect_response(handler, "/runs")
                return
            if handler.command == "GET" and len(path_parts) == 2 and path_parts[0] == "progress":
                self._redirect_response(handler, f"/runs/{path_parts[1]}/execution")
                return
            if handler.command == "GET" and len(path_parts) == 2 and path_parts[0] == "results":
                self._redirect_response(handler, f"/runs/{path_parts[1]}/summary")
                return
            if handler.command == "GET" and parsed.path == "/dashboard":
                self._redirect_response(handler, "/runs")
                return
            if handler.command == "GET" and parsed.path == "/runs/new":
                self._redirect_response(handler, "/runs?newScan=1")
                return
            if handler.command == "GET" and self._is_react_app_route(path_parts):
                self._serve_react_app(handler)
                return
            if handler.command == "GET" and path_parts == ["api", "runs"]:
                self._write_json(handler, {"runs": self.list_runs()})
                return
            if handler.command == "GET" and path_parts == ["api", "presets"]:
                self._write_json(handler, self.list_presets())
                return
            if handler.command == "GET" and path_parts == ["api", "settings"]:
                self._write_json(handler, self.get_settings())
                return
            if handler.command == "PATCH" and path_parts == ["api", "settings"]:
                payload = self._read_json(handler)
                self._write_json(handler, self.update_settings(payload))
                return
            if handler.command == "GET" and path_parts == ["api", "wordlists"]:
                self._write_json(handler, self.list_wordlists())
                return
            if handler.command == "GET" and path_parts == ["api", "wordlists", "file"]:
                query = parse_qs(parsed.query)
                wordlist_path = (query.get("path") or [""])[0]
                self._write_json(handler, self.get_wordlist_file(wordlist_path))
                return
            if handler.command == "PATCH" and path_parts == ["api", "wordlists", "file"]:
                payload = self._read_json(handler)
                self._write_json(handler, self.update_wordlist_file(payload))
                return
            if handler.command == "GET" and path_parts == ["api", "ffuf-extension-catalog"]:
                self._write_json(
                    handler,
                    {
                        "catalog": list(FFUF_EXTENSION_CATALOG),
                        "recommendation_map": {k: list(v) for k, v in EXTENSION_MAP.items()},
                    },
                )
                return
            if handler.command == "GET" and path_parts == ["api", "system", "tools"]:
                self._write_json(handler, self.list_tools())
                return
            if handler.command == "PATCH" and path_parts == ["api", "system", "tools"]:
                payload = self._read_json(handler)
                self._write_json(handler, self.update_tool_paths(payload))
                return
            if handler.command == "GET" and path_parts == ["api", "system", "tools", "install-status"]:
                self._write_json(handler, self.get_install_status())
                return
            if handler.command == "POST" and path_parts == ["api", "system", "tools", "install"]:
                payload = self._read_json(handler) if handler.headers.get("Content-Length") else {}
                self._write_json(handler, self.install_missing_tools(payload or {}))
                return
            if (
                handler.command == "POST"
                and len(path_parts) == 4
                and path_parts[:2] == ["api", "runs"]
                and path_parts[3] == "watchdog"
            ):
                run_id = path_parts[2]
                payload = self._read_json(handler) if handler.headers.get("Content-Length") else {}
                self._write_json(handler, self.start_watchdog(run_id, payload or {}))
                return
            if (
                handler.command == "DELETE"
                and len(path_parts) == 4
                and path_parts[:2] == ["api", "runs"]
                and path_parts[3] == "watchdog"
            ):
                run_id = path_parts[2]
                self._write_json(handler, self.stop_watchdog(run_id))
                return
            if (
                handler.command == "GET"
                and len(path_parts) == 4
                and path_parts[:2] == ["api", "runs"]
                and path_parts[3] == "watchdog"
            ):
                run_id = path_parts[2]
                self._write_json(handler, self.get_watchdog_status(run_id))
                return
            if handler.command == "POST" and path_parts == ["api", "profiles"]:
                payload = self._read_json(handler)
                self._write_json(handler, self.save_profile(payload), status=HTTPStatus.CREATED)
                return
            if handler.command == "DELETE" and len(path_parts) == 3 and path_parts[:2] == ["api", "profiles"]:
                self._write_json(handler, self.delete_profile(path_parts[2]))
                return
            if handler.command == "GET" and path_parts == ["api", "recommended-extensions"]:
                query = parse_qs(parsed.query)
                svc = (query.get("service") or [""])[0]
                tch = (query.get("tech") or [""])[0]
                exts = getRecommendedExtensions(svc, tch)
                self._write_json(handler, {"extensions": exts, "service": svc, "tech": tch})
                return
            if handler.command == "POST" and path_parts == ["api", "runs"]:
                payload = self._read_json(handler)
                result = self.create_run(payload)
                self._write_json(handler, result, status=HTTPStatus.CREATED)
                return
            if (
                len(path_parts) == 4
                and path_parts[:2] == ["api", "runs"]
                and path_parts[3] == "config"
                and handler.command in {"POST", "PATCH"}
            ):
                payload = self._read_json(handler)
                self._write_json(handler, self.update_run_config(path_parts[2], payload))
                return
            if (
                len(path_parts) == 4
                and path_parts[:2] == ["api", "runs"]
                and path_parts[3] == "clone-config"
                and handler.command == "GET"
            ):
                self._write_json(handler, self.get_clone_config(path_parts[2]))
                return
            if len(path_parts) == 3 and path_parts[:2] == ["api", "runs"] and handler.command == "GET":
                self._write_json(handler, self.get_run_view(path_parts[2]))
                return
            if len(path_parts) == 3 and path_parts[:2] == ["api", "runs"] and handler.command == "DELETE":
                self._write_json(handler, self.delete_run(path_parts[2]))
                return
            if (
                len(path_parts) == 4
                and path_parts[:2] == ["api", "runs"]
                and path_parts[3] == "diff"
                and handler.command == "GET"
            ):
                query = parse_qs(parsed.query)
                baseline_run_id = (query.get("baseline") or [""])[0]
                self._write_json(handler, self.get_run_diff(path_parts[2], baseline_run_id))
                return
            if (
                len(path_parts) == 4
                and path_parts[:2] == ["api", "runs"]
                and path_parts[3] == "logs"
                and handler.command == "GET"
            ):
                self._write_json(handler, self.get_run_logs(path_parts[2]))
                return
            if (
                len(path_parts) == 4
                and path_parts[:2] == ["api", "runs"]
                and path_parts[3] == "execute"
                and handler.command == "POST"
            ):
                payload = self._read_json(handler)
                self._write_json(
                    handler,
                    self.start_execution(path_parts[2], payload.get("module")),
                    status=HTTPStatus.ACCEPTED,
                )
                return
            if (
                len(path_parts) == 4
                and path_parts[:2] == ["api", "runs"]
                and path_parts[3] == "dir-enum"
                and handler.command == "POST"
            ):
                payload = self._read_json(handler)
                self._write_json(
                    handler,
                    self.enqueue_dir_enum_followup(path_parts[2], payload),
                    status=HTTPStatus.ACCEPTED,
                )
                return
            if (
                len(path_parts) == 4
                and path_parts[:2] == ["api", "runs"]
                and path_parts[3] == "cancel"
                and handler.command == "POST"
            ):
                self._write_json(
                    handler,
                    self.cancel_execution(path_parts[2]),
                    status=HTTPStatus.ACCEPTED,
                )
                return
            if (
                len(path_parts) == 4
                and path_parts[:2] == ["api", "runs"]
                and path_parts[3] == "service-notes"
                and handler.command == "GET"
            ):
                self._write_json(handler, self.list_service_notes(path_parts[2]))
                return
            if (
                len(path_parts) == 4
                and path_parts[:2] == ["api", "runs"]
                and path_parts[3] == "service-notes"
                and handler.command == "POST"
            ):
                payload = self._read_json(handler)
                self._write_json(
                    handler,
                    self.create_service_note(path_parts[2], payload),
                    status=HTTPStatus.CREATED,
                )
                return
            if (
                len(path_parts) == 5
                and path_parts[:2] == ["api", "runs"]
                and path_parts[3] == "service-notes"
                and handler.command == "PATCH"
            ):
                payload = self._read_json(handler)
                self._write_json(handler, self.update_service_note(path_parts[2], path_parts[4], payload))
                return
            if (
                len(path_parts) == 5
                and path_parts[:2] == ["api", "runs"]
                and path_parts[3] == "service-notes"
                and handler.command == "DELETE"
            ):
                self._write_json(handler, self.delete_service_note(path_parts[2], path_parts[4]))
                return
            if (
                len(path_parts) == 4
                and path_parts[:2] == ["api", "runs"]
                and path_parts[3] == "report.html"
                and handler.command == "GET"
            ):
                query = parse_qs(parsed.query)
                baseline_run_id = (query.get("baseline") or [""])[0]
                self._write_html(handler, self.render_report_html(path_parts[2], baseline_run_id=baseline_run_id or None))
                return
            if handler.command == "GET" and path_parts == ["api", "dashboard", "artifact"]:
                query = parse_qs(parsed.query)
                artifact_path = (query.get("path") or [""])[0]
                self._write_artifact_content(handler, artifact_path)
                return
            if handler.command == "GET" and path_parts == ["api", "dashboard", "runs"]:
                self._write_json(handler, {"runs": self._dashboard_runs()})
                return
            if (
                len(path_parts) == 5
                and path_parts[:3] == ["api", "dashboard", "runs"]
                and path_parts[4] == "report"
                and handler.command == "GET"
            ):
                self._write_json(handler, self._dashboard_run_report(path_parts[3]))
                return
            if (
                len(path_parts) == 5
                and path_parts[:3] == ["api", "dashboard", "runs"]
                and path_parts[4] == "diff"
                and handler.command == "GET"
            ):
                query = parse_qs(parsed.query)
                baseline_run_id = (query.get("baseline") or [""])[0]
                self._write_json(handler, self._dashboard_run_diff(path_parts[3], baseline_run_id))
                return

            self._write_json(
                handler,
                {"error": f"unknown route: {parsed.path}"},
                status=HTTPStatus.NOT_FOUND,
            )
        except FileNotFoundError as exc:
            self._write_json(handler, {"error": str(exc)}, status=HTTPStatus.NOT_FOUND)
        except LookupError as exc:
            self._write_json(handler, {"error": str(exc)}, status=HTTPStatus.NOT_FOUND)
        except RuntimeError as exc:
            self._write_json(handler, {"error": str(exc)}, status=HTTPStatus.CONFLICT)
        except ValueError as exc:
            self._write_json(handler, {"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
        except json.JSONDecodeError:
            self._write_json(handler, {"error": "invalid JSON request body"}, status=HTTPStatus.BAD_REQUEST)

    def list_wordlists(self) -> dict[str, Any]:
        wordlists_dir = self.workspace / "wordlists"
        wordlists: list[str] = []
        wordlist_entries: list[dict[str, Any]] = []
        wordlist_paths: list[tuple[str, Path]] = []
        if wordlists_dir.exists():
            for path in sorted(wordlists_dir.rglob("*")):
                if path.is_file() and path.suffix.lower() in WORDLIST_EDITABLE_SUFFIXES:
                    try:
                        rel_path = path.relative_to(wordlists_dir)
                        rel_str = f"wordlists/{rel_path.as_posix()}"
                        wordlist_paths.append((rel_str, path))
                    except ValueError:
                        continue
        wordlist_paths.sort(key=lambda item: self._wordlist_sort_key(item[0]))
        wordlists = [rel_str for rel_str, _path in wordlist_paths]
        for index, (rel_str, path) in enumerate(wordlist_paths):
            count_entry_lines = len(wordlist_paths) <= 500 or index < 250
            stats = (
                self._wordlist_file_stats(path)
                if count_entry_lines
                else {"size_bytes": 0, "size_human": "—", "line_count": 0, "lines_human": "—"}
            )
            wordlist_entries.append(
                {
                    "path": rel_str,
                    "label": self._short_wordlist_label(rel_str),
                    "editable": path.suffix.lower() in WORDLIST_EDITABLE_SUFFIXES,
                    **stats,
                }
            )
        bundle = self._wordlist_project_bundle()
        presets = self._wordlist_recommended_presets(wordlists)
        default_extra_headers_text = "\n".join(f"{name}: {value}" for name, value in BROWSER_HEADER_DEFAULTS)
        return {
            "wordlists": wordlists,
            "wordlist_entries": wordlist_entries,
            "wordlist_bundle": bundle,
            "recommended_presets": presets,
            "default_extra_headers_text": default_extra_headers_text,
        }

    def list_presets(self) -> dict[str, Any]:
        presets = {
            key: {**value, "custom": False}
            for key, value in get_ui_run_presets().items()
        }
        for key, value in self._custom_profiles().items():
            if not isinstance(value, dict):
                continue
            modules = value.get("modules")
            defaults = value.get("defaults")
            presets[str(key)] = {
                "label": str(value.get("label") or key),
                "description": str(value.get("description") or "Custom scan profile."),
                "modules": [str(item) for item in modules] if isinstance(modules, list) else ["http_probe"],
                "profile": str(value.get("profile") or "safe"),
                "defaults": dict(defaults) if isinstance(defaults, dict) else {},
                "custom": True,
            }
        return {"presets": presets}

    def get_settings(self) -> dict[str, Any]:
        settings = self._load_workspace_settings()
        return {
            "settings": settings,
            "presets": self.list_presets()["presets"],
            "tools": self.list_tools()["tools"],
            "wordlists": self.list_wordlists(),
        }

    def update_settings(self, payload: dict[str, Any]) -> dict[str, Any]:
        settings = self._load_workspace_settings()
        if "defaults" in payload:
            raw_defaults = payload.get("defaults")
            if not isinstance(raw_defaults, dict):
                raise ValueError("defaults must be an object")
            defaults = dict(settings.get("defaults") or {})
            sanitized = self._extract_config_patch(raw_defaults)
            for key, value in sanitized.items():
                if value in (None, ""):
                    defaults.pop(key, None)
                else:
                    defaults[key] = value
            self._validate_config_defaults(defaults)
            settings["defaults"] = defaults
        if "tool_paths" in payload or "tools" in payload:
            tool_payload = payload.get("tool_paths", payload.get("tools"))
            if not isinstance(tool_payload, dict):
                raise ValueError("tool paths must be an object")
            settings["tool_paths"] = self._sanitize_tool_paths(tool_payload)
        self._write_workspace_settings(settings)
        return self.get_settings()

    def list_tools(self) -> dict[str, Any]:
        tools: list[dict[str, Any]] = []
        custom_paths = self._custom_tool_paths()
        for _field_name, binary_name in TOOL_BINARY_FIELDS:
            configured = custom_paths.get(binary_name)
            resolved = self._resolve_tool_display_path(binary_name, configured)
            version = ""
            error = ""
            installed = bool(resolved and resolved["installed"])
            if installed and resolved is not None:
                version, error = self._tool_version(binary_name, str(resolved["command"]))
            tools.append(
                {
                    "name": binary_name,
                    "path": resolved["path"] if resolved is not None else None,
                    "command": resolved["command"] if resolved is not None else None,
                    "configured_path": configured,
                    "custom": bool(configured),
                    "installed": installed,
                    "version": version,
                    "error": error,
                }
            )
        return {"tools": tools}

    def update_tool_paths(self, payload: dict[str, Any]) -> dict[str, Any]:
        tool_payload = payload.get("tools", payload.get("tool_paths", payload))
        if not isinstance(tool_payload, dict):
            raise ValueError("tools must be an object")
        settings = self._load_workspace_settings()
        settings["tool_paths"] = self._sanitize_tool_paths(tool_payload)
        self._write_workspace_settings(settings)
        return self.list_tools()

    def get_install_status(self) -> dict[str, Any]:
        from scanner.installer import check_all_tools, detect_platform, is_go_available
        go_ok, go_version = is_go_available()
        return {
            "platform": detect_platform(),
            "go_available": go_ok,
            "go_version": go_version,
            "tools": check_all_tools(),
        }

    def start_watchdog(self, run_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        from scanner.watchdog import (
            WatchdogConfig, daemonize_and_run, default_workspace_paths, watchdog_status as _status,
        )
        if not isinstance(run_id, str) or not run_id.strip():
            raise ValueError("run_id is required")
        paths = default_workspace_paths(run_id, self.workspace)
        existing = _status(paths["pid"], paths["state"])
        if existing.get("running"):
            return {"started": False, "already_running": True, **existing, "paths": {k: str(v) for k, v in paths.items()}}
        interval = int(payload.get("interval_seconds") or payload.get("interval") or 120)
        stall = int(payload.get("stall_threshold") or 15)
        cfg = WatchdogConfig(
            base_url=f"http://{getattr(self, 'host', '127.0.0.1')}:{getattr(self, 'port', 8000)}",
            check_interval_seconds=max(30, min(3600, interval)),
            stall_threshold=max(2, min(120, stall)),
            log_path=str(paths["log"]),
            state_path=str(paths["state"]),
            pid_path=str(paths["pid"]),
        )
        pid = daemonize_and_run(run_id, cfg)
        return {
            "started": True,
            "pid": pid,
            "paths": {k: str(v) for k, v in paths.items()},
            "config": {
                "check_interval_seconds": cfg.check_interval_seconds,
                "stall_threshold": cfg.stall_threshold,
            },
        }

    def stop_watchdog(self, run_id: str) -> dict[str, Any]:
        from scanner.watchdog import default_workspace_paths, stop_daemon
        if not isinstance(run_id, str) or not run_id.strip():
            raise ValueError("run_id is required")
        paths = default_workspace_paths(run_id, self.workspace)
        stopped = stop_daemon(paths["pid"])
        return {"stopped": stopped}

    def get_watchdog_status(self, run_id: str) -> dict[str, Any]:
        from scanner.watchdog import default_workspace_paths, watchdog_status as _status
        if not isinstance(run_id, str) or not run_id.strip():
            raise ValueError("run_id is required")
        paths = default_workspace_paths(run_id, self.workspace)
        status = _status(paths["pid"], paths["state"])
        log_tail: list[str] = []
        log_path = paths["log"]
        if log_path.exists():
            try:
                with open(log_path) as f:
                    log_tail = f.readlines()[-50:]
            except OSError:
                log_tail = []
        status["log_tail"] = [line.rstrip() for line in log_tail]
        status["paths"] = {k: str(v) for k, v in paths.items()}
        return status

    def install_missing_tools(self, payload: dict[str, Any]) -> dict[str, Any]:
        from scanner.installer import TOOL_SPECS, install_tool
        names_raw = payload.get("tools") or payload.get("names") or []
        if not isinstance(names_raw, list):
            raise ValueError("tools must be an array of tool names")
        names = [str(n).strip() for n in names_raw if str(n).strip()]
        if not names:
            names = list(TOOL_SPECS.keys())
        unknown = [n for n in names if n not in TOOL_SPECS]
        if unknown:
            raise ValueError(f"unknown tool(s): {', '.join(unknown)}")
        force = bool(payload.get("force"))
        results = [install_tool(n, force=force) for n in names]
        return {
            "results": [
                {
                    "name": r.name,
                    "success": r.success,
                    "path": r.path,
                    "version": r.version,
                    "method": r.method,
                    "message": r.message,
                    "install_commands": r.install_commands,
                    "stdout": (r.stdout or "")[-2000:],
                    "stderr": (r.stderr or "")[-2000:],
                }
                for r in results
            ],
            "status": self.get_install_status(),
        }

    def save_profile(self, payload: dict[str, Any]) -> dict[str, Any]:
        key = str(payload.get("key") or payload.get("name") or "").strip()
        if not CUSTOM_PROFILE_KEY_RE.fullmatch(key):
            raise ValueError("profile key must be 1-48 letters, numbers, underscores, or hyphens")
        if key in get_ui_run_presets():
            raise ValueError("custom profile key cannot replace a built-in preset")
        modules_raw = payload.get("modules")
        if not isinstance(modules_raw, list) or not modules_raw:
            raise ValueError("modules must be a non-empty array")
        modules = [str(item) for item in modules_raw]
        unknown_modules = sorted(set(modules) - set(MODULE_ORDER))
        if unknown_modules:
            raise ValueError(f"unsupported modules: {', '.join(unknown_modules)}")
        defaults_raw = payload.get("defaults") if isinstance(payload.get("defaults"), dict) else {}
        defaults = self._extract_config_patch(cast(dict[str, Any], defaults_raw))
        self._validate_config_defaults(defaults)
        profile = str(payload.get("profile") or "safe").strip().lower()
        self._validate_config_defaults({"profile": profile})
        settings = self._load_workspace_settings()
        profiles = dict(settings.get("profiles") or {})
        profiles[key] = {
            "label": str(payload.get("label") or key).strip() or key,
            "description": str(payload.get("description") or "Custom scan profile.").strip(),
            "modules": modules,
            "profile": profile,
            "defaults": defaults,
        }
        settings["profiles"] = profiles
        self._write_workspace_settings(settings)
        return self.list_presets()

    def delete_profile(self, key: str) -> dict[str, Any]:
        normalized = str(key or "").strip()
        if normalized in get_ui_run_presets():
            raise ValueError("built-in presets cannot be deleted")
        settings = self._load_workspace_settings()
        profiles = dict(settings.get("profiles") or {})
        if normalized not in profiles:
            raise LookupError(f"profile '{normalized}' was not found")
        del profiles[normalized]
        settings["profiles"] = profiles
        self._write_workspace_settings(settings)
        return self.list_presets()

    def get_wordlist_file(self, value: object) -> dict[str, Any]:
        rel_str, path = self._resolve_wordlist_file_path(value)
        if not path.exists():
            raise FileNotFoundError(f"wordlist '{rel_str}' was not found")
        content = path.read_text(encoding="utf-8", errors="replace")
        return {
            "path": rel_str,
            "label": self._short_wordlist_label(rel_str),
            "content": content,
            **self._wordlist_file_stats(path),
        }

    def update_wordlist_file(self, payload: dict[str, Any]) -> dict[str, Any]:
        rel_str, path = self._resolve_wordlist_file_path(payload.get("path"))
        content = payload.get("content")
        if not isinstance(content, str):
            raise ValueError("content must be a string")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return {
            "path": rel_str,
            "label": self._short_wordlist_label(rel_str),
            **self._wordlist_file_stats(path),
        }

    def _tool_version(self, binary_name: str, command: str) -> tuple[str, str]:
        args = TOOL_VERSION_ARGS.get(binary_name, ("--version",))
        try:
            completed = run_text_capture([command, *args], timeout=5)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return "", str(exc)
        output = "\n".join(part for part in (completed.stdout, completed.stderr) if part).strip()
        first_line = next(
            (ANSI_ESCAPE_RE.sub("", line).strip() for line in output.splitlines() if line.strip()),
            "",
        )
        return first_line[:240], "" if completed.returncode == 0 or first_line else f"exit {completed.returncode}"

    def _settings_path(self) -> Path:
        return self.workspace / WORKSPACE_SETTINGS_FILENAME

    def _load_workspace_settings(self) -> dict[str, Any]:
        path = self._settings_path()
        if not path.exists():
            return {"tool_paths": {}, "defaults": {}, "profiles": {}}
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("workspace settings file must contain a JSON object")
        tool_paths = raw.get("tool_paths")
        defaults = raw.get("defaults")
        profiles = raw.get("profiles")
        return {
            "tool_paths": dict(tool_paths) if isinstance(tool_paths, dict) else {},
            "defaults": dict(defaults) if isinstance(defaults, dict) else {},
            "profiles": dict(profiles) if isinstance(profiles, dict) else {},
        }

    def _write_workspace_settings(self, settings: dict[str, Any]) -> None:
        path = self._settings_path()
        path.write_text(
            json.dumps(settings, indent=2, sort_keys=True, ensure_ascii=False),
            encoding="utf-8",
        )

    def _workspace_defaults_patch(self) -> dict[str, Any]:
        defaults = self._load_workspace_settings().get("defaults")
        return dict(defaults) if isinstance(defaults, dict) else {}

    def _custom_profiles(self) -> dict[str, Any]:
        profiles = self._load_workspace_settings().get("profiles")
        return dict(profiles) if isinstance(profiles, dict) else {}

    def _custom_tool_paths(self) -> dict[str, str]:
        configured = self._load_workspace_settings().get("tool_paths")
        if not isinstance(configured, dict):
            return {}
        allowed = {binary_name for _field_name, binary_name in TOOL_BINARY_FIELDS}
        return {
            str(name): str(value).strip()
            for name, value in configured.items()
            if str(name) in allowed and str(value).strip()
        }

    def _sanitize_tool_paths(self, payload: dict[Any, Any]) -> dict[str, str]:
        existing = self._custom_tool_paths()
        allowed = {binary_name for _field_name, binary_name in TOOL_BINARY_FIELDS}
        for name, value in payload.items():
            key = str(name).strip()
            if key not in allowed:
                raise ValueError(f"unsupported tool '{key}'")
            text = str(value or "").strip()
            if text:
                existing[key] = text
            else:
                existing.pop(key, None)
        return existing

    def _resolve_tool_display_path(self, binary_name: str, configured: str | None) -> dict[str, Any] | None:
        if configured:
            configured_text = configured.strip()
            configured_path = Path(configured_text)
            if configured_path.is_absolute() or "\\" in configured_text or "/" in configured_text:
                resolved_path = configured_path.resolve()
                return {
                    "path": str(resolved_path),
                    "command": str(resolved_path),
                    "installed": resolved_path.is_file(),
                }
            found = shutil.which(configured_text)
            return {
                "path": found or configured_text,
                "command": found or configured_text,
                "installed": found is not None,
            }
        resolved = resolve_default_binary_path(binary_name)
        if resolved is None:
            return None
        return {
            "path": str(resolved),
            "command": str(resolved),
            "installed": True,
        }

    def _validate_config_defaults(self, defaults: dict[str, Any]) -> None:
        config_data = ScanConfig(target="settings-validation").model_dump(mode="json")
        config_data.update(defaults)
        ScanConfig.model_validate(config_data)

    _SECLISTS_DISPLAY_STRIP: tuple[str, ...] = (
        "wordlists/SecLists-master/",
        "wordlists/SecLists/",
    )

    def _short_wordlist_label(self, full_path: str) -> str:
        """Strip common SecLists path prefix for UI; keep relative path under wordlists/ otherwise."""
        p = str(full_path or "").replace("\\", "/").strip()
        if not p:
            return ""
        for pref in self._SECLISTS_DISPLAY_STRIP:
            if p.startswith(pref):
                return p[len(pref) :]
        if p.startswith("wordlists/"):
            return p[len("wordlists/") :]
        return p

    def _wordlist_sort_key(self, full_path: str) -> tuple[int, str]:
        normalized = str(full_path or "").replace("\\", "/").lower()
        priority = {
            "wordlists/test.txt": 0,
            "wordlists/small.txt": 1,
        }.get(normalized, 2)
        return (priority, normalized)

    def _resolve_wordlist_file_path(self, value: object) -> tuple[str, Path]:
        text = str(value or "").strip().replace("\\", "/")
        if not text:
            raise ValueError("wordlist path is required")
        base = (self.workspace / "wordlists").resolve()
        raw = text[len("wordlists/") :] if text.startswith("wordlists/") else text
        candidate = Path(raw)
        path = candidate.resolve() if candidate.is_absolute() else (base / raw).resolve()
        try:
            rel_path = path.relative_to(base)
        except ValueError as exc:
            raise ValueError("wordlist path must stay under the workspace wordlists directory") from exc
        if path.suffix.lower() not in WORDLIST_EDITABLE_SUFFIXES:
            allowed = ", ".join(sorted(WORDLIST_EDITABLE_SUFFIXES))
            raise ValueError(f"wordlist files must use one of: {allowed}")
        return f"wordlists/{rel_path.as_posix()}", path

    def _count_wordlist_newlines(self, path: Path) -> int:
        total = 0
        try:
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    total += chunk.count(b"\n")
        except OSError:
            return 0
        return total

    def _format_wordlist_bytes(self, size: int) -> str:
        if size < 0:
            return "—"
        if size < 1024:
            return f"{size} B"
        if size < 1024 * 1024:
            kb = size / 1024
            if abs(kb - round(kb)) < 0.05:
                return f"{int(round(kb))} KB"
            return f"{kb:.1f} KB"
        if size < 1024**3:
            mb = size / (1024 * 1024)
            if abs(mb - round(mb)) < 0.05:
                return f"{int(round(mb))} MB"
            return f"{mb:.1f} MB"
        gb = size / (1024**3)
        if abs(gb - round(gb)) < 0.05:
            return f"{int(round(gb))} GB"
        return f"{gb:.1f} GB"

    def _format_wordlist_lines_human(self, line_count: int) -> str:
        """Rough bucket labels e.g. 약 2만 줄 — newline-delimited entries (ffuf words)."""
        if line_count <= 0:
            return "0 줄"
        if line_count >= 10_000:
            man = line_count / 10_000.0
            rounded = round(man)
            if abs(man - rounded) < 0.12:
                return f"약 {int(rounded)}만 줄"
            text = f"{man:.1f}".rstrip("0").rstrip(".")
            return f"약 {text}만 줄"
        if line_count >= 1_000:
            k = line_count / 1000.0
            rounded = round(k)
            if abs(k - rounded) < 0.12:
                return f"약 {int(rounded)}k 줄"
            text = f"{k:.1f}".rstrip("0").rstrip(".")
            return f"약 {text}k 줄"
        return f"{line_count} 줄"

    def _wordlist_file_stats(self, path: Path, *, count_lines: bool = True) -> dict[str, Any]:
        try:
            st = path.stat()
        except OSError:
            return {
                "size_bytes": 0,
                "size_human": "—",
                "line_count": 0,
                "lines_human": "—",
            }
        size = st.st_size
        if count_lines:
            lines = self._count_wordlist_newlines(path)
            if size > 0 and lines == 0:
                lines = 1
            lines_human = self._format_wordlist_lines_human(lines)
        else:
            lines = 0
            lines_human = "—"
        return {
            "size_bytes": size,
            "size_human": self._format_wordlist_bytes(size),
            "line_count": lines,
            "lines_human": lines_human,
        }

    def _wordlist_project_bundle(self) -> list[dict[str, Any]]:
        """Top-level project wordlists (test / small) as explicit quick picks."""
        out: list[dict[str, Any]] = []
        for rel, title in (("wordlists/test.txt", "test.txt"), ("wordlists/small.txt", "small.txt")):
            path = self.workspace / rel
            if path.is_file():
                row: dict[str, Any] = {"path": rel.replace("\\", "/"), "label": title}
                row.update(self._wordlist_file_stats(path))
                out.append(row)
        return out

    def _wordlist_recommended_presets(self, available: list[str]) -> list[dict[str, Any]]:
        normalized = {p.replace("\\", "/") for p in available}

        def pick(paths: list[str]) -> str | None:
            for candidate in paths:
                c = candidate.replace("\\", "/")
                if c in normalized:
                    return c
            return None

        tiers: list[tuple[str, list[str]]] = [
            (
                "WEB-기본",
                [
                    "wordlists/SecLists-master/Discovery/Web-Content/raft-small-directories.txt",
                    "wordlists/SecLists/Discovery/Web-Content/raft-small-directories.txt",
                    "wordlists/SecLists-master/Discovery/Web-Content/common.txt",
                    "wordlists/SecLists/Discovery/Web-Content/common.txt",
                ],
            ),
            (
                "WEB-보통",
                [
                    "wordlists/SecLists-master/Discovery/Web-Content/raft-medium-directories.txt",
                    "wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt",
                ],
            ),
            (
                "WEB-강력",
                [
                    "wordlists/SecLists-master/Discovery/Web-Content/raft-large-directories.txt",
                    "wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt",
                ],
            ),
        ]
        out: list[dict[str, Any]] = []
        for label, choices in tiers:
            resolved = pick(choices)
            if not resolved and label == "WEB-기본" and available:
                resolved = available[0].replace("\\", "/")
            if resolved:
                item: dict[str, Any] = {
                    "label": label,
                    "path": resolved,
                    "short_label": self._short_wordlist_label(resolved),
                }
                try:
                    cand = (self.workspace / resolved.replace("\\", "/")).resolve()
                    cand.relative_to(self.workspace.resolve())
                    if cand.is_file():
                        item.update(self._wordlist_file_stats(cand))
                except ValueError:
                    pass
                out.append(item)
        return out

    def list_runs(self) -> list[dict[str, Any]]:
        runs_dir = self.workspace / "runs"
        if not runs_dir.exists():
            return []

        items: list[dict[str, Any]] = []
        for state_db_path in sorted(runs_dir.glob("*/state.db")):
            run_id = state_db_path.parent.name
            connection = connect(state_db_path)
            try:
                run = get_run(connection, run_id)
                if run is None:
                    continue
                tasks = self._load_tasks(connection, run_id)
                items.append(
                    {
                        "run_id": run.run_id,
                        "display_name": display_run_name(run.target, run.created_at),
                        "target": run.target,
                        "target_display": format_run_target_display(self.workspace, run_id, run.target),
                        "status": run.status,
                        "profile": run.config.profile,
                        "modules": run.config.enabled_phases,
                        "created_at": run.created_at.isoformat(),
                        "started_at": run.started_at.isoformat() if run.started_at else None,
                        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
                        "task_counts": self._task_counts(tasks),
                        "execution": {
                            "active": self.execution_manager.is_active(run_id),
                            "cancel_requested": self.execution_manager.is_cancel_requested(run_id),
                        },
                        "progress": self._build_run_progress(tasks),
                    }
                )
            finally:
                connection.close()

        items.sort(key=lambda item: str(item["created_at"]), reverse=True)
        return items

    def _user_scan_mode_skip_keys(self, payload: dict[str, Any]) -> frozenset[str]:
        skip: set[str] = set()
        for key in PATCHABLE_CONFIG_FIELDS:
            if key in payload and payload.get(key) not in (None, ""):
                skip.add(key)
        auth_field_keys = {"extra_headers_text", "cookies", "bearer_token", "host_header"}
        if any(key in payload for key in auth_field_keys):
            skip.add("extra_headers")
        if isinstance(payload.get("modules"), list):
            skip.add("enabled_phases")
        return frozenset(skip)

    def _reapply_scan_mode_after_patches(self, run_id: str, user_skip: frozenset[str]) -> None:
        state_db_path = self.workspace / "runs" / run_id / "state.db"
        if not state_db_path.exists():
            return
        connection = connect(state_db_path)
        try:
            run = get_run(connection, run_id)
            if run is None:
                return
            new_c = apply_scan_mode_defaults(run.config, skip_fields=user_skip)
            if new_c.model_dump(mode="json") == run.config.model_dump(mode="json"):
                return
            connection.execute(
                "UPDATE runs SET config_json = ?, updated_at = CURRENT_TIMESTAMP WHERE run_id = ?",
                (
                    json.dumps(
                        new_c.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
                    ),
                    run_id,
                ),
            )
            connection.commit()
        finally:
            connection.close()

    def create_run(self, payload: dict[str, Any]) -> dict[str, Any]:
        raw_target = str(payload.get("target") or "").strip()
        lines = normalize_bulk_target_lines(raw_target)
        if not lines:
            raise ValueError("target is required")
        primary_target = lines[0]
        user_include = parse_scope_entries(payload.get("scope_include"))
        merged_payload = dict(payload)
        if len(lines) > 1:
            merged_include: list[str] = []
            seen_inc: set[str] = set()
            for item in lines + user_include:
                key = item.lower()
                if key in seen_inc:
                    continue
                seen_inc.add(key)
                merged_include.append(item)
            merged_payload["scope_include"] = "\n".join(merged_include)
        elif user_include:
            merged_payload["scope_include"] = "\n".join(user_include)

        workspace_defaults = self._workspace_defaults_patch()
        preset = self._resolve_preset(payload.get("preset"))
        preset_defaults = cast(dict[str, Any], preset["defaults"]) if preset is not None else {}
        modules = payload.get("modules")
        if modules is None and preset is not None:
            modules = list(cast(list[str], preset["modules"]))
        if modules is not None and not isinstance(modules, list):
            raise ValueError("modules must be a JSON array when provided")
        preset_supplied_modules = preset is not None and modules is not None and not isinstance(payload.get("modules"), list)
        preserve_preset_modules = preset_supplied_modules and "scan_mode" not in payload
        user_chose_modules = isinstance(payload.get("modules"), list) or preserve_preset_modules
        scan_mode = normalize_scan_mode(
            payload.get("scan_mode")
            or preset_defaults.get("scan_mode")
            or workspace_defaults.get("scan_mode")
            or "balanced"
        )
        modules_for_plan = [str(item) for item in modules] if modules is not None else None
        any_line_is_domain = any(classify_bulk_line(x) == "domain" for x in lines)
        force_domain_phases = len(lines) > 1 and any_line_is_domain
        phase_list = apply_scan_mode_to_modules(
            primary_target,
            modules_for_plan,
            scan_mode=scan_mode,
            user_chose_modules=user_chose_modules,
            any_line_is_domain=force_domain_phases,
        )
        profile = str(
            payload.get("profile")
            or (preset["profile"] if preset is not None else None)
            or workspace_defaults.get("profile")
            or "safe"
        )
        skip_fields = set(self._user_scan_mode_skip_keys(payload))
        if preserve_preset_modules:
            skip_fields.add("enabled_phases")
        skip_fields.update(key for key, value in workspace_defaults.items() if value not in (None, ""))
        skip_fields.update(key for key, value in preset_defaults.items() if value not in (None, ""))
        user_skip = frozenset(skip_fields)
        created = create_scan_run(
            primary_target,
            modules=[str(m) for m in phase_list],
            profile=profile,
            workspace=self.workspace,
            scan_mode=scan_mode,
            mode_skip_fields=user_skip,
            bulk_targets=lines,
            any_line_is_domain=force_domain_phases,
        )
        patch: dict[str, Any] = dict(self._default_local_binary_patch())
        for key, value in workspace_defaults.items():
            if key in user_skip and key in payload:
                continue
            if value in (None, ""):
                continue
            patch[key] = value
        if preset is not None:
            for key, value in preset_defaults.items():
                if key in payload:
                    continue
                if value in (None, ""):
                    continue
                patch[key] = value
        for key, value in self._extract_config_patch(payload).items():
            if value in (None, ""):
                continue
            patch[key] = value
        self._patch_run_config(created["run_id"], patch)
        self._reapply_scan_mode_after_patches(created["run_id"], user_skip)
        self._write_scope_controls(created["run_id"], merged_payload)
        if bool(payload.get("include_notes_context")):
            source_run_id = str(payload.get("source_run_id") or "").strip()
            if source_run_id:
                self._copy_service_notes_to_new_run(source_run_id, created["run_id"])
        if bool(payload.get("auto_start")):
            self.start_execution(created["run_id"], None)
        return self.get_run_view(created["run_id"])

    def update_run_config(self, run_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        state_db_path = self.workspace / "runs" / run_id / "state.db"
        if not state_db_path.exists():
            raise FileNotFoundError(f"run state database not found for run_id '{run_id}'")
        connection = connect(state_db_path)
        try:
            run = get_run(connection, run_id)
            if run is None:
                raise LookupError(f"run_id '{run_id}' was not found")
            running_task = connection.execute(
                "SELECT task_id, module FROM tasks WHERE run_id = ? AND state = 'running' LIMIT 1",
                (run_id,),
            ).fetchone()
        finally:
            connection.close()

        previous_target = str(run.target or "")
        previous_modules = list(run.config.enabled_phases)
        previous_config = run.config.model_dump(mode="json")
        is_running = bool(
            self.execution_manager.is_active(run_id)
            or running_task is not None
            or str(run.status) == "running"
        )
        status = "running" if is_running else str(run.status or "pending")
        extracted_patch = self._extract_config_patch(payload)

        if status == "pending":
            target_value = str(payload.get("target") or "").strip()
            if target_value:
                self._patch_run_target(run_id, target_value)
            modules = payload.get("modules")
            if modules is not None:
                if not isinstance(modules, list):
                    raise ValueError("modules must be a JSON array when provided")
                extend_scan_run(
                    run_id,
                    modules=[str(item) for item in modules],
                    workspace=self.workspace,
                )
            self._patch_run_config(run_id, extracted_patch, allow_running_updates=False)
            self._write_scope_controls(run_id, payload)
            view = self.get_run_view(run_id)
            self._log_config_update(
                run_id=run_id,
                status=status,
                previous_target=previous_target,
                previous_modules=previous_modules,
                previous_config=previous_config,
                view=view,
                running_task=running_task,
            )
            return view

        if status == "running":
            disallowed = [key for key in extracted_patch if key not in RUNNING_SAFE_PATCH_FIELDS]
            if disallowed:
                allowed = ", ".join(sorted(RUNNING_SAFE_PATCH_FIELDS))
                raise ValueError(f"running run allows only safe fields: {allowed}")
            self._patch_run_config(run_id, extracted_patch, allow_running_updates=True)
            view = self.get_run_view(run_id)
            self._log_config_update(
                run_id=run_id,
                status=status,
                previous_target=previous_target,
                previous_modules=previous_modules,
                previous_config=previous_config,
                view=view,
                running_task=running_task,
            )
            return view

        raise ValueError("config edit is allowed only for pending or running runs")

    def _log_config_update(
        self,
        *,
        run_id: str,
        status: str,
        previous_target: str,
        previous_modules: Sequence[str],
        previous_config: dict[str, Any],
        view: dict[str, Any],
        running_task: Any,
    ) -> None:
        run = cast(dict[str, Any], view.get("run") or {})
        current_config = cast(dict[str, Any], run.get("config") or {})
        changed = self._build_changed_fields(
            previous_target=previous_target,
            current_target=str(run.get("target") or ""),
            previous_modules=previous_modules,
            current_modules=[str(item) for item in (current_config.get("enabled_phases") or [])],
            previous_config=previous_config,
            current_config=current_config,
        )
        if not changed:
            return
        changed_keys = sorted(changed.keys())
        short = ", ".join(changed_keys[:4]) + (", ..." if len(changed_keys) > 4 else "")
        apply_scope = (
            "Config changes will apply to upcoming tasks only."
            if status == "running"
            else "Config changes will apply from the next execution start."
        )
        task_scope = None
        if status == "running" and running_task is not None:
            task_scope = {
                "task_id": str(running_task[0] or ""),
                "module": str(running_task[1] or ""),
            }
        self.execution_manager.append_log(
            run_id,
            f"Config updated ({short})",
            level="info",
            data={
                "event": "config_updated",
                "changed_fields": changed,
                "changed_field_count": len(changed_keys),
                "apply_scope": apply_scope,
                "running_task": task_scope,
            },
        )
        if status == "running":
            self.execution_manager.append_log(
                run_id,
                "Config changes will apply to upcoming tasks only.",
                level="info",
                data={"event": "config_apply_scope", "apply_scope": apply_scope, "running_task": task_scope},
            )

    def _build_changed_fields(
        self,
        *,
        previous_target: str,
        current_target: str,
        previous_modules: Sequence[str],
        current_modules: Sequence[str],
        previous_config: dict[str, Any],
        current_config: dict[str, Any],
    ) -> dict[str, list[Any]]:
        changed: dict[str, list[Any]] = {}
        if previous_target != current_target:
            changed["target"] = [previous_target, current_target]
        if previous_modules != current_modules:
            changed["modules"] = [previous_modules, current_modules]
        for key in PATCHABLE_CONFIG_FIELDS:
            before = previous_config.get(key)
            after = current_config.get(key)
            if before != after:
                changed[key] = [before, after]
        return changed

    def _patch_run_target(self, run_id: str, target: str) -> None:
        state_db_path = self.workspace / "runs" / run_id / "state.db"
        connection = sqlite3.connect(state_db_path)
        try:
            row = connection.execute(
                "SELECT config_json FROM runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            if row is None:
                raise LookupError(f"run_id '{run_id}' was not found")
            config = json.loads(row[0])
            config["target"] = target
            validated = ScanConfig.model_validate(config)
            connection.execute(
                """
                UPDATE runs
                SET target = ?, config_json = ?, updated_at = CURRENT_TIMESTAMP
                WHERE run_id = ?
                """,
                (
                    target,
                    json.dumps(validated.model_dump(mode="json"), sort_keys=True, separators=(",", ":")),
                    run_id,
                ),
            )
            connection.commit()
        finally:
            connection.close()

    def get_clone_config(self, run_id: str) -> dict[str, Any]:
        state_db_path = self.workspace / "runs" / run_id / "state.db"
        if not state_db_path.exists():
            raise FileNotFoundError(f"run state database not found for run_id '{run_id}'")

        connection = connect(state_db_path)
        try:
            run = get_run(connection, run_id)
            if run is None:
                raise LookupError(f"run_id '{run_id}' was not found")
            source_note_count = len(list_service_notes(connection))
        finally:
            connection.close()

        config = run.config
        auth_fields = split_auth_header_fields(config.extra_headers)
        scope = self._load_scope_controls(run_id, run.target)

        return {
            "source_run_id": run_id,
            "target": run.target,
            "profile": config.profile,
            "scan_mode": getattr(config, "scan_mode", "balanced") or "balanced",
            "proxy_mode": str(getattr(config, "proxy_mode", "none") or "none"),
            "proxy_url": str(getattr(config, "proxy_url", "") or ""),
            "modules": list(config.enabled_phases),
            "ffuf_wordlist_path": str(config.ffuf_wordlist_path) if config.ffuf_wordlist_path else "",
            "ffuf_concurrency": int(getattr(config, "ffuf_concurrency", 40) or 40),
            "ffuf_parallel_enabled": bool(getattr(config, "ffuf_parallel_enabled", True)),
            "ffuf_max_parallel_tasks": int(getattr(config, "ffuf_max_parallel_tasks", 3) or 3),
            "ffuf_replay_proxy": str(getattr(config, "ffuf_replay_proxy", "") or ""),
            "ffuf_extensions": [str(x) for x in (getattr(config, "ffuf_extensions", None) or [])],
            "auto_recommendation_enabled": bool(getattr(config, "auto_recommendation_enabled", True)),
            "nmap_ports": config.nmap_ports,
            "nmap_timing_template": str(config.nmap_timing_template),
            "nmap_version_detection": bool(config.nmap_version_detection),
            "subfinder_bin": config.subfinder_bin,
            "assetfinder_bin": config.assetfinder_bin,
            "httpx_bin": config.httpx_bin,
            "ffuf_bin": config.ffuf_bin,
            "nmap_bin": config.nmap_bin,
            "extra_headers_text": auth_fields.get("extra_headers_text", ""),
            "cookies": auth_fields.get("cookies", ""),
            "bearer_token": auth_fields.get("bearer_token", ""),
            "host_header": auth_fields.get("host_header", ""),
            "scope_include": "\n".join(scope.get("include") or []),
            "scope_exclude": "\n".join(scope.get("exclude") or []),
            "dir_recursive_enabled": bool(config.dir_recursive_enabled),
            "dir_recursive_max_depth": int(config.dir_recursive_max_depth),
            "dir_recursive_max_paths_per_host": int(config.dir_recursive_max_paths_per_host),
            "dir_recursive_same_host_only": bool(config.dir_recursive_same_host_only),
            "cidr_split_enabled": bool(config.cidr_split_enabled),
            "cidr_split_max_hosts_per_chunk": int(config.cidr_split_max_hosts_per_chunk),
            "cidr_split_target_interval_minutes": int(config.cidr_split_target_interval_minutes),
            "cidr_split_min_prefix": config.cidr_split_min_prefix,
            "cidr_split_strategy": str(config.cidr_split_strategy),
            "include_notes_context": True,
            "source_note_count": source_note_count,
        }

    def _copy_service_notes_to_new_run(self, source_run_id: str, new_run_id: str) -> dict[str, Any]:
        source_db = self.workspace / "runs" / source_run_id / "state.db"
        target_db = self.workspace / "runs" / new_run_id / "state.db"
        if not source_db.is_file() or not target_db.is_file():
            return {"copied": 0}
        source_connection = connect(source_db)
        target_connection = connect(target_db)
        copied = 0
        try:
            rows = list_service_notes(source_connection)
            if not rows:
                return {"copied": 0}
            now = datetime.now(UTC).replace(microsecond=0).isoformat()
            for row in rows:
                insert_service_note(
                    target_connection,
                    note_id=f"note-{uuid4().hex[:16]}",
                    host=str(row.get("host") or ""),
                    port=int(row.get("port") or 0),
                    protocol=_optional_clean_str(row.get("protocol")) or "tcp",
                    service_name=_optional_clean_str(row.get("service_name")),
                    note=str(row.get("note") or ""),
                    created_at=now,
                    updated_at=now,
                )
                copied += 1
            return {"copied": copied}
        finally:
            source_connection.close()
            target_connection.close()

    def get_run_view(self, run_id: str) -> dict[str, Any]:
        return get_run_view_data(
            workspace=self.workspace,
            run_id=run_id,
            execution_manager=self.execution_manager,
            load_tasks=self._load_tasks,
            task_counts=self._task_counts,
            load_scope_controls=self._load_scope_controls,
            build_run_progress=self._build_run_progress,
            build_execution_plan=self._build_execution_plan,
            build_execution_notes=self._build_execution_notes,
        )

    def list_service_notes(self, run_id: str) -> dict[str, Any]:
        state_db_path = self.workspace / "runs" / run_id / "state.db"
        if not state_db_path.is_file():
            raise FileNotFoundError(f"run state database not found for run_id '{run_id}'")
        connection = connect(state_db_path)
        try:
            return {"notes": list_service_notes(connection)}
        finally:
            connection.close()

    def create_service_note(self, run_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_run_exists(run_id)
        host = str(payload.get("host") or "").strip()
        if not host:
            raise ValueError("host is required")
        port = _parse_service_note_port(payload.get("port"))
        note_text = str(payload.get("note") or "").strip()
        if not note_text:
            raise ValueError("note is required")
        opt_protocol = _optional_clean_str(payload.get("protocol"))
        protocol = opt_protocol if opt_protocol is not None else "tcp"
        service_name = _optional_clean_str(payload.get("service_name"))
        state_db_path = self.workspace / "runs" / run_id / "state.db"
        note_id = f"note-{uuid4().hex[:16]}"
        now = datetime.now(UTC).replace(microsecond=0).isoformat()
        connection = connect(state_db_path)
        try:
            insert_service_note(
                connection,
                note_id=note_id,
                host=host,
                port=port,
                protocol=protocol,
                service_name=service_name,
                note=note_text,
                created_at=now,
                updated_at=now,
            )
            row = fetch_service_note_by_id(connection, note_id)
            if row is None:
                raise RuntimeError("failed to read created service note")
            return row
        finally:
            connection.close()

    def update_service_note(self, run_id: str, note_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_run_exists(run_id)
        note_id_clean = str(note_id).strip()
        if not note_id_clean:
            raise ValueError("note_id is required")
        note_text = str(payload.get("note") or "").strip()
        if not note_text:
            raise ValueError("note is required")
        state_db_path = self.workspace / "runs" / run_id / "state.db"
        now = datetime.now(UTC).replace(microsecond=0).isoformat()
        connection = connect(state_db_path)
        try:
            updated = update_service_note_text(connection, note_id_clean, note_text, now)
            if updated == 0:
                raise LookupError(f"service note '{note_id_clean}' was not found")
            row = fetch_service_note_by_id(connection, note_id_clean)
            if row is None:
                raise RuntimeError("failed to read updated service note")
            return row
        finally:
            connection.close()

    def delete_service_note(self, run_id: str, note_id: str) -> dict[str, Any]:
        self._require_run_exists(run_id)
        note_id_clean = str(note_id).strip()
        if not note_id_clean:
            raise ValueError("note_id is required")
        state_db_path = self.workspace / "runs" / run_id / "state.db"
        connection = connect(state_db_path)
        try:
            deleted = delete_service_note_by_id(connection, note_id_clean)
            if deleted == 0:
                raise LookupError(f"service note '{note_id_clean}' was not found")
            return {"success": True}
        finally:
            connection.close()

    def delete_run(self, run_id: str) -> dict[str, Any]:
        run_id = str(run_id).strip()
        if not run_id:
            raise ValueError("run_id is required")
        if self.execution_manager.is_active(run_id):
            raise RuntimeError("run is currently executing; cancel the run and wait before deleting")
        state_db = self.workspace / "runs" / run_id / "state.db"
        if not state_db.is_file():
            raise FileNotFoundError(f"run_id '{run_id}' was not found")
        connection = connect(state_db)
        try:
            row = connection.execute(
                "SELECT 1 FROM tasks WHERE run_id = ? AND state = 'running' LIMIT 1",
                (run_id,),
            ).fetchone()
            if row is not None:
                raise RuntimeError("run has an active task; wait for it to finish before deleting")
        finally:
            connection.close()
        run_root = self.workspace / "runs" / run_id
        if run_root.is_dir():
            shutil.rmtree(run_root)
        for name in (f"{run_id}.json", f"{run_id}.html"):
            p = self.workspace / "reports" / name
            if p.is_file():
                p.unlink()
        return {"success": True}

    def get_run_logs(self, run_id: str) -> dict[str, Any]:
        self._require_run_exists(run_id)
        items = self.execution_manager.get_logs(run_id)
        return {
            "run_id": run_id,
            "log_count": len(items),
            "items": items,
        }

    def get_run_diff(self, current_run_id: str, baseline_run_id: str) -> dict[str, Any]:
        self._require_run_exists(current_run_id)
        if not baseline_run_id:
            raise ValueError("baseline run_id is required")
        self._require_run_exists(baseline_run_id)
        return generate_run_diff(
            baseline_run_id,
            current_run_id,
            workspace=self.workspace,
        )

    def start_execution(self, run_id: str, module: object) -> dict[str, Any]:
        requested_module = str(module).strip() if module is not None else None
        if requested_module and requested_module not in MODULE_EXECUTORS:
            raise ValueError(f"unsupported module '{requested_module}'")

        state_db_path = self.workspace / "runs" / run_id / "state.db"
        if not state_db_path.exists():
            raise FileNotFoundError(f"run state database not found for run_id '{run_id}'")

        connection = connect(state_db_path)
        try:
            run = get_run(connection, run_id)
            if run is None:
                raise LookupError(f"run_id '{run_id}' was not found")
            if run.status == "cancelled":
                if try_revive_resumable_cidr_port_scan(connection, run_id):
                    run = get_run(connection, run_id)
            if run is not None and run.status == "cancelled":
                raise RuntimeError(f"run '{run_id}' is cancelled and cannot be executed")
            tasks = self._load_tasks(connection, run_id)
        finally:
            connection.close()
        if any(task["state"] == "running" for task in tasks):
            raise RuntimeError(f"run '{run_id}' already has a running task")

        if requested_module is None:
            started = self.execution_manager.start(
                run_id,
                lambda: self._execute_all_pending(run_id),
            )
        else:
            started = self.execution_manager.start(
                run_id,
                lambda: self._execute_module(run_id, requested_module),
            )
        if not started:
            raise RuntimeError(f"run '{run_id}' is already executing")
        self.execution_manager.append_log(
            run_id,
            "Execution requested",
            module=cast(PhaseName | None, requested_module),
            data={"mode": requested_module or "all_pending"},
        )
        return self.get_run_view(run_id)

    def cancel_execution(self, run_id: str) -> dict[str, Any]:
        self._require_run_exists(run_id)
        cancel_requested = self.execution_manager.request_cancel(run_id)
        cancelled = cancel_run(run_id, workspace=self.workspace)
        self.execution_manager.append_log(
            run_id,
            "Cancellation requested",
            level="warning",
            data={
                "cancel_requested": cancel_requested,
                "cancelled_task_count": cancelled["cancelled_task_count"],
            },
        )
        return {
            "cancel": cancelled,
            "run": self.get_run_view(run_id)["run"],
            "execution": {
                "active": self.execution_manager.is_active(run_id),
                "cancel_requested": self.execution_manager.is_cancel_requested(run_id),
            },
        }

    def enqueue_dir_enum_followup(self, run_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        state_db_path = self.workspace / "runs" / run_id / "state.db"
        if not state_db_path.exists():
            raise FileNotFoundError(f"run state database not found for run_id '{run_id}'")

        targets = payload.get("targets")
        if not isinstance(targets, list) or not targets:
            raise ValueError("targets must be a non-empty array")
        force = bool(payload.get("force", False))
        recursive = bool(payload.get("recursive", False))
        max_depth_raw = payload.get("max_depth", 1)
        max_depth = int(max_depth_raw) if isinstance(max_depth_raw, (int, float)) else 1
        if max_depth < 1:
            max_depth = 1
        requested_wordlist = str(payload.get("wordlist") or "").strip()
        if requested_wordlist:
            self._patch_run_config(run_id, {"ffuf_wordlist_path": requested_wordlist})

        connection = connect(state_db_path)
        try:
            run = get_run(connection, run_id)
            if run is None:
                raise LookupError(f"run_id '{run_id}' was not found")
            discovered_web, discovered_any = self._load_discovered_service_sets(connection, run_id)
            requested_urls: list[str] = []
            requested_details: list[dict[str, Any]] = []
            invalid_non_web: list[str] = []
            invalid_unknown: list[str] = []

            for item in targets:
                if not isinstance(item, dict):
                    raise ValueError("targets[] entries must be objects")
                base_url = self._normalize_followup_target_to_base_url(item)
                host = urlsplit(base_url).hostname or ""
                parsed_target = urlsplit(base_url)
                port = parsed_target.port
                if port is None:
                    port = 443 if parsed_target.scheme == "https" else 80
                if not host or port is None:
                    raise ValueError(f"invalid target: {item!r}")
                key = (host.casefold(), int(port))
                if key in discovered_any and key not in discovered_web:
                    invalid_non_web.append(f"{host}:{port}")
                    continue
                if key not in discovered_any:
                    invalid_unknown.append(f"{host}:{port}")
                    continue
                requested_urls.append(base_url)
                requested_details.append(
                    {
                        "host": host,
                        "port": int(port),
                        "scheme": urlsplit(base_url).scheme,
                        "base_url": base_url,
                        "service_id": item.get("service_id"),
                    }
                )

            if invalid_non_web:
                raise ValueError(
                    "Directory scan is only available for web services. "
                    f"non-web selections: {', '.join(sorted(set(invalid_non_web)))}"
                )
            if invalid_unknown:
                raise ValueError(
                    f"targets must belong to discovered services in this run: {', '.join(sorted(set(invalid_unknown)))}"
                )

            from scanner.execution.subdomain import filter_scope_urls, load_run_scope_controls

            scope_controls = load_run_scope_controls(run_id, workspace=self.workspace)
            allowed_urls, skipped_urls = filter_scope_urls(requested_urls, scope_controls)

            enqueue_result = enqueue_manual_dir_enum_targets(
                connection,
                run_id,
                base_urls=allowed_urls,
                force=force,
                trigger_label="web_followup",
                recursive=recursive,
                max_depth=max_depth,
            )
            queued_urls = list(enqueue_result.get("queued_urls") or [])
            skipped_entries = list(enqueue_result.get("skipped_entries") or [])
            if skipped_urls:
                skipped_entries.extend(
                    [
                        {"base_url": url, "reason": "out_of_scope"}
                        for url in skipped_urls
                    ]
                )
            skipped_targets = [
                self._build_skipped_target_entry(item) for item in skipped_entries
            ]
            return {
                "run_id": run_id,
                "queued": len(queued_urls),
                "skipped": len(skipped_targets),
                "targets": requested_details,
                "queued_targets": queued_urls,
                "skipped_targets": skipped_targets,
                "task_id": enqueue_result.get("task_id"),
                "message": f"Queued ffuf for {len(queued_urls)} web services",
            }
        finally:
            connection.close()

    @staticmethod
    def _normalize_followup_target_to_base_url(target: dict[str, Any]) -> str:
        base_url_raw = str(target.get("base_url") or "").strip()
        if base_url_raw:
            parsed = urlsplit(base_url_raw)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError(f"invalid base_url '{base_url_raw}'")
            port = parsed.port
            if port is None:
                port = 443 if parsed.scheme == "https" else 80
            netloc = parsed.hostname if (
                (parsed.scheme == "http" and port == 80) or (parsed.scheme == "https" and port == 443)
            ) else f"{parsed.hostname}:{port}"
            return urlunsplit((parsed.scheme, netloc, "/", "", ""))
        host = str(target.get("host") or "").strip()
        if not host:
            raise ValueError("target host is required")
        port_obj = target.get("port")
        if not isinstance(port_obj, (int, float)):
            raise ValueError(f"target port is required for '{host}'")
        port = int(port_obj)
        scheme = str(target.get("scheme") or "").strip().lower()
        if scheme not in {"http", "https"}:
            scheme = "https" if port in {443, 8443} else "http"
        netloc = host if ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)) else f"{host}:{port}"
        return urlunsplit((scheme, netloc, "/", "", ""))

    @staticmethod
    def _load_discovered_service_sets(
        connection: sqlite3.Connection, run_id: str
    ) -> tuple[set[tuple[str, int]], set[tuple[str, int]]]:
        discovered_web: set[tuple[str, int]] = set()
        discovered_any: set[tuple[str, int]] = set()
        rows = connection.execute(
            """
            SELECT module, evidence_json
            FROM findings
            WHERE run_id = ?
              AND module IN ('port_scan', 'http_probe')
            ORDER BY created_at ASC, finding_id ASC
            """,
            (run_id,),
        ).fetchall()
        for row in rows:
            module = str(row["module"])
            try:
                evidence = json.loads(row["evidence_json"] or "{}")
            except json.JSONDecodeError:
                continue
            if not isinstance(evidence, dict):
                continue
            host = str(evidence.get("host") or evidence.get("ip") or "").strip()
            if not host:
                host = str(urlsplit(str(evidence.get("url") or "")).hostname or "").strip()
            port_obj = evidence.get("port")
            if port_obj is None:
                parsed = urlsplit(str(evidence.get("url") or ""))
                if parsed.port is not None:
                    port_obj = parsed.port
                elif parsed.scheme in {"http", "https"}:
                    port_obj = 443 if parsed.scheme == "https" else 80
            if not host or not isinstance(port_obj, (int, float)):
                continue
            port = int(port_obj)
            key = (host.casefold(), port)
            discovered_any.add(key)
            if module == "http_probe":
                discovered_web.add(key)
                continue
            service_name = str(evidence.get("service") or evidence.get("name") or "").lower()
            protocol = str(evidence.get("protocol") or "").lower()
            if (
                "http" in service_name
                or "https" in service_name
                or "http" in protocol
                or port in {80, 443, 8080, 8443}
            ):
                discovered_web.add(key)
        return discovered_web, discovered_any

    @staticmethod
    def _build_skipped_target_entry(item: dict[str, Any]) -> dict[str, Any]:
        base_url = str(item.get("base_url") or "")
        reason = str(item.get("reason") or "unknown")
        parsed = urlsplit(base_url)
        host = str(parsed.hostname or "")
        port = parsed.port
        if port is None and parsed.scheme in {"http", "https"}:
            port = 443 if parsed.scheme == "https" else 80
        return {
            "host": host,
            "port": int(port) if isinstance(port, int) else None,
            "base_url": base_url,
            "reason": reason,
        }

    def render_report_html(self, run_id: str, *, baseline_run_id: str | None = None) -> str:
        from scanner.report import render_html_report

        summary = generate_report_summary(run_id, workspace=self.workspace)
        if baseline_run_id:
            summary = {**summary, "diff_summary": generate_run_diff(baseline_run_id, run_id, workspace=self.workspace)}
        return render_html_report(summary)

    def _dashboard_runs(self) -> list[dict[str, Any]]:
        runs = self.list_runs()
        result = []
        for run in runs:
            status = str(run.get("status", ""))
            progress = cast(dict[str, Any], run.get("progress") or {})
            task_counts = cast(dict[str, Any], run.get("task_counts") or {})
            started_at = run.get("started_at")
            completed_at = run.get("completed_at")
            duration_str = ""
            if started_at and completed_at:
                try:
                    from datetime import datetime as _dt
                    s = _dt.fromisoformat(started_at)
                    e = _dt.fromisoformat(completed_at)
                    secs = int((e - s).total_seconds())
                    duration_str = f"{secs // 60}m {secs % 60:02d}s"
                except Exception:
                    pass
            host_count = int(progress.get("host_count") or 0)
            finding_count = int(task_counts.get("completed") or 0)
            report: dict[str, Any] = {}
            if status == "completed":
                try:
                    report = generate_report_summary(str(run["run_id"]), workspace=self.workspace)
                    host_groups = report.get("host_groups") or []
                    host_count = len(host_groups)
                    finding_count = int(report.get("run_summary", {}).get("observed_finding_count") or 0)
                    finding_count += int(report.get("run_summary", {}).get("candidate_cve_count") or 0)
                except Exception:
                    pass
            result.append({
                "id": run["run_id"],
                "name": str(run.get("display_name") or run["run_id"]),
                "target": str(run.get("target", "")),
                "status": status,
                "created_at": str(run.get("created_at", "")),
                "duration": duration_str,
                "modules": list(run.get("modules") or []),
                "host_count": host_count,
                "finding_count": finding_count,
            })
        return result

    def _dashboard_run_report(self, run_id: str) -> dict[str, Any]:
        self._require_run_exists(run_id)
        summary = generate_report_summary(run_id, workspace=self.workspace)
        host_groups = summary.get("host_groups") or []

        hosts = []
        services: dict[str, list[dict[str, Any]]] = {}
        findings: dict[str, Any] = {}

        for grp in host_groups:
            host_label = str(grp["host"])
            open_ports = grp.get("open_ports") or []
            http_probe = grp.get("http_probe") or []
            dir_findings = grp.get("directory_findings") or []
            cves = grp.get("candidate_cves") or []
            artifacts = grp.get("artifacts") or []
            domain_map_rows = grp.get("domain_mappings") or []
            banner_rows = grp.get("banner_findings") or []
            domain_mappings_ui: list[dict[str, Any]] = []
            for dm in domain_map_rows:
                ev = dm.get("evidence") or {}
                if not isinstance(ev, dict):
                    continue
                d = str(ev.get("domain") or "").strip()
                if not d:
                    continue
                src = str(ev.get("source") or "")
                href = f"http://{d}/" if src == "http" else f"https://{d}/"
                domain_mappings_ui.append({"domain": d, "source": src, "href": href})
            banner_by_port: dict[int, dict[str, Any]] = {}
            for bf in banner_rows:
                ev = bf.get("evidence") or {}
                if not isinstance(ev, dict):
                    continue
                p = ev.get("port")
                if p is None:
                    continue
                try:
                    banner_by_port[int(p)] = ev
                except (TypeError, ValueError):
                    continue

            web_ports: set[int] = set()
            for probe in http_probe:
                ev = probe.get("evidence") or {}
                p = ev.get("port")
                if isinstance(p, int):
                    web_ports.add(p)
                elif isinstance(p, str) and p.isdigit():
                    web_ports.add(int(p))

            port_list: list[dict[str, Any]] = []
            for port_item in open_ports:
                ev = port_item.get("evidence") or {}
                port_num = ev.get("port")
                if port_num is None:
                    continue
                port_num = int(port_num)
                is_web = port_num in web_ports or str(ev.get("service", "")).lower() in ("http", "https")
                port_list.append({
                    "id": str(port_item.get("finding_id", "")),
                    "port": port_num,
                    "protocol": str(ev.get("protocol") or "tcp"),
                    "service_name": str(ev.get("service") or "unknown"),
                    "is_web": is_web,
                    "banner": " ".join(filter(None, [
                        ev.get("product"), ev.get("version")
                    ])) or str(ev.get("service") or ""),
                })
            for probe in http_probe:
                ev = probe.get("evidence") or {}
                port_num = ev.get("port")
                if port_num is None:
                    p_url = str(ev.get("url") or "")
                    if ":443" in p_url or p_url.startswith("https"):
                        port_num = 443
                    else:
                        port_num = 80
                port_num = int(port_num)
                if not any(p["port"] == port_num for p in port_list):
                    port_list.append({
                        "id": str(probe.get("finding_id", "")),
                        "port": port_num,
                        "protocol": "tcp",
                        "service_name": "https" if port_num == 443 else "http",
                        "is_web": True,
                        "banner": str(ev.get("webserver") or ev.get("server") or ""),
                    })

            for port_info in port_list:
                pnum = int(port_info["port"])
                if pnum in banner_by_port:
                    bev = banner_by_port[pnum]
                    gs = str(bev.get("guessed_service") or "unknown")
                    prev = str(bev.get("banner_preview") or "").strip()
                    port_info["banner"] = f"{gs}: {prev[:500]}" if prev else gs

            hosts.append({
                "id": host_label,
                "label": host_label,
                "ip": (grp.get("ip_addresses") or [""])[0],
                "type": "domain" if not host_label.replace(".", "").isdigit() else "ip",
                "ports_count": len(port_list),
                "findings_count": len(dir_findings) + len(cves) + sum(
                    1 for p in http_probe if (p.get("evidence") or {}).get("status_code") in (401, 403)
                ),
                "has_web": bool(web_ports) or any(p["is_web"] for p in port_list),
                "domain_mappings": domain_mappings_ui,
            })
            services[host_label] = port_list

            for port_info in port_list:
                fkey = f"{host_label}:{port_info['port']}"
                probe_for_port = next(
                    (p for p in http_probe if int((p.get("evidence") or {}).get("port") or (443 if port_info["port"] == 443 else 80)) == port_info["port"]),
                    None,
                )
                overview: dict[str, Any] = {}
                if probe_for_port:
                    ev = probe_for_port.get("evidence") or {}
                    overview = {
                        "status_code": ev.get("status_code"),
                        "title": ev.get("title"),
                        "server": ev.get("webserver") or ev.get("server"),
                        "content_type": ev.get("content_type"),
                        "response_time": f"{ev.get('response_time_ms') or ev.get('time_ms', '')}ms" if ev.get("response_time_ms") or ev.get("time_ms") else None,
                        "redirect_chain": ev.get("redirect_chain") or [],
                        "tls": ev.get("tls"),
                    }
                else:
                    port_ev = (next(
                        (p.get("evidence") or {} for p in open_ports if int((p.get("evidence") or {}).get("port") or 0) == port_info["port"]),
                        {},
                    ))
                    overview = {"banner": port_ev.get("product") or port_ev.get("version")}

                port_dirs = [
                    {
                        "id": str(d.get("finding_id", "")),
                        "path": str((d.get("evidence") or {}).get("path") or d.get("target") or ""),
                        "status": (d.get("evidence") or {}).get("status_code"),
                        "size": str((d.get("evidence") or {}).get("size") or "—"),
                        "redirect": (d.get("evidence") or {}).get("redirect_location"),
                    }
                    for d in dir_findings
                    if str((d.get("evidence") or {}).get("port") or "") == str(port_info["port"])
                    or not (d.get("evidence") or {}).get("port")
                ]
                port_cves = [
                    {
                        "id": str(c.get("finding_id", "")),
                        "cve_id": str((c.get("evidence") or {}).get("cve_id") or c.get("summary") or ""),
                        "severity": str((c.get("evidence") or {}).get("severity") or "info"),
                        "cvss": (c.get("evidence") or {}).get("cvss") or 0.0,
                        "title": str(c.get("summary") or ""),
                        "affected": str((c.get("evidence") or {}).get("affected") or ""),
                        "fixed_in": str((c.get("evidence") or {}).get("fixed_in") or ""),
                    }
                    for c in cves
                    if str((c.get("evidence") or {}).get("port") or "") == str(port_info["port"])
                    or not (c.get("evidence") or {}).get("port")
                ]
                port_artifacts = [
                    {
                        "id": str(a.get("artifact_id", "")),
                        "name": str(a.get("path", "").split("/")[-1] or a.get("artifact_id", "")),
                        "module": str(a.get("module", "")),
                        "size": f"{a.get('size_bytes', 0) / 1024:.1f}KB" if a.get("size_bytes") else "—",
                        "path": str(a.get("path", "")),
                    }
                    for a in artifacts
                ]
                http_findings: list[dict[str, Any]] = []
                if probe_for_port:
                    ev = probe_for_port.get("evidence") or {}
                    missing_hdrs = [str(h) for h in (ev.get("missing_headers") or [])]
                    for hdr in missing_hdrs:
                        http_findings.append({
                            "id": f"hdr-{hdr}",
                            "severity": "medium",
                            "type": "header",
                            "title": f"Missing {hdr}",
                            "detail": f"Response is missing the {hdr} header.",
                        })
                    if ev.get("status_code") in (401, 403):
                        http_findings.append({
                            "id": f"auth-{port_info['port']}",
                            "severity": "info",
                            "type": "auth",
                            "title": f"Auth required ({ev.get('status_code')})",
                            "detail": str(probe_for_port.get("summary") or ""),
                        })

                findings[fkey] = {
                    "overview": overview,
                    "http": http_findings if port_info["is_web"] else None,
                    "directories": port_dirs if port_info["is_web"] else None,
                    "cves": port_cves,
                    "artifacts": port_artifacts,
                }

        return {
            "run_id": run_id,
            "hosts": hosts,
            "services": services,
            "findings": findings,
        }

    def _dashboard_run_diff(self, run_id: str, baseline_run_id: str) -> dict[str, Any]:
        if not baseline_run_id:
            return {"hosts": {}, "services": {}, "findings": {}}
        diff = self.get_run_diff(run_id, baseline_run_id)
        result: dict[str, Any] = {"hosts": {}, "services": {}, "findings": {}}
        categories = diff.get("categories") or {}
        for category_name, category in categories.items():
            for item in category.get("added") or []:
                ev = (item.get("evidence") or {})
                host = str(ev.get("host") or ev.get("hostname") or item.get("target") or "")
                if category_name == "open_ports":
                    port = ev.get("port")
                    if host and port:
                        result["services"][f"{host}:{port}"] = "added"
                elif category_name == "http_probe_results":
                    if host:
                        result["hosts"][host] = "added"
                elif category_name in ("directory_findings", "candidate_cves"):
                    fid = str(item.get("finding_id") or "")
                    if fid:
                        result["findings"][fid] = "added"
        return result

    def _execute_all_pending(self, run_id: str) -> None:
        # Multiple passes let the ai_triage phase enqueue scope-locked follow-up scans
        # (and re-queue itself) and have that new work executed within the same run.
        # Without ai_triage this collapses to a single pass (original behavior).
        max_passes = self._max_execution_passes(run_id)
        previous_signature: frozenset[str] | None = None
        for _pass in range(max_passes):
            if self.execution_manager.is_cancel_requested(run_id):
                self.execution_manager.append_log(run_id, "Execution loop stopped by cancellation request", level="warning")
                break
            executed_any = False
            for module in self._execution_module_order(run_id):
                if self.execution_manager.is_cancel_requested(run_id):
                    self.execution_manager.append_log(run_id, "Execution loop stopped by cancellation request", level="warning")
                    break
                view = self.get_run_view(run_id)
                if str(view["run"]["status"]) == "cancelled":
                    self.execution_manager.append_log(run_id, "Execution loop observed cancelled run state", level="warning")
                    break
                pending_modules = {
                    str(task["module"])
                    for task in view["tasks"]
                    if str(task["state"]) in {"pending", "failed"}
                }
                if module not in pending_modules:
                    continue
                self._execute_module(run_id, module)
                executed_any = True
            signature = self._pending_task_signature(run_id)
            # Stop when there is no pending work, nothing ran, or no progress was made
            # (guards against re-running a permanently failing task forever).
            if not signature or not executed_any or signature == previous_signature:
                break
            previous_signature = signature
        self._finalize_run_after_execution(run_id)

    def _max_execution_passes(self, run_id: str) -> int:
        view = self.get_run_view(run_id)
        config = view["run"]["config"]
        enabled = [str(module) for module in config.get("enabled_phases", [])]
        if "ai_triage" not in enabled:
            return 1
        iterations = int(config.get("ai_max_iterations", 3) or 3)
        return 1 + 2 * max(1, iterations)

    def _pending_task_signature(self, run_id: str) -> frozenset[str]:
        view = self.get_run_view(run_id)
        return frozenset(
            f"{task['task_id']}:{task['state']}"
            for task in view["tasks"]
            if str(task["state"]) in {"pending", "failed"}
        )

    def _finalize_run_after_execution(self, run_id: str) -> None:
        state_db_path = self.workspace / "runs" / run_id / "state.db"
        if not state_db_path.exists():
            return
        connection = connect(state_db_path)
        try:
            run = get_run(connection, run_id)
            if run is None or run.status == "cancelled":
                return
            tasks = get_tasks(connection, run_id)
            if not tasks:
                return
            states = {str(task.state) for task in tasks}
            if states & {"pending", "running"}:
                return
            if "failed" in states:
                mark_run_finished(connection, run_id, "failed")
            else:
                mark_run_finished(connection, run_id, "completed")
        finally:
            connection.close()

    def _execution_module_order(self, run_id: str) -> list[str]:
        view = self.get_run_view(run_id)
        enabled_modules = [str(module) for module in view["run"]["config"].get("enabled_phases", [])]
        ordered: list[str] = []
        for module in enabled_modules:
            if module in MODULE_EXECUTORS and module not in ordered:
                ordered.append(module)
        for module in MODULE_ORDER:
            if module not in ordered:
                ordered.append(module)
        return ordered

    def _execute_module(self, run_id: str, module: str) -> dict[str, Any]:
        module_name = cast(PhaseName, module)
        if self.execution_manager.is_cancel_requested(run_id):
            self.execution_manager.append_log(run_id, "Skipped module after cancellation request", level="warning", module=module_name)
            return {"run_id": run_id, "module": module, "skipped": True}
        self.execution_manager.append_log(run_id, "Module execution started", module=module_name)
        result = MODULE_EXECUTORS[module](run_id, workspace=self.workspace)
        self.execution_manager.append_log(run_id, "Module execution finished", module=module_name, data=result)
        return result

    def _load_tasks(self, connection: sqlite3.Connection, run_id: str) -> list[dict[str, Any]]:
        return [
            {
                "task_id": task.task_id,
                "module": task.module,
                "tool": task.tool,
                "scope": task.scope,
                "state": task.state,
                "attempts": task.attempts,
                "last_error": task.last_error,
                "cursor_json": task.cursor_json,
                "started_at": task.started_at.isoformat() if task.started_at else None,
                "completed_at": task.completed_at.isoformat() if task.completed_at else None,
                "created_at": task.created_at.isoformat(),
                "updated_at": task.updated_at.isoformat(),
                "progress": summarize_task_progress(task).model_dump(mode="json"),
            }
            for task in get_tasks(connection, run_id)
        ]

    def _task_counts(self, tasks: list[dict[str, Any]]) -> dict[str, int]:
        counts = {"pending": 0, "running": 0, "completed": 0, "failed": 0, "cancelled": 0, "other": 0}
        for task in tasks:
            state = str(task["state"])
            if state in counts:
                counts[state] += 1
            else:
                counts["other"] += 1
        return counts

    def _build_run_progress(self, tasks: list[dict[str, Any]]) -> dict[str, Any]:
        current_phase: str | None = None
        active_task_id: str | None = None
        for task in tasks:
            if str(task["state"]) == "running":
                current_phase = str(task["module"])
                active_task_id = str(task["task_id"])
                break
        if current_phase is None:
            for task in tasks:
                if str(task["state"]) in {"pending", "failed"}:
                    current_phase = str(task["module"])
                    active_task_id = str(task["task_id"])
                    break
        return {
            "current_phase": current_phase,
            "active_task_id": active_task_id,
            "total_tasks": len(tasks),
            "completed_tasks": sum(1 for task in tasks if str(task["state"]) == "completed"),
            "cancelled_tasks": sum(1 for task in tasks if str(task["state"]) == "cancelled"),
            "tasks": [task["progress"] for task in tasks],
        }

    def _build_execution_plan(
        self,
        enabled_modules: list[str],
        tasks: list[dict[str, Any]],
    ) -> dict[str, Any]:
        ordered_modules: list[str] = []
        for module in enabled_modules:
            if module in MODULE_EXECUTORS and module not in ordered_modules:
                ordered_modules.append(module)
        for module in MODULE_ORDER:
            if module in MODULE_EXECUTORS and module not in ordered_modules:
                ordered_modules.append(module)

        task_groups: dict[str, list[dict[str, Any]]] = {}
        for task in tasks:
            task_groups.setdefault(str(task["module"]), []).append(task)

        items: list[dict[str, Any]] = []
        for module in ordered_modules:
            module_tasks = task_groups.get(module, [])
            items.append(
                {
                    "module": module,
                    "state": self._aggregate_execution_plan_state(module_tasks),
                    "task_count": len(module_tasks),
                    "scope_count": len({str(task["scope"]) for task in module_tasks}),
                    "current_phase": self._aggregate_execution_plan_phase(module_tasks),
                }
            )

        focus_index: int | None = None
        for index, item in enumerate(items):
            if item["state"] == "running":
                focus_index = index
                break
        if focus_index is None:
            for index, item in enumerate(items):
                if item["state"] in {"pending", "failed"}:
                    focus_index = index
                    break

        stage_counts: dict[str, int] = {
            "current": 0,
            "next": 0,
            "upcoming": 0,
            "revisit": 0,
            "completed": 0,
            "failed": 0,
            "cancelled": 0,
        }
        for index, item in enumerate(items):
            display_state = self._execution_plan_display_state(str(item["state"]), index, focus_index)
            item["display_state"] = display_state
            stage_counts[display_state] = stage_counts.get(display_state, 0) + 1

        return {
            "focus_index": focus_index,
            "items": items,
            "counts": stage_counts,
        }

    @staticmethod
    def _aggregate_execution_plan_state(tasks: list[dict[str, Any]]) -> str:
        if not tasks:
            return "pending"
        states = {str(task["state"]) for task in tasks}
        for preferred in ("running", "failed", "pending", "cancelled", "completed"):
            if preferred in states:
                return preferred
        return str(tasks[0]["state"])

    @staticmethod
    def _aggregate_execution_plan_phase(tasks: list[dict[str, Any]]) -> str | None:
        for task in tasks:
            progress = cast(dict[str, Any], task.get("progress") or {})
            phase = progress.get("current_phase")
            if phase:
                return str(phase)
        return None

    @staticmethod
    def _execution_plan_display_state(state: str, index: int, focus_index: int | None) -> str:
        if focus_index is None:
            if state in {"completed", "failed", "cancelled"}:
                return state
            return "next"
        if index == focus_index:
            return "current" if state == "running" else "next"
        if index > focus_index:
            return "revisit" if state == "completed" else "upcoming"
        if state in {"failed", "cancelled"}:
            return state
        return "completed"

    def _build_execution_notes(self, tasks: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        raw_tasks: list[TaskState] = []
        for task_dict in tasks:
             # Repack into TaskState for summarize_execution_notes
             raw_tasks.append(TaskState(
                 task_id=str(task_dict["task_id"]),
                 run_id="", # Not needed for summary
                 module=cast(Any, task_dict["module"]),
                 tool=cast(Any, task_dict["tool"]),
                 scope=str(task_dict["scope"]),
                 state=cast(Any, task_dict["state"]),
                 cursor_json=task_dict.get("cursor_json"),
                 attempts=int(task_dict["attempts"]),
                 last_error=task_dict.get("last_error"),
                 created_at=datetime.fromisoformat(task_dict["created_at"]),
                 updated_at=datetime.fromisoformat(task_dict["updated_at"]),
             ))
        notes = summarize_execution_notes(raw_tasks)
        return {
            key: sorted(value, key=self._execution_note_sort_key)
            for key, value in notes.items()
        }

    @staticmethod
    def _execution_note_sort_key(item: dict[str, Any]) -> tuple[str, str, str]:
        base_url = str(item.get("base_url") or "")
        scope = str(item.get("scope") or "")
        task_id = str(item.get("task_id") or "")
        return (base_url, scope, task_id)

    def _extract_config_patch(self, payload: dict[str, Any]) -> dict[str, Any]:
        patch = {
            key: payload[key]
            for key in PATCHABLE_CONFIG_FIELDS
            if key in payload
        }
        auth_field_keys = {"extra_headers_text", "cookies", "bearer_token", "host_header"}
        if any(key in payload for key in auth_field_keys):
            headers = parse_header_lines(payload.get("extra_headers_text"))
            cookies = str(payload.get("cookies") or "").strip()
            bearer_token = str(payload.get("bearer_token") or "").strip()
            host_header = str(payload.get("host_header") or "").strip()
            if cookies:
                headers["Cookie"] = cookies
            if bearer_token:
                headers["Authorization"] = f"Bearer {bearer_token}"
            if host_header:
                headers["Host"] = host_header
            patch["extra_headers"] = headers
        return patch

    def _resolve_preset(self, value: object) -> dict[str, Any] | None:
        if value in (None, ""):
            return None
        preset_name = str(value).strip().lower()
        presets = cast(dict[str, dict[str, Any]], self.list_presets()["presets"])
        if preset_name not in presets:
            values = ", ".join(sorted(presets))
            raise ValueError(f"unsupported preset '{value}'. expected one of: {values}")
        return presets[preset_name]

    def _default_local_binary_patch(self) -> dict[str, str]:
        patch: dict[str, str] = {}
        custom_paths = self._custom_tool_paths()
        for field_name, binary_name in TOOL_BINARY_FIELDS:
            configured = custom_paths.get(binary_name)
            if configured:
                patch[field_name] = configured
                continue
            resolved = resolve_default_binary_path(binary_name)
            if resolved is not None:
                patch[field_name] = str(resolved)
        return patch

    def _patch_run_config(
        self,
        run_id: str,
        patch: dict[str, Any],
        *,
        allow_running_updates: bool = False,
    ) -> None:
        if not patch:
            return

        state_db_path = self.workspace / "runs" / run_id / "state.db"
        connection = sqlite3.connect(state_db_path)
        try:
            row = connection.execute(
                "SELECT config_json FROM runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            if row is None:
                raise LookupError(f"run_id '{run_id}' was not found")
            if not allow_running_updates and self.execution_manager.is_active(run_id):
                raise RuntimeError(f"run '{run_id}' is executing; wait for it to finish before changing options")
            running_task = connection.execute(
                "SELECT 1 FROM tasks WHERE run_id = ? AND state = 'running' LIMIT 1",
                (run_id,),
            ).fetchone()
            if not allow_running_updates and running_task is not None:
                raise RuntimeError(f"run '{run_id}' has a running task; wait for it to finish before changing options")
            config = json.loads(row[0])
            for key, value in patch.items():
                if key == "ffuf_wordlist_path":
                    if value in (None, ""):
                        # Keep current or default value
                        continue
                    wordlist_path = self._resolve_workspace_path(str(value))
                    config[key] = str(wordlist_path)
                    continue
                if value in (None, ""):
                    continue
                config[key] = value
            validated = ScanConfig.model_validate(config)
            connection.execute(
                "UPDATE runs SET config_json = ?, updated_at = CURRENT_TIMESTAMP WHERE run_id = ?",
                (json.dumps(validated.model_dump(mode="json"), sort_keys=True, separators=(",", ":")), run_id),
            )
            connection.commit()
        finally:
            connection.close()

    def _scope_controls_path(self, run_id: str) -> Path:
        return resolve_scope_controls_path(run_id, workspace=self.workspace)

    def _load_scope_controls(self, run_id: str, target: str) -> dict[str, Any]:
        path = self._scope_controls_path(run_id)
        raw: dict[str, Any] = {}
        if path.exists():
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                raw = loaded
        include = parse_scope_entries(raw.get("include"))
        exclude = parse_scope_entries(raw.get("exclude"))
        effective_targets = include or [target]
        return {
            "base_target": target,
            "include": include,
            "exclude": exclude,
            "effective_targets": effective_targets,
        }

    def _write_scope_controls(self, run_id: str, payload: dict[str, Any]) -> None:
        if not any(key in payload for key in SCOPE_CONTROL_FIELDS):
            return
        path = self._scope_controls_path(run_id)
        current = self._load_scope_controls(run_id, target="")
        include = current["include"]
        exclude = current["exclude"]
        if "scope_include" in payload:
            include = parse_scope_entries(payload.get("scope_include"))
        if "scope_exclude" in payload:
            exclude = parse_scope_entries(payload.get("scope_exclude"))
        if not include and not exclude:
            if path.exists():
                path.unlink()
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({"include": include, "exclude": exclude}, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def _resolve_workspace_path(self, value: str) -> Path:
        path = Path(value)
        return path.resolve() if path.is_absolute() else (self.workspace / path).resolve()

    def _require_run_exists(self, run_id: str) -> None:
        state_db_path = self.workspace / "runs" / run_id / "state.db"
        if not state_db_path.exists():
            raise FileNotFoundError(f"run state database not found for run_id '{run_id}'")
        connection = connect(state_db_path)
        try:
            run = get_run(connection, run_id)
            if run is None:
                raise LookupError(f"run_id '{run_id}' was not found")
        finally:
            connection.close()

    def _read_json(self, handler: BaseHTTPRequestHandler) -> dict[str, Any]:
        length = int(handler.headers.get("Content-Length", "0"))
        raw_body = handler.rfile.read(length) if length > 0 else b"{}"
        payload = json.loads(raw_body.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("JSON request body must be an object")
        return payload

    def _write_json(
        self,
        handler: BaseHTTPRequestHandler,
        payload: dict[str, Any],
        *,
        status: HTTPStatus = HTTPStatus.OK,
    ) -> None:
        write_json_response(handler, payload, status=status)

    def _redirect_response(
        self,
        handler: BaseHTTPRequestHandler,
        location: str,
        *,
        status: HTTPStatus = HTTPStatus.FOUND,
    ) -> None:
        write_redirect_response(handler, location, status=status)

    def _serve_react_app(self, handler: BaseHTTPRequestHandler) -> None:
        self._write_html(handler, DASHBOARD_HTML)

    def _is_react_app_route(self, path_parts: list[str]) -> bool:
        app_pages = {
            "execution",
            "summary",
            "findings",
            "artifacts",
            "reports",
            "settings",
            "tools",
            "profiles",
            "wordlists",
        }
        return path_parts == ["runs"] or (
            len(path_parts) == 1 and path_parts[0] in app_pages
        ) or (
            len(path_parts) == 3
            and path_parts[0] == "runs"
            and path_parts[2] in app_pages
        )

    def _write_artifact_content(self, handler: BaseHTTPRequestHandler, artifact_path: str) -> None:
        if not artifact_path:
            self._write_json(handler, {"error": "path is required"}, status=HTTPStatus.BAD_REQUEST)
            return
        candidate = Path(artifact_path)
        if not candidate.is_absolute():
            candidate = self.workspace / artifact_path
        try:
            workspace_root = self.workspace.resolve(strict=False)
            resolved = candidate.resolve(strict=True)
        except FileNotFoundError:
            self._write_json(handler, {"error": "artifact not found"}, status=HTTPStatus.NOT_FOUND)
            return
        except OSError:
            self._write_json(handler, {"error": "artifact not accessible"}, status=HTTPStatus.BAD_REQUEST)
            return
        try:
            resolved.relative_to(workspace_root)
        except ValueError:
            self._write_json(handler, {"error": "artifact path is outside workspace"}, status=HTTPStatus.FORBIDDEN)
            return
        if not resolved.is_file():
            self._write_json(handler, {"error": "artifact not found"}, status=HTTPStatus.NOT_FOUND)
            return
        try:
            content = resolved.read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            self._write_json(handler, {"error": "artifact not found"}, status=HTTPStatus.NOT_FOUND)
            return
        except OSError:
            _log.exception("failed reading artifact %s", resolved)
            self._write_json(
                handler,
                {"error": "failed to read artifact"},
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
            )
            return
        write_text_response(handler, content, status=HTTPStatus.OK)

    def _write_html(
        self,
        handler: BaseHTTPRequestHandler,
        body: str,
        *,
        status: HTTPStatus = HTTPStatus.OK,
    ) -> None:
        write_html_response(handler, body, status=status)

def serve_ui(
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
    workspace: Path | None = None,
) -> None:
    handle = start_ui_server(host=host, port=port, workspace=workspace)
    try:
        handle.thread.join()
    except KeyboardInterrupt:
        pass
    finally:
        handle.close()


def start_ui_server(
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
    workspace: Path | None = None,
) -> UIServerHandle:
    app = WebUIApp(workspace=workspace)
    httpd = LocalThreadingHTTPServer((host, port), app.build_handler())
    thread = threading.Thread(target=httpd.serve_forever, daemon=True, name="scanner-ui-http")
    thread.start()
    actual_host, actual_port = httpd.server_address[:2]
    return UIServerHandle(
        httpd=httpd,
        thread=thread,
        host=str(actual_host),
        port=int(actual_port),
    )


# Legacy vanilla UI removed in Phase 9.
# React dashboard is now the only UI.
