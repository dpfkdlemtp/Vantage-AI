from __future__ import annotations

import json
import subprocess

import pytest

from scanner.adapters.httpx_runner import HttpxError, run_httpx_probe


def test_run_httpx_probe_parses_successful_jsonl() -> None:
    captured_command: list[str] = []
    captured_stdin: list[str] = []

    def runner(command: list[str], stdin_text: str) -> subprocess.CompletedProcess[str]:
        captured_command[:] = command
        captured_stdin[:] = [stdin_text]
        stdout = "\n".join(
            [
                json.dumps(
                    {
                        "input": "api.example.com",
                        "url": "https://api.example.com/",
                        "status_code": 200,
                        "title": "API",
                        "tech": ["nginx"],
                        "content_type": "text/html",
                        "webserver": "nginx",
                        "ip": "1.2.3.4",
                        "cname": ["api-origin.example.com"],
                        "probe_status": "success",
                    }
                ),
                json.dumps(
                    {
                        "input": "www.example.com",
                        "url": "https://www.example.com/login",
                        "port": "443",
                        "status_code": 302,
                        "probe_status": "success",
                    }
                ),
            ]
        )
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    result = run_httpx_probe(
        ["api.example.com", "www.example.com"],
        httpx_bin="httpx-custom",
        profile="balanced",
        rate_limit_per_second=55,
        runner=runner,
    )

    assert captured_command[0] == "httpx-custom"
    assert "-json" in captured_command
    assert "-threads" in captured_command
    assert "-rate-limit" in captured_command
    assert captured_stdin == ["api.example.com\nwww.example.com"]
    assert len(result.entries) == 2
    assert result.entries[0].host == "api.example.com"
    assert result.entries[0].technologies == ["nginx"]
    assert result.entries[1].path == "/login"
    assert result.entries[1].port == 443


def test_run_httpx_probe_handles_empty_output() -> None:
    def runner(command: list[str], stdin_text: str) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    result = run_httpx_probe(["api.example.com"], runner=runner)

    assert result.entries == []
    assert result.raw_output == ""


def test_run_httpx_probe_raises_on_failure() -> None:
    def runner(command: list[str], stdin_text: str) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="httpx failed")

    with pytest.raises(HttpxError, match="httpx exited with code 1: httpx failed"):
        run_httpx_probe(["api.example.com"], runner=runner)
