from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from scanner.adapters.ffuf_runner import FfufError, run_ffuf_scan


def test_run_ffuf_scan_parses_successful_json_output(tmp_path: Path) -> None:
    wordlist_path = tmp_path / "words.txt"
    wordlist_path.write_text("admin\nlogin\n", encoding="utf-8")
    output_path = tmp_path / "ffuf.json"
    captured_command: list[str] = []

    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        captured_command[:] = command
        output_path.write_text(
            json.dumps(
                {
                    "results": [
                        {
                            "input": {"FUZZ": "admin"},
                            "status": 200,
                            "length": 1234,
                            "words": 111,
                            "lines": 25,
                            "content-type": "text/html",
                            "url": "https://app.example.com/admin",
                            "host": "app.example.com",
                        },
                        {
                            "input": {"FUZZ": "login.php"},
                            "status": 302,
                            "length": 0,
                            "words": 0,
                            "lines": 0,
                            "redirectlocation": "https://app.example.com/sign-in",
                            "url": "https://app.example.com/login.php",
                            "host": "app.example.com",
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    result = run_ffuf_scan(
        "https://app.example.com/",
        output_path=output_path,
        ffuf_bin="ffuf-custom",
        wordlist_path=wordlist_path,
        profile="balanced",
        threads=40,
        match_status_codes=[403, 200],
        extensions=["php", ".txt"],
        auto_calibration=True,
        per_host_auto_calibration=True,
        filter_sizes=[1234, 512, 1234],
        runner=runner,
    )

    assert captured_command[0] == "ffuf-custom"
    assert "-u" in captured_command
    assert "https://app.example.com/FUZZ" in captured_command
    assert "-of" in captured_command
    assert "json" in captured_command
    assert "-t" in captured_command
    assert captured_command[captured_command.index("-t") + 1] == "25"
    assert "-ac" in captured_command
    assert "-ach" in captured_command
    assert captured_command[captured_command.index("-mc") + 1] == "200,403"
    assert captured_command[captured_command.index("-e") + 1] == "php,txt"
    assert captured_command[captured_command.index("-fs") + 1] == "512,1234"
    assert len(result.matches) == 2
    assert result.matches[0].input_value == "admin"
    assert result.matches[1].redirect_target == "https://app.example.com/sign-in"


def test_run_ffuf_scan_handles_empty_result_set(tmp_path: Path) -> None:
    wordlist_path = tmp_path / "words.txt"
    wordlist_path.write_text("admin\n", encoding="utf-8")
    output_path = tmp_path / "ffuf.json"
    captured_command: list[str] = []

    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        captured_command[:] = command
        output_path.write_text(json.dumps({"results": []}), encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    result = run_ffuf_scan(
        "https://app.example.com/",
        output_path=output_path,
        wordlist_path=wordlist_path,
        auto_calibration=False,
        per_host_auto_calibration=False,
        runner=runner,
    )

    assert "-ac" not in captured_command
    assert "-ach" not in captured_command
    assert result.matches == []
    assert json.loads(result.raw_output) == {"results": []}


def test_run_ffuf_scan_raises_on_subprocess_failure(tmp_path: Path) -> None:
    wordlist_path = tmp_path / "words.txt"
    wordlist_path.write_text("admin\n", encoding="utf-8")

    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="ffuf failed")

    with pytest.raises(FfufError, match="ffuf exited with code 1: ffuf failed"):
        run_ffuf_scan(
            "https://app.example.com/",
            output_path=tmp_path / "ffuf.json",
            wordlist_path=wordlist_path,
            runner=runner,
        )
