from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest

from scanner.execution import portscan
from scanner.adapters.nmap_runner import NmapError, run_nmap_scan


def test_run_nmap_scan_parses_successful_xml_output() -> None:
    captured_command: list[str] = []

    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        captured_command[:] = command
        stdout = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" />
    <address addr="203.0.113.10" addrtype="ipv4" />
    <hostnames>
      <hostname name="api.example.com" type="user" />
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" />
        <service name="ssh" product="OpenSSH" version="9.0" />
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" />
        <service name="https" product="nginx" version="1.25.3" />
      </port>
    </ports>
  </host>
</nmaprun>
"""
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    result = run_nmap_scan(
        ["api.example.com", "blog.example.com"],
        nmap_bin="nmap-custom",
        profile="balanced",
        ports="22,80,443",
        timing_template="T4",
        version_detection=True,
        runner=runner,
    )

    assert captured_command[0] == "nmap-custom"
    assert "-oX" in captured_command
    assert "-" in captured_command
    assert "-sS" in captured_command
    assert "-v" in captured_command
    assert "--stats-every" in captured_command
    assert "10s" in captured_command
    assert "-Pn" in captured_command
    assert "-n" in captured_command
    assert "--max-retries" in captured_command
    assert captured_command[captured_command.index("--max-retries") + 1] == "1"
    assert "--disable-arp-ping" in captured_command
    assert "--send-ip" in captured_command
    assert "-T3" in captured_command
    assert "-sV" in captured_command
    assert "-p" in captured_command
    assert "22,80,443" in captured_command
    assert captured_command[-2:] == ["api.example.com", "blog.example.com"]
    assert len(result.hosts) == 1
    assert result.hosts[0].host == "api.example.com"
    assert result.hosts[0].ip == "203.0.113.10"
    assert result.hosts[0].ports[0].service == "ssh"
    assert result.hosts[0].ports[1].version == "1.25.3"
    assert result.scan_warnings == []


def test_run_nmap_scan_defaults_to_syn_scan_on_windows() -> None:
    captured_command: list[str] = []

    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        captured_command[:] = command
        return subprocess.CompletedProcess(command, 0, stdout="<nmaprun></nmaprun>", stderr="")

    run_nmap_scan(["127.0.0.1"], ports="80", runner=runner)

    assert "-sS" in captured_command
    assert "--send-ip" in captured_command
    assert "-sT" not in captured_command


def test_run_nmap_scan_retries_with_tcp_connect_when_syn_scan_is_unavailable() -> None:
    commands: list[list[str]] = []

    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        commands.append(list(command))
        if len(commands) == 1:
            return subprocess.CompletedProcess(
                command,
                1,
                stdout="",
                stderr="You requested a scan type which requires root privileges.",
            )
        return subprocess.CompletedProcess(command, 0, stdout="<nmaprun></nmaprun>", stderr="")

    result = run_nmap_scan(["127.0.0.1"], ports="80", runner=runner)

    assert len(commands) == 2
    assert "-sS" in commands[0]
    assert "--send-ip" in commands[0]
    assert "-sT" in commands[1]
    assert "-sS" not in commands[1]
    assert "--send-ip" not in commands[1]
    assert result.command == commands[1]
    assert result.scan_warnings == [
        "nmap SYN scan (-sS) failed because raw packet access was unavailable; retried with TCP connect scan (-sT)."
    ]


def test_run_nmap_scan_with_progress_notifies_when_retrying_with_tcp_connect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[list[str]] = []
    progress: list[dict[str, object]] = []

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(list(command))
        if len(commands) == 1:
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="raw socket unavailable")
        return subprocess.CompletedProcess(command, 0, stdout="<nmaprun></nmaprun>", stderr="")

    monkeypatch.setattr(portscan.runner_core, "_run_command_with_live_progress", runner)
    run = SimpleNamespace(
        config=SimpleNamespace(
            nmap_bin="nmap",
            profile="safe",
            nmap_ports="80",
            nmap_timing_template="T3",
            nmap_version_detection=False,
            proxy_mode="none",
            proxy_url=None,
        )
    )

    result = portscan._run_nmap_scan_with_progress(
        ["127.0.0.1"],
        run=run,
        progress_callback=progress.append,
    )

    assert "-sS" in commands[0]
    assert "--send-ip" in commands[0]
    assert "-sT" in commands[1]
    assert result.scan_warnings
    assert any("nmap_scan_warnings" in item for item in progress)


def test_run_nmap_scan_handles_empty_output() -> None:
    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    result = run_nmap_scan(["api.example.com"], runner=runner)

    assert result.hosts == []
    assert result.raw_output == ""


def test_run_nmap_scan_raises_on_subprocess_failure() -> None:
    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="nmap failed")

    with pytest.raises(NmapError, match="nmap exited with code 1: nmap failed"):
        run_nmap_scan(["api.example.com"], runner=runner)


def test_run_nmap_scan_uses_top_ports_for_top1000_alias() -> None:
    captured: list[str] = []

    def runner(command: list[str]) -> subprocess.CompletedProcess[str]:
        captured[:] = command
        return subprocess.CompletedProcess(command, 0, stdout="<nmaprun></nmaprun>", stderr="")

    run_nmap_scan(["10.0.0.1"], profile="fast", ports="top1000", timing_template="T4", runner=runner)
    assert "--top-ports" in captured
    assert "1000" in captured
    assert "-p" not in captured
