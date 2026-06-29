from __future__ import annotations

import json
import subprocess
from pathlib import Path

from scanner.adapters import dnsx_runner


def _make_fake_dnsx(name_to_ips: dict[str, list[str]], wildcard_ips: list[str]):
    """Return a fake run_text_capture that emulates dnsx -json -a -resp.

    Any label starting with 'wildcard-probe-' resolves to the wildcard IPs;
    other names resolve per name_to_ips (suffix-matched on the leftmost label).
    """

    def fake_run_text_capture(command, *args, **kwargs):
        list_path = Path(command[command.index("-l") + 1])
        names = [n.strip() for n in list_path.read_text().splitlines() if n.strip()]
        lines: list[str] = []
        for name in names:
            label = name.split(".", 1)[0]
            if label.startswith("wildcard-probe-"):
                ips = wildcard_ips
            else:
                ips = name_to_ips.get(label, [])
            if ips:
                lines.append(json.dumps({"host": name, "a": ips}))
        return subprocess.CompletedProcess(
            args=command, returncode=0, stdout="\n".join(lines), stderr=""
        )

    return fake_run_text_capture


def test_wildcard_only_hosts_are_filtered(monkeypatch) -> None:
    fake = _make_fake_dnsx(
        name_to_ips={
            "www": ["5.6.7.8"],          # real, kept
            "admin": ["1.2.3.4"],        # wildcard-only, filtered
            "api": ["1.2.3.4", "9.9.9.9"],  # mixed, kept
        },
        wildcard_ips=["1.2.3.4"],
    )
    monkeypatch.setattr(dnsx_runner, "run_text_capture", fake)

    result = dnsx_runner.run_dnsx_bruteforce_detailed(
        "example.com", wordlist=["www", "admin", "api"]
    )

    assert result.wildcard_ips == ["1.2.3.4"]
    assert "admin.example.com" in result.filtered_hosts
    assert "www.example.com" in result.hosts
    assert "api.example.com" in result.hosts
    assert "admin.example.com" not in result.hosts


def test_no_wildcard_keeps_all_resolved(monkeypatch) -> None:
    fake = _make_fake_dnsx(
        name_to_ips={"www": ["5.6.7.8"], "api": ["5.6.7.9"]},
        wildcard_ips=[],  # random probes resolve to nothing -> no wildcard
    )
    monkeypatch.setattr(dnsx_runner, "run_text_capture", fake)

    result = dnsx_runner.run_dnsx_bruteforce_detailed(
        "example.com", wordlist=["www", "api"]
    )

    assert result.wildcard_ips == []
    assert result.filtered_hosts == []
    assert set(result.hosts) == {"www.example.com", "api.example.com"}


def test_detect_wildcard_disabled_keeps_wildcard_hosts(monkeypatch) -> None:
    fake = _make_fake_dnsx(
        name_to_ips={"admin": ["1.2.3.4"]},
        wildcard_ips=["1.2.3.4"],
    )
    monkeypatch.setattr(dnsx_runner, "run_text_capture", fake)

    result = dnsx_runner.run_dnsx_bruteforce_detailed(
        "example.com", wordlist=["admin"], detect_wildcard=False
    )

    assert result.wildcard_ips == []
    assert "admin.example.com" in result.hosts


def test_backcompat_run_dnsx_bruteforce_returns_list(monkeypatch) -> None:
    fake = _make_fake_dnsx(name_to_ips={"www": ["5.6.7.8"]}, wildcard_ips=[])
    monkeypatch.setattr(dnsx_runner, "run_text_capture", fake)

    hosts = dnsx_runner.run_dnsx_bruteforce("example.com", wordlist=["www"])
    assert hosts == ["www.example.com"]
