from __future__ import annotations

import json

import pytest

from scanner.adapters.crtsh_runner import CrtshError, fetch_crtsh_subdomains


def test_fetch_crtsh_subdomains_success() -> None:
    captured: dict[str, object] = {}

    def requester(request: object, timeout_seconds: int) -> tuple[int, bytes]:
        captured["request"] = request
        captured["timeout_seconds"] = timeout_seconds
        payload = [
            {"name_value": "api.example.com\nwww.example.com"},
            {"common_name": "cdn.example.com"},
        ]
        return 200, json.dumps(payload).encode("utf-8")

    result = fetch_crtsh_subdomains("Example.COM", timeout_seconds=12, requester=requester)

    assert getattr(captured["request"], "full_url") == "https://crt.sh/?q=%25.example.com&output=json"
    assert captured["timeout_seconds"] == 12
    assert result.root_domain == "example.com"
    assert result.entry_count == 2
    assert result.hosts == ["api.example.com", "cdn.example.com", "www.example.com"]


def test_fetch_crtsh_subdomains_cleans_wildcards_and_duplicates() -> None:
    def requester(request: object, timeout_seconds: int) -> tuple[int, bytes]:
        payload = [
            {"name_value": "*.api.example.com\napi.example.com\nexample.com"},
            {"name_value": "*.api.example.com\nblog.example.com"},
        ]
        return 200, json.dumps(payload).encode("utf-8")

    result = fetch_crtsh_subdomains("example.com", requester=requester)

    assert result.hosts == ["api.example.com", "blog.example.com"]


def test_fetch_crtsh_subdomains_empty_result() -> None:
    def requester(request: object, timeout_seconds: int) -> tuple[int, bytes]:
        return 200, b""

    result = fetch_crtsh_subdomains("example.com", requester=requester)

    assert result.hosts == []
    assert result.entry_count == 0
    assert result.raw_output == ""


def test_fetch_crtsh_subdomains_failure() -> None:
    def requester(request: object, timeout_seconds: int) -> tuple[int, bytes]:
        return 503, b"service unavailable"

    with pytest.raises(CrtshError, match="status 503"):
        fetch_crtsh_subdomains("example.com", requester=requester)
