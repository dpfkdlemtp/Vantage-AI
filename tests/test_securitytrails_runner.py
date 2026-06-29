from __future__ import annotations

import json

import pytest

from scanner.adapters.securitytrails_runner import (
    SecurityTrailsError,
    fetch_subdomains,
)


def test_fetch_subdomains_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURITYTRAILS_TOKEN", "secret-token")
    captured: dict[str, object] = {}

    def requester(request: object, timeout_seconds: int) -> tuple[int, bytes]:
        captured["request"] = request
        captured["timeout_seconds"] = timeout_seconds
        payload = {"subdomains": ["www", "api", "www"], "record_count": 3}
        return 200, json.dumps(payload).encode("utf-8")

    result = fetch_subdomains(
        "Example.COM",
        api_key_env_var="SECURITYTRAILS_TOKEN",
        timeout_seconds=12,
        requester=requester,
    )

    request = captured["request"]
    headers = {
        str(key).lower(): str(value)
        for key, value in getattr(request, "header_items")()
    }
    assert getattr(request, "full_url") == "https://api.securitytrails.com/v1/domain/example.com/subdomains"
    assert headers["apikey"] == "secret-token"
    assert captured["timeout_seconds"] == 12
    assert result.root_domain == "example.com"
    assert result.subdomains == ["api", "www"]
    assert result.record_count == 3


def test_fetch_subdomains_empty_result(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURITYTRAILS_API_KEY", "secret-token")

    def requester(request: object, timeout_seconds: int) -> tuple[int, bytes]:
        return 200, json.dumps({"subdomains": [], "record_count": 0}).encode("utf-8")

    result = fetch_subdomains("example.com", requester=requester)

    assert result.subdomains == []
    assert result.record_count == 0
    assert result.raw_response["subdomains"] == []


def test_fetch_subdomains_api_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECURITYTRAILS_API_KEY", "secret-token")

    def requester(request: object, timeout_seconds: int) -> tuple[int, bytes]:
        return 429, json.dumps({"message": "rate limit exceeded"}).encode("utf-8")

    with pytest.raises(SecurityTrailsError, match="429: rate limit exceeded"):
        fetch_subdomains("example.com", requester=requester)
