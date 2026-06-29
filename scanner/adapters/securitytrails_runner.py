"""Legacy compatibility wrapper kept for existing tests and migrations.

The supported subdomain discovery flow is now the free passive source set driven by
`subfinder`, `assetfinder`, and `crt.sh`. This module is no longer part of the
documented runtime path, but remains import-compatible so older tests and saved state
can be handled safely.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from collections.abc import Callable
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

SECURITYTRAILS_API_BASE_URL = "https://api.securitytrails.com/v1"
SecurityTrailsRequester = Callable[[Request, int], tuple[int, bytes]]


class SecurityTrailsError(RuntimeError):
    pass


@dataclass(frozen=True)
class SecurityTrailsSubdomainsResult:
    root_domain: str
    endpoint: str
    subdomains: list[str]
    record_count: int
    raw_response: dict[str, Any]


def fetch_subdomains(
    root_domain: str,
    *,
    api_key_env_var: str = "SECURITYTRAILS_API_KEY",
    timeout_seconds: int = 30,
    requester: SecurityTrailsRequester | None = None,
) -> SecurityTrailsSubdomainsResult:
    api_key = os.environ.get(api_key_env_var)
    if not api_key:
        raise SecurityTrailsError(
            f"missing SecurityTrails API key in environment variable '{api_key_env_var}'"
        )

    normalized_domain = root_domain.strip().lower().rstrip(".")
    endpoint = f"{SECURITYTRAILS_API_BASE_URL}/domain/{quote(normalized_domain)}/subdomains"
    request = Request(endpoint, headers={"Accept": "application/json", "APIKEY": api_key})
    status_code, response_body = (requester or _default_requester)(request, timeout_seconds)
    payload = _parse_json_payload(response_body)

    if status_code != 200:
        detail = _extract_error_message(payload)
        raise SecurityTrailsError(f"SecurityTrails API returned status {status_code}: {detail}")

    subdomains = _parse_subdomains(payload)
    raw_record_count = payload.get("record_count")
    record_count = raw_record_count if isinstance(raw_record_count, int) and raw_record_count >= 0 else len(subdomains)
    return SecurityTrailsSubdomainsResult(
        root_domain=normalized_domain,
        endpoint=endpoint,
        subdomains=subdomains,
        record_count=record_count,
        raw_response=payload,
    )


def _default_requester(request: Request, timeout_seconds: int) -> tuple[int, bytes]:
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            return response.getcode(), response.read()
    except HTTPError as exc:
        return exc.code, exc.read()
    except URLError as exc:
        raise SecurityTrailsError(f"SecurityTrails request failed: {exc.reason}") from exc


def _parse_json_payload(response_body: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(response_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SecurityTrailsError("SecurityTrails API returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise SecurityTrailsError("SecurityTrails API returned an unexpected JSON structure")
    return payload


def _parse_subdomains(payload: dict[str, Any]) -> list[str]:
    raw_subdomains = payload.get("subdomains")
    if raw_subdomains is None:
        return []
    if not isinstance(raw_subdomains, list) or any(not isinstance(item, str) for item in raw_subdomains):
        raise SecurityTrailsError("SecurityTrails API returned an invalid subdomains payload")

    normalized = {
        item.strip().lower().rstrip(".")
        for item in raw_subdomains
        if item.strip()
    }
    return sorted(normalized)


def _extract_error_message(payload: dict[str, Any]) -> str:
    for key in ("message", "error", "errors"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value
        if isinstance(value, list):
            messages = [item for item in value if isinstance(item, str) and item.strip()]
            if messages:
                return "; ".join(messages)
    return "request failed"
