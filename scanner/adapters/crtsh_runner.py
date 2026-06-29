from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

CRTSH_BASE_URL = "https://crt.sh/"
CrtshRequester = Callable[[Request, int], tuple[int, bytes]]


class CrtshError(RuntimeError):
    pass


@dataclass(frozen=True)
class CrtshRunResult:
    root_domain: str
    query_url: str
    hosts: list[str]
    entry_count: int
    raw_output: str


def fetch_crtsh_subdomains(
    root_domain: str,
    *,
    timeout_seconds: int = 30,
    requester: CrtshRequester | None = None,
) -> CrtshRunResult:
    normalized_domain = _normalize_root_domain(root_domain)
    query_url = f"{CRTSH_BASE_URL}?q={quote(f'%.{normalized_domain}')}&output=json"
    headers = {
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    }
    request = Request(query_url, headers=headers)
    status_code, response_body = (requester or _default_requester)(request, timeout_seconds)

    if status_code != 200:
        raise CrtshError(f"crt.sh returned status {status_code}")

    raw_output = _decode_response(response_body)
    if not raw_output.strip():
        return CrtshRunResult(
            root_domain=normalized_domain,
            query_url=query_url,
            hosts=[],
            entry_count=0,
            raw_output=raw_output,
        )

    payload = _parse_json_payload(raw_output)
    return CrtshRunResult(
        root_domain=normalized_domain,
        query_url=query_url,
        hosts=_parse_hosts(payload, normalized_domain),
        entry_count=len(payload),
        raw_output=raw_output,
    )


def _default_requester(request: Request, timeout_seconds: int) -> tuple[int, bytes]:
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            return response.getcode(), response.read()
    except HTTPError as exc:
        return exc.code, exc.read()
    except URLError as exc:
        raise CrtshError(f"crt.sh request failed: {exc.reason}") from exc


def _decode_response(response_body: bytes) -> str:
    try:
        return response_body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CrtshError("crt.sh returned a non-UTF-8 response") from exc


def _parse_json_payload(raw_output: str) -> list[dict[str, Any]]:
    try:
        payload = json.loads(raw_output)
    except json.JSONDecodeError as exc:
        raise CrtshError("crt.sh returned invalid JSON output") from exc
    if not isinstance(payload, list):
        raise CrtshError("crt.sh returned an unexpected JSON structure")
    normalized_payload: list[dict[str, Any]] = []
    for item in payload:
        if not isinstance(item, dict):
            raise CrtshError("crt.sh returned a non-object entry")
        normalized_payload.append(item)
    return normalized_payload


def _parse_hosts(payload: list[dict[str, Any]], root_domain: str) -> list[str]:
    hosts: set[str] = set()
    for item in payload:
        for field_name in ("name_value", "common_name"):
            value = item.get(field_name)
            if not isinstance(value, str):
                continue
            for line in value.splitlines():
                normalized = _normalize_name(line, root_domain)
                if normalized is not None:
                    hosts.add(normalized)
    return sorted(hosts)


def _normalize_name(value: str, root_domain: str) -> str | None:
    normalized = value.strip().lower().rstrip(".")
    while normalized.startswith("*."):
        normalized = normalized[2:]
    if not normalized or normalized == root_domain:
        return None
    if normalized.endswith(f".{root_domain}"):
        return normalized
    return None


def _normalize_root_domain(root_domain: str) -> str:
    normalized = root_domain.strip().lower().rstrip(".")
    if not normalized:
        raise ValueError("root_domain must not be empty")
    return normalized
