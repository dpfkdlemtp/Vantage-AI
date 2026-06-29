from __future__ import annotations

from typing import Any

import httpx

from scanner.ser.models import AuthSession


def build_request_headers(session: AuthSession) -> dict[str, str]:
    """Merge extra headers and Authorization from bearer token (in-memory only)."""

    h = dict(session.headers)
    if session.bearer_token:
        h["Authorization"] = f"Bearer {session.bearer_token}"
    return h


def httpx_client_kwargs(session: AuthSession) -> dict[str, Any]:
    headers = build_request_headers(session)
    cookies = dict(session.cookies)
    return {"headers": headers, "cookies": cookies, "follow_redirects": True}


def fetch_url(
    url: str,
    session: AuthSession,
    *,
    method: str = "GET",
    content: bytes | None = None,
    timeout: float = 30.0,
) -> httpx.Response:
    kw = httpx_client_kwargs(session)
    with httpx.Client(timeout=timeout) as client:
        return client.request(method.upper(), url, content=content, **kw)
