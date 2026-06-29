from __future__ import annotations

import os
from pathlib import Path

from scanner.ser.models import AuthCookie, AuthHeader, AuthSession, SessionSource
from scanner.ser.session_file import load_session_file_record


def parse_cookie_flag(pairs: list[str] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    if not pairs:
        return out
    for raw in pairs:
        item = raw.strip()
        if "=" not in item:
            raise ValueError(f"cookie must be name=value, got: {raw!r}")
        name, _, value = item.partition("=")
        name, value = name.strip(), value.strip()
        if not name:
            raise ValueError(f"invalid cookie: {raw!r}")
        out[name] = value
    return out


def parse_header_flag(lines: list[str] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    if not lines:
        return out
    for raw in lines:
        item = raw.strip()
        if ":" not in item:
            raise ValueError(f'header must be "Name: value", got: {raw!r}')
        name, _, value = item.partition(":")
        name, value = name.strip(), value.strip()
        if not name:
            raise ValueError(f"invalid header: {raw!r}")
        out[name] = value
    return out


def load_bearer_from_env(env_name: str | None) -> tuple[str | None, str | None]:
    if not env_name or not str(env_name).strip():
        return None, None
    key = str(env_name).strip()
    val = os.environ.get(key)
    if val is None or val == "":
        return None, key
    return val, key


def merge_cli_session(
    *,
    cookies: dict[str, str],
    headers: dict[str, str],
    bearer_token_env_name: str | None,
    session_file: Path | None,
    source: SessionSource = SessionSource.MERGED,
    allowed_prefixes: tuple[str, ...] = (),
) -> AuthSession:
    file_headers: dict[str, str] = {}
    file_cookies: dict[str, str] = {}
    file_bearer_env: str | None = None

    if session_file is not None:
        rec = load_session_file_record(session_file)
        file_headers = dict(rec.get("headers") or {})
        file_cookies = dict(rec.get("cookies") or {})
        file_bearer_env = rec.get("bearer_token_env")

    merged_headers = {**file_headers, **headers}
    merged_cookies = {**file_cookies, **cookies}

    bearer_token: str | None = None
    bearer_env: str | None = None
    if bearer_token_env_name:
        bearer_token, bearer_env = load_bearer_from_env(bearer_token_env_name)
    elif file_bearer_env:
        bearer_token, bearer_env = load_bearer_from_env(file_bearer_env)

    return AuthSession(
        headers=merged_headers,
        cookies=merged_cookies,
        bearer_token=bearer_token,
        bearer_token_env=bearer_env,
        source=source,
        allowed_url_prefixes=allowed_prefixes,
    )


def cookies_as_models(cookies: dict[str, str]) -> list[AuthCookie]:
    return [AuthCookie(name=k, value=v) for k, v in sorted(cookies.items())]


def headers_as_models(headers: dict[str, str]) -> list[AuthHeader]:
    return [AuthHeader(name=k, value=v) for k, v in sorted(headers.items())]
