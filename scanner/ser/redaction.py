from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner.ser.models import AuthSession

# Headers whose values must never appear in summaries or audit beyond "present".
_SENSITIVE_NAME = frozenset(
    {
        "authorization",
        "cookie",
        "proxy-authorization",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
        "set-cookie",
    }
)


def _redact_header_line(name: str, value: str) -> str:
    ln = name.strip().lower()
    if ln in _SENSITIVE_NAME or "auth" in ln or "token" in ln or "secret" in ln:
        return f"{name.strip()}=<redacted>"
    # Non-sensitive custom headers: still avoid echoing long values
    if len(value) > 64:
        return f"{name.strip()}=<redacted len={len(value)}>"
    return f"{name.strip()}={value.strip()}"


def redacted_session_summary(session: AuthSession) -> str:
    parts: list[str] = []
    if session.cookies:
        parts.append("cookies: " + ", ".join(sorted(session.cookies.keys())))
    if session.headers:
        lines = []
        for k, v in sorted(session.headers.items(), key=lambda kv: kv[0].lower()):
            lines.append(_redact_header_line(k, v))
        parts.append("headers: " + "; ".join(lines))
    if session.bearer_token or session.bearer_token_env:
        parts.append(
            "bearer: present"
            + (f" (env={session.bearer_token_env})" if session.bearer_token_env else "")
        )
    else:
        parts.append("bearer: absent")
    if session.allowed_url_prefixes:
        parts.append("scope_prefixes: " + ", ".join(session.allowed_url_prefixes))
    return " | ".join(parts) if parts else "empty session"


def sanitize_for_report(text: str) -> str:
    """Remove accidental secret patterns from free-form strings (best-effort)."""

    out = text
    # Authorization / Proxy-Authorization headers: redact token until end-of-line / EOF.
    out = re.sub(
        r"(?im)^(\s*(?:proxy-)?authorization\s*:\s*)(.+)$",
        r"\1<redacted>",
        out,
    )
    # Inline "Authorization: Bearer ..." anywhere (e.g. embedded in a JSON value).
    out = re.sub(
        r"(?i)((?:proxy-)?authorization\s*[:=]\s*(?:bearer|basic|digest)\s+)[^\s\"',;]+",
        r"\1<redacted>",
        out,
    )
    # Cookie / Set-Cookie headers: redact entire value until newline.
    out = re.sub(
        r"(?im)^(\s*(?:set-)?cookie\s*:\s*).+$",
        r"\1<redacted>",
        out,
    )
    # X-Api-Key / X-Auth-Token / X-Csrf-Token style headers.
    out = re.sub(
        r"(?im)^(\s*x-(?:api-key|auth-token|csrf-token)\s*:\s*).+$",
        r"\1<redacted>",
        out,
    )
    # Bearer/api-key tokens that appear as JSON-style key/value pairs.
    out = re.sub(
        r"(?i)((?:api[_-]?key|access[_-]?token|secret|token|bearer)\s*[:=]\s*[\"']?)[^\s\"',;}]+",
        r"\1<redacted>",
        out,
    )
    return out
