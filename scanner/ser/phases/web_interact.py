from __future__ import annotations

from scanner.ser.http_client import fetch_url
from scanner.ser.models import AuthSession
from scanner.ser.scope_guard import enforce_scope


def web_interact(
    url: str,
    session: AuthSession,
    *,
    method: str = "GET",
    body: bytes | None = None,
) -> dict[str, object]:
    """
    WEB_INTERACT: single HTTP interaction using operator session (no destructive verbs by default).
    """

    enforce_scope(url, session)
    m = method.upper()
    if m not in {"GET", "HEAD", "OPTIONS"}:
        raise ValueError("only safe read-only methods allowed in web_interact (GET/HEAD/OPTIONS)")
    resp = fetch_url(url, session, method=m, content=body)
    return {
        "url": url,
        "method": m,
        "status_code": resp.status_code,
        "audit": session.model_for_audit(),
        "session_summary": session.redacted_summary,
    }
