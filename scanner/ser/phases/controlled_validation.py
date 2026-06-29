from __future__ import annotations

from scanner.ser.http_client import fetch_url
from scanner.ser.models import AuthSession
from scanner.ser.scope_guard import enforce_scope


class ApprovalRequiredError(PermissionError):
    """Controlled validation is approval-gated."""


def run_controlled_validation(
    url: str,
    session: AuthSession,
    *,
    approved: bool,
    method: str = "GET",
) -> dict[str, object]:
    """
    Sends an authenticated request only after explicit operator approval.
    Does not bypass scope; does not enable destructive actions.
    """

    if not approved:
        raise ApprovalRequiredError(
            "controlled validation requires explicit approval; refusing to send authenticated request"
        )
    enforce_scope(url, session)
    m = method.upper()
    if m not in {"GET", "HEAD", "OPTIONS"}:
        raise ValueError("controlled validation allows only safe methods in this build")
    resp = fetch_url(url, session, method=m)
    return {
        "url": url,
        "method": m,
        "status_code": resp.status_code,
        "approval_applied": True,
        "audit": session.model_for_audit(),
        "session_summary": session.redacted_summary,
    }
