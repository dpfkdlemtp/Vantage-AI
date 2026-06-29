from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SessionSource(StrEnum):
    """Where the session material was loaded from (for audit / UX only; never contains secrets)."""

    CLI = "cli"
    FILE = "file"
    ENV = "env"
    MERGED = "merged"


class AuthCookie(BaseModel):
    """A single HTTP cookie (name + value). Values are never written to reports."""

    name: str
    value: str


class AuthHeader(BaseModel):
    """A single HTTP header (name + value). Values are never written to reports."""

    name: str
    value: str


class AuthSession(BaseModel):
    """
    Operator-provided session context. Raw secrets exist only in memory for live requests;
    `redacted_summary` is safe for reports and audit logs.
    """

    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    bearer_token: str | None = None
    bearer_token_env: str | None = Field(
        default=None,
        description="Name of environment variable used to load bearer token (not the token value).",
    )
    source: SessionSource = SessionSource.CLI
    redacted_summary: str = ""
    # Optional scope: request URLs must start with one of these prefixes (in addition to product rules).
    allowed_url_prefixes: tuple[str, ...] = Field(default_factory=tuple)

    def model_post_init(self, __context: Any) -> None:
        if not self.redacted_summary:
            from scanner.ser.redaction import redacted_session_summary

            object.__setattr__(self, "redacted_summary", redacted_session_summary(self))

    def model_for_audit(self) -> dict[str, Any]:
        """JSON-serializable dict safe for reports (no raw secrets)."""

        return {
            "headers": sorted(self.headers.keys()),
            "cookies": sorted(self.cookies.keys()),
            "bearer_token": "present" if (self.bearer_token or self.bearer_token_env) else "absent",
            "bearer_token_env": self.bearer_token_env,
            "source": self.source,
            "redacted_summary": self.redacted_summary,
            "allowed_url_prefixes": list(self.allowed_url_prefixes),
        }
