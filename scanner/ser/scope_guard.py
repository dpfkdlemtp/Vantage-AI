from __future__ import annotations

from urllib.parse import urlparse

from scanner.ser.models import AuthSession


class ScopeViolationError(ValueError):
    """Raised when a URL is outside the configured scope allowlist."""


def _origin_and_path(value: str) -> tuple[str, str, str, str]:
    parsed = urlparse(value.strip())
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    if parsed.port is not None:
        port = str(parsed.port)
    elif scheme == "https":
        port = "443"
    elif scheme == "http":
        port = "80"
    else:
        port = ""
    path = parsed.path or "/"
    return scheme, host, port, path


def enforce_scope(url: str, session: AuthSession) -> None:
    """Auth session never widens scope: URLs must match allowed prefixes when configured."""

    if not session.allowed_url_prefixes:
        return
    u = url.strip()
    if not u:
        raise ScopeViolationError("empty url")

    u_scheme, u_host, u_port, u_path = _origin_and_path(u)
    if not u_scheme or not u_host:
        raise ScopeViolationError(f"url missing scheme/host: {url!r}")

    for prefix in session.allowed_url_prefixes:
        p = prefix.strip()
        if not p:
            continue
        p_scheme, p_host, p_port, p_path = _origin_and_path(p)
        if not p_scheme or not p_host:
            continue
        if u_scheme != p_scheme or u_host != p_host or u_port != p_port:
            continue
        # Path must match exactly or be a sub-path (with "/" boundary) to avoid
        # "/admin" prefix accidentally matching "/administration".
        if p_path in ("", "/"):
            return
        if u_path == p_path or u_path.startswith(p_path.rstrip("/") + "/"):
            return
    raise ScopeViolationError(f"url not in allowed scope prefixes: {url!r}")


def same_origin_prefix(base_url: str) -> str:
    """Derive a conservative default scope prefix from a base URL (scheme://host:port)."""

    p = urlparse(base_url.strip())
    scheme = (p.scheme or "").lower()
    host = (p.hostname or "").lower()
    if not scheme or not host:
        raise ValueError(f"invalid base url for scope: {base_url!r}")
    if p.port is not None:
        port = p.port
    elif scheme == "https":
        port = 443
    elif scheme == "http":
        port = 80
    else:
        raise ValueError(f"unsupported scheme for scope: {base_url!r}")
    return f"{scheme}://{host}:{port}"
