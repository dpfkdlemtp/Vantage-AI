from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from scanner.ser.http_client import fetch_url
from scanner.ser.models import AuthSession
from scanner.ser.redaction import sanitize_for_report
from scanner.ser.scope_guard import enforce_scope


def crawl_web(
    start_url: str,
    session: AuthSession,
    *,
    max_pages: int = 10,
) -> dict[str, object]:
    """
    Minimal WEB_CRAWL: same-origin link discovery with AuthSession on every request.
    Returns only safe summary fields (no secrets).
    """

    enforce_scope(start_url, session)
    visited: set[str] = set()
    frontier: list[str] = [start_url.strip()]
    origin = urlparse(start_url).netloc
    fetched: list[dict[str, object]] = []

    link_re = re.compile(r"""href\s*=\s*["']([^"']+)["']""", re.I)

    while frontier and len(visited) < max_pages:
        url = frontier.pop(0)
        if url in visited:
            continue
        enforce_scope(url, session)
        visited.add(url)
        resp = fetch_url(url, session)
        body_text = resp.text[:500_000]
        titles = link_re.findall(body_text)

        discovered: list[str] = []
        for href in titles:
            joined = urljoin(url, href)
            pu = urlparse(joined)
            if pu.netloc == origin:
                discovered.append(joined)
                if joined not in visited and joined not in frontier:
                    frontier.append(joined)

        fetched.append(
            {
                "url": url,
                "status_code": resp.status_code,
                "discovered_same_origin": discovered[:50],
                "session_summary": session.redacted_summary,
            }
        )

    return {
        "pages_fetched": len(fetched),
        "visited_urls": list(visited),
        "fetch_log": [
            {**entry, "session_summary": sanitize_for_report(str(entry["session_summary"]))}
            for entry in fetched
        ],
        "audit": session.model_for_audit(),
    }
