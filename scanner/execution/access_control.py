"""Broken Access Control / unauthenticated-exposure auto-testing.

Discovery phases (dir_enum, gau, http_probe) only record that an endpoint
*exists*; nothing replays it without credentials to check whether it is
actually protected. This module takes the discovered endpoints, requests them
**unauthenticated** (GET only, capped, scope-filtered) and flags those that
return sensitive content anyway -- the class of bug that dominated the
engagement (a system/data endpoint returning member PII / internal IPs with no
auth). When an auth session is configured it is deliberately stripped for the
test request so a "still 200 with data" result means the resource is open.

Design priorities: conservative (avoid false positives on login/redirect/error
pages), non-disruptive (GET only, bounded count, per-request timeout) and fully
unit-testable (the HTTP fetch is injected).
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Callable
from urllib.parse import urlsplit
from uuid import uuid4

from scanner.models import Finding
from scanner.storage import insert_finding

# Endpoint path markers worth testing first -- these are where missing authz
# hurts most (system/admin/data/file/user/auth surfaces).
SENSITIVE_PATH_MARKERS: tuple[str, ...] = (
    "admin", "system", "config", "api", "internal", "user", "users", "member",
    "account", "mail", "auth", "data", "file", "download", "export", "backup",
    "manage", "console", "dashboard", "report", "log", "db", "sql", ".dpg",
    ".cpg", "actuator", "env", "secret", "token", "key",
)

# Content patterns that indicate a response is leaking sensitive data.
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PRIVATE_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
)
_SECRET_KEY_RE = re.compile(
    r"\"?(?:password|passwd|pwd|secret|api[_-]?key|auth[_-]?key|access[_-]?token|"
    r"private[_-]?key|client[_-]?secret)\"?\s*[:=]",
    re.IGNORECASE,
)

# Markers that a 200 body is really a login / auth-gate / error page (so it must
# NOT be reported as an exposure even though the status code is 200).
_AUTH_GATE_MARKERS: tuple[str, ...] = (
    "login", "sign in", "signin", "log in", "password", "authentication required",
    "unauthorized", "access denied", "forbidden", "세션", "로그인", "인증",
    "권한이 없", "please log in", "session expired",
)

# How much of the body to inspect / store (keep evidence small).
_BODY_SCAN_LIMIT = 200_000
_BODY_EVIDENCE_LIMIT = 600


@dataclass(frozen=True)
class BACCandidate:
    url: str
    host: str
    source: str
    priority: int = 0


@dataclass(frozen=True)
class BACVerdict:
    exposed: bool
    severity: str = "info"
    indicators: list[str] = field(default_factory=list)
    reason: str = ""


@dataclass(frozen=True)
class HttpResponse:
    status_code: int
    content_type: str
    body: str


# fetch(url, timeout) -> HttpResponse | None  (None == request failed)
FetchFn = Callable[[str, float], "HttpResponse | None"]


def _path_priority(path: str) -> int:
    lowered = path.casefold()
    return sum(1 for marker in SENSITIVE_PATH_MARKERS if marker in lowered)


def analyze_unauth_response(
    url: str,
    response: HttpResponse | None,
) -> BACVerdict:
    """Decide whether an unauthenticated response constitutes an exposure."""
    if response is None:
        return BACVerdict(exposed=False, reason="no_response")
    status = response.status_code
    # Only 2xx is an exposure. 3xx (redirect to login), 401/403 (challenge),
    # 404/5xx all mean the resource is not openly serving data.
    if not (200 <= status < 300):
        return BACVerdict(exposed=False, reason=f"status_{status}")

    body = response.body or ""
    scan = body[:_BODY_SCAN_LIMIT]
    lowered = scan.casefold()

    # A 200 that is actually a login/auth-gate page is protected, not exposed.
    if any(marker in lowered for marker in _AUTH_GATE_MARKERS):
        # ...unless it also clearly leaks records (an auth page would not).
        if not (_EMAIL_RE.search(scan) or _PRIVATE_IP_RE.search(scan) or _SECRET_KEY_RE.search(scan)):
            return BACVerdict(exposed=False, reason="auth_gate_page")

    indicators: list[str] = []
    emails = _EMAIL_RE.findall(scan)
    if len(emails) >= 3:
        indicators.append(f"emails:{len(emails)}")
    private_ips = _PRIVATE_IP_RE.findall(scan)
    if private_ips:
        indicators.append(f"internal_ips:{len(set(private_ips))}")
    if _SECRET_KEY_RE.search(scan):
        indicators.append("secret_keyword")

    content_type = (response.content_type or "").casefold()
    is_data = "json" in content_type or "xml" in content_type
    # A sizeable JSON/XML array of records served unauthenticated is itself a
    # signal even without an obvious PII regex hit.
    looks_like_record_set = is_data and scan.count("{") >= 5 and len(scan) >= 512

    if not indicators and not looks_like_record_set:
        return BACVerdict(exposed=False, reason="no_sensitive_indicators")

    # Severity: leaked credentials/PII/internal topology = high; bulk data = medium.
    severity = "medium"
    if "secret_keyword" in indicators or any(i.startswith("emails:") for i in indicators):
        severity = "high"
    elif any(i.startswith("internal_ips:") for i in indicators):
        severity = "high"
    if looks_like_record_set and not indicators:
        indicators.append("unauth_data_payload")

    return BACVerdict(
        exposed=True,
        severity=severity,
        indicators=indicators,
        reason="unauthenticated_sensitive_response",
    )


def select_bac_candidates(
    connection: Any,
    run_id: str,
    *,
    limit: int = 50,
    in_scope: Callable[[str], bool] | None = None,
) -> list[BACCandidate]:
    """Pick discovered endpoints worth an unauthenticated re-request.

    Sources: dir_enum 2xx/redirect hits, gau historical URLs and http_probe
    live hosts. Highest sensitive-path priority first, deduped by URL.
    """
    rows = connection.execute(
        """
        SELECT module, evidence_json
        FROM findings
        WHERE run_id = ?
          AND module IN ('dir_enum', 'http_probe')
        ORDER BY created_at ASC, finding_id ASC
        """,
        (run_id,),
    ).fetchall()

    seen: set[str] = set()
    candidates: list[BACCandidate] = []
    for row in rows:
        try:
            evidence = json.loads(row["evidence_json"])
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if not isinstance(evidence, dict):
            continue
        etype = str(evidence.get("type") or "")

        urls: list[str] = []
        if etype == "wayback_urls":
            urls = [str(u) for u in (evidence.get("urls") or []) if str(u).strip()]
        else:
            single = str(evidence.get("url") or "").strip()
            if single:
                urls = [single]

        for url in urls:
            split = urlsplit(url)
            if split.scheme not in {"http", "https"} or not split.netloc:
                continue
            key = url.split("#", 1)[0]
            if key in seen:
                continue
            host = split.hostname or ""
            if in_scope is not None and host and not in_scope(host):
                continue
            seen.add(key)
            candidates.append(
                BACCandidate(
                    url=url,
                    host=host,
                    source=str(row["module"]),
                    priority=_path_priority(split.path),
                )
            )

    candidates.sort(key=lambda c: (-c.priority, c.url))
    return candidates[:limit]


def _default_fetch(url: str, timeout: float) -> HttpResponse | None:
    """Unauthenticated GET via stdlib (no redirect following, bounded read)."""

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
            return None  # surface the 3xx instead of following it

    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(
        url,
        method="GET",
        headers={"User-Agent": "web-scanner/access-control-check"},
    )
    try:
        with opener.open(request, timeout=timeout) as resp:
            raw = resp.read(_BODY_SCAN_LIMIT + 1)
            content_type = resp.headers.get("Content-Type", "")
            return HttpResponse(
                status_code=getattr(resp, "status", 200) or 200,
                content_type=content_type,
                body=raw.decode("utf-8", errors="replace"),
            )
    except urllib.error.HTTPError as exc:  # 4xx/5xx still carry a status
        try:
            body = exc.read(_BODY_SCAN_LIMIT + 1).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return HttpResponse(
            status_code=int(getattr(exc, "code", 0) or 0),
            content_type=exc.headers.get("Content-Type", "") if exc.headers else "",
            body=body,
        )
    except Exception:
        return None


def run_access_control_checks(
    connection: Any,
    run_id: str,
    *,
    config: Any,
    fetch: FetchFn | None = None,
    in_scope: Callable[[str], bool] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Re-request discovered endpoints unauthenticated and record exposures."""
    if not bool(getattr(config, "access_control_test_enabled", False)):
        return {"tested": 0, "findings": 0, "skipped": "disabled"}

    limit = int(getattr(config, "access_control_max_endpoints", 50) or 50)
    timeout = float(getattr(config, "access_control_request_timeout_seconds", 8) or 8)
    fetch_fn = fetch or _default_fetch

    candidates = select_bac_candidates(connection, run_id, limit=limit, in_scope=in_scope)
    stamp = now or datetime.now(UTC)
    tested = 0
    exposures = 0
    for candidate in candidates:
        response = fetch_fn(candidate.url, timeout)
        tested += 1
        verdict = analyze_unauth_response(candidate.url, response)
        if not verdict.exposed:
            continue
        exposures += 1
        body_excerpt = (response.body or "")[:_BODY_EVIDENCE_LIMIT] if response else ""
        insert_finding(
            connection,
            Finding(
                finding_id=f"bac-{uuid4().hex[:12]}",
                run_id=run_id,
                module="access_control",
                target=candidate.host or candidate.url,
                status="observed",
                summary=(
                    f"Broken access control: {candidate.url} returns sensitive "
                    f"content WITHOUT authentication ({', '.join(verdict.indicators)})"
                ),
                evidence_json={
                    "type": "broken_access_control",
                    "url": candidate.url,
                    "host": candidate.host,
                    "source": candidate.source,
                    "severity": verdict.severity,
                    "indicators": verdict.indicators,
                    "status_code": response.status_code if response else None,
                    "content_type": response.content_type if response else "",
                    "body_excerpt": body_excerpt,
                },
                tags=["access-control", "broken-access-control", verdict.severity],
                created_at=stamp,
            ),
        )
    return {"tested": tested, "findings": exposures, "candidate_count": len(candidates)}
