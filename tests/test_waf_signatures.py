from __future__ import annotations

from scanner.execution.waf_signatures import detect_waf


def _vendors(detections) -> set[str]:
    return {d.vendor for d in detections}


def test_fortiweb_detected_by_server_and_title() -> None:
    detections = detect_waf(
        webserver="FortiWeb",
        title="Web Page Blocked",
        response_headers={},
        status_code=403,
    )
    assert "Fortinet FortiWeb/FortiGuard" in _vendors(detections)
    fortinet = next(d for d in detections if d.vendor.startswith("Fortinet"))
    assert any("Server~fortiweb" in ind for ind in fortinet.indicators)


def test_cloudflare_detected_by_header() -> None:
    detections = detect_waf(
        webserver="cloudflare",
        title=None,
        response_headers={"CF-RAY": "abc123-ICN", "Server": "cloudflare"},
        status_code=200,
    )
    assert "Cloudflare" in _vendors(detections)


def test_incapsula_detected_by_cookie() -> None:
    detections = detect_waf(
        webserver=None,
        title=None,
        response_headers={"Set-Cookie": "visid_incap_123=abc; incap_ses_456=def"},
        status_code=200,
    )
    assert "Imperva Incapsula" in _vendors(detections)


def test_generic_block_page_when_vendor_unknown() -> None:
    detections = detect_waf(
        webserver="nginx",
        title="Request Blocked",
        response_headers={},
        status_code=403,
    )
    assert "Unknown WAF/IPS" in _vendors(detections)


def test_clean_response_yields_no_detection() -> None:
    detections = detect_waf(
        webserver="nginx",
        title="Welcome to Example",
        response_headers={"Server": "nginx", "Content-Type": "text/html"},
        status_code=200,
    )
    assert detections == []


def test_plain_403_without_block_title_not_flagged() -> None:
    # A normal 403 with an ordinary title must not be misread as a WAF block.
    detections = detect_waf(
        webserver="Apache",
        title="Index of /private",
        response_headers={},
        status_code=403,
    )
    assert detections == []
