from __future__ import annotations

import pytest

from scanner.adapters.ffuf_runner import FfufResultEntry
from scanner.execution.dirscan_helpers import (
    DirscanConfirmationRequired,
    derive_calibration_decision,
)


def _entry(path: str, *, status_code: int, length: int, redirect: str | None = None) -> FfufResultEntry:
    return FfufResultEntry(
        url=f"http://target.example/{path}",
        status_code=status_code,
        length=length,
        words=10,
        lines=3,
        content_type="text/html",
        redirect_target=redirect,
        host="target.example",
        input_value=path,
        position=1,
        raw_entry={"url": f"http://target.example/{path}"},
    )


def _canary(count: int) -> list[str]:
    return [f"__canary__{index}" for index in range(count)]


def test_stable_length_baseline_uses_size_filter() -> None:
    canary = _canary(20)
    matches = [_entry(path, status_code=200, length=5120) for path in canary]

    decision = derive_calibration_decision("http://target.example/", canary, matches)

    assert decision.filter_sizes == [5120]
    assert decision.filter_codes == []
    assert decision.details["decision"] == "auto_filter"
    assert decision.details["reason"] == "stable_soft_response_length"


def test_redirect_wildcard_uses_status_filter() -> None:
    # Every canary path 301-redirects to its own Location, so each body length
    # differs and the size filter never stabilizes -- this is the
    # per-path redirect false-positive case. The uniform 301 must be filtered via -fc.
    canary = _canary(20)
    matches = [
        _entry(path, status_code=301, length=200 + index, redirect=f"/{path}/")
        for index, path in enumerate(canary)
    ]

    decision = derive_calibration_decision("http://target.example/", canary, matches)

    assert decision.filter_sizes == []
    assert decision.filter_codes == [301]
    assert decision.details["decision"] == "auto_filter"
    assert decision.details["reason"] == "stable_soft_response_status"
    assert decision.details["dominant_status_code"] == 301


def test_uniform_200_with_varying_lengths_stays_ambiguous() -> None:
    # All canary paths return 200 but with two distinct body sizes. Filtering
    # status 200 would hide real findings, so this must remain confirmation-
    # required rather than auto-resolving.
    canary = _canary(20)
    matches = [
        _entry(path, status_code=200, length=(7000 if index < 11 else 6400))
        for index, path in enumerate(canary)
    ]

    with pytest.raises(DirscanConfirmationRequired):
        derive_calibration_decision("http://target.example/", canary, matches)


def test_uniform_403_wall_stays_ambiguous() -> None:
    # A blanket 403 is intentionally NOT auto-filtered (could be a real
    # protected dir) -- only redirects qualify as catch-all.
    canary = _canary(20)
    matches = [
        _entry(path, status_code=403, length=90 + index)
        for index, path in enumerate(canary)
    ]

    with pytest.raises(DirscanConfirmationRequired):
        derive_calibration_decision("http://target.example/", canary, matches)


def test_no_matches_means_no_filter() -> None:
    canary = _canary(20)

    decision = derive_calibration_decision("http://target.example/", canary, [])

    assert decision.filter_sizes == []
    assert decision.filter_codes == []
    assert decision.details["decision"] == "no_filter"
