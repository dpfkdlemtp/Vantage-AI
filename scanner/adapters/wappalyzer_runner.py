from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from typing import Any

DEFAULT_WAPPALYZER_TIMEOUT_SECONDS = 3.0


def detect_technologies(url: str, *, timeout_seconds: float = DEFAULT_WAPPALYZER_TIMEOUT_SECONDS) -> list[str]:
    normalized_url = str(url or "").strip()
    if not normalized_url:
        return []
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_detect_sync, normalized_url)
        try:
            return future.result(timeout=max(0.1, float(timeout_seconds)))
        except FutureTimeoutError:
            return []
        except Exception:
            return []


def _detect_sync(url: str) -> list[str]:
    try:
        from Wappalyzer import Wappalyzer, WebPage  # type: ignore[import-not-found]
    except Exception:
        return []

    try:
        webpage = WebPage.new_from_url(url, timeout=2)
    except TypeError:
        try:
            webpage = WebPage.new_from_url(url)
        except Exception:
            return []
    except Exception:
        return []

    try:
        raw_detected = Wappalyzer.latest().analyze(webpage)
    except Exception:
        return []

    detected = _normalize_detected(raw_detected)
    return sorted(detected)


def _normalize_detected(value: Any) -> set[str]:
    if isinstance(value, set):
        return {item.strip().lower() for item in value if isinstance(item, str) and item.strip()}
    if isinstance(value, (list, tuple)):
        return {item.strip().lower() for item in value if isinstance(item, str) and item.strip()}
    if isinstance(value, dict):
        return {str(item).strip().lower() for item in value.keys() if str(item).strip()}
    return set()
