from __future__ import annotations

import subprocess
from typing import Any

# Centralised subprocess wrappers. Encoding is always UTF-8 with replacement
# fallback so non-UTF-8 stdout/stderr (common on Windows CP949 locales)
# never raises UnicodeDecodeError mid-scan.

DEFAULT_ENCODING = "utf-8"
DEFAULT_ERRORS = "replace"


def run_text_capture(
    command: list[str],
    *,
    stdin_text: str | None = None,
    check: bool = False,
    timeout: float | None = None,
    **kwargs: Any,
) -> subprocess.CompletedProcess[str]:
    """subprocess.run with capture_output=True, text=True and UTF-8 decoding.

    Intentionally does not set a default timeout: legitimate scans can be
    long-running. Callers may pass `timeout=` when appropriate.
    """

    return subprocess.run(
        command,
        input=stdin_text,
        capture_output=True,
        check=check,
        text=True,
        encoding=DEFAULT_ENCODING,
        errors=DEFAULT_ERRORS,
        timeout=timeout,
        **kwargs,
    )


def open_text_pipe(
    command: list[str],
    *,
    stdin_pipe: bool = False,
    bufsize: int = 1,
    **kwargs: Any,
) -> subprocess.Popen[str]:
    """subprocess.Popen with text mode + UTF-8 decoding for streaming use."""

    return subprocess.Popen(
        command,
        stdin=subprocess.PIPE if stdin_pipe else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding=DEFAULT_ENCODING,
        errors=DEFAULT_ERRORS,
        bufsize=bufsize,
        **kwargs,
    )
