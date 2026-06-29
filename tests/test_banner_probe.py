from __future__ import annotations

import pytest

from scanner.execution.banner_probe import classify_banner, read_tcp_banner


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (b"SSH-2.0-OpenSSH_8.2", "SSH"),
        (b"HTTP/1.1 200 OK\r\n", "HTTP"),
        (b"220 ftp.example FTP server ready\r\n", "FTP"),
        (b"220 mail ESMTP Postfix\r\n", "SMTP"),
    ],
)
def test_classify_banner(raw: bytes, expected: str) -> None:
    assert classify_banner(raw) == expected


def test_read_tcp_banner_connect_fails_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeSock:
        def __init__(self, *a: object, **k: object) -> None:
            pass

        def settimeout(self, *_a: object) -> None:
            return

        def connect(self, *_a: object) -> None:
            raise OSError("nope")

        def close(self) -> None:
            return

    monkeypatch.setattr("scanner.execution.banner_probe.socket.socket", FakeSock)
    assert read_tcp_banner("127.0.0.1", 1) == b""


def test_read_tcp_banner_recv_timeout_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeSock:
        def __init__(self, *a: object, **k: object) -> None:
            pass

        def settimeout(self, *_a: object) -> None:
            return

        def connect(self, *_a: object) -> None:
            return

        def recv(self, *_a: object) -> bytes:
            raise TimeoutError()

        def close(self) -> None:
            return

    monkeypatch.setattr("scanner.execution.banner_probe.socket.socket", FakeSock)
    assert read_tcp_banner("127.0.0.1", 1) == b""
