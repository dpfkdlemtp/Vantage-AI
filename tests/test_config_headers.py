from __future__ import annotations

from scanner.config import build_web_headers


def test_referer_added_when_supplied() -> None:
    headers = build_web_headers(referer="https://target.example/")
    assert headers["Referer"] == "https://target.example/"


def test_referer_not_added_when_blank() -> None:
    headers = build_web_headers(referer="   ")
    assert "Referer" not in headers


def test_user_supplied_referer_is_not_overridden() -> None:
    headers = build_web_headers(
        {"Referer": "https://custom.example/page"},
        referer="https://target.example/",
    )
    assert headers["Referer"] == "https://custom.example/page"


def test_referer_default_absent() -> None:
    headers = build_web_headers()
    assert "Referer" not in headers
