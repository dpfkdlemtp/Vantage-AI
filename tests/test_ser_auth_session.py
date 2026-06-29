from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scanner.ser.http_client import build_request_headers, fetch_url, httpx_client_kwargs
from scanner.ser.models import AuthSession, SessionSource
from scanner.ser.parsing import (
    load_bearer_from_env,
    merge_cli_session,
    parse_cookie_flag,
    parse_header_flag,
)
from scanner.ser.phases.controlled_validation import ApprovalRequiredError, run_controlled_validation
from scanner.ser.phases.web_crawl import crawl_web
from scanner.ser.phases.web_interact import web_interact
from scanner.ser.redaction import redacted_session_summary, sanitize_for_report
from scanner.ser.scope_guard import ScopeViolationError, enforce_scope


def test_parse_cookie_header_flags() -> None:
    assert parse_cookie_flag(["a=b", "c=d"]) == {"a": "b", "c": "d"}
    with pytest.raises(ValueError):
        parse_cookie_flag(["bad"])
    assert parse_header_flag(["X-Trace: 1", "Y: two"]) == {"X-Trace": "1", "Y": "two"}
    with pytest.raises(ValueError):
        parse_header_flag(["no-colon"])


def test_bearer_token_env_loading(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SER_TEST_TOKEN", raising=False)
    tok, env = load_bearer_from_env("SER_TEST_TOKEN")
    assert tok is None and env == "SER_TEST_TOKEN"
    monkeypatch.setenv("SER_TEST_TOKEN", "secret-value")
    tok2, env2 = load_bearer_from_env("SER_TEST_TOKEN")
    assert tok2 == "secret-value" and env2 == "SER_TEST_TOKEN"


def test_redacted_summary_never_shows_secrets() -> None:
    s = AuthSession(
        headers={"Authorization": "Bearer SECRET", "X-Debug": "yes"},
        cookies={"sessionid": "abc"},
        bearer_token="direct-token",
        source=SessionSource.CLI,
    )
    txt = redacted_session_summary(s)
    assert "SECRET" not in txt
    assert "abc" not in txt
    assert "direct-token" not in txt
    assert "sessionid" in txt
    assert "Authorization=<redacted>" in txt or "authorization=<redacted>" in txt.lower()
    audit = s.model_for_audit()
    assert "SECRET" not in json.dumps(audit)
    assert audit["bearer_token"] == "present"


def test_sanitize_for_report() -> None:
    dirty = "Authorization: Bearer leak-token-here"
    clean = sanitize_for_report(dirty)
    assert "leak-token" not in clean


def test_merge_session_file_json(tmp_path: Path) -> None:
    p = tmp_path / "sess.json"
    p.write_text(
        json.dumps(
            {"headers": {"H": "v"}, "cookies": {"c": "d"}, "bearer_token_env": "NONESuch"}
        ),
        encoding="utf-8",
    )
    s = merge_cli_session(cookies={}, headers={}, bearer_token_env_name=None, session_file=p)
    assert s.headers.get("H") == "v"
    assert s.cookies.get("c") == "d"
    assert s.bearer_token_env == "NONESuch"


def test_merge_session_file_yaml(tmp_path: Path) -> None:
    yaml = pytest.importorskip("yaml")
    p = tmp_path / "sess.yaml"
    p.write_text(
        yaml.safe_dump({"headers": {"A": "b"}, "cookies": {"sid": "x"}}),
        encoding="utf-8",
    )
    s = merge_cli_session(cookies={}, headers={}, bearer_token_env_name=None, session_file=p)
    assert s.headers["A"] == "b"
    assert "sid" in s.cookies


def test_scope_guard_blocks_foreign_urls() -> None:
    s = AuthSession(
        source=SessionSource.CLI,
        allowed_url_prefixes=("https://good.example/",),
    )
    enforce_scope("https://good.example/path", s)
    with pytest.raises(ScopeViolationError):
        enforce_scope("https://evil.example/", s)


def test_crawler_uses_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, object]] = []

    class FakeResp:
        status_code = 200
        headers = {"content-type": "text/html"}
        text = '<html><a href="/p">x</a></html>'

        @property
        def url(self) -> str:
            return "http://127.0.0.1:9/"

    def fake_fetch(url: str, session: AuthSession, **kw: object) -> FakeResp:
        hdr: dict[str, str] = build_request_headers(session)
        ck: dict[str, str] = dict(session.cookies)
        calls.append({"url": url, "headers": hdr, "cookies": ck})
        return FakeResp()

    session = AuthSession(
        cookies={"c": "v"},
        headers={"X": "y"},
        bearer_token="tok",
        source=SessionSource.CLI,
        allowed_url_prefixes=("http://127.0.0.1:9",),
    )
    with patch("scanner.ser.phases.web_crawl.fetch_url", side_effect=fake_fetch):
        out = crawl_web("http://127.0.0.1:9/", session, max_pages=2)
    first = calls[0]
    assert isinstance(first["headers"], dict) and isinstance(first["cookies"], dict)
    assert first["headers"].get("Authorization") == "Bearer tok"
    assert first["cookies"].get("c") == "v"
    audit = out["audit"]
    assert isinstance(audit, dict)
    dump = json.dumps(out)
    assert "Bearer tok" not in dump
    assert "c=v" not in dump


def test_interact_uses_session(monkeypatch: pytest.MonkeyPatch) -> None:
    session = AuthSession(
        cookies={"s": "1"},
        source=SessionSource.CLI,
        allowed_url_prefixes=("https://ex.example",),
    )

    class R:
        status_code = 204
        headers: dict[str, str] = {}

    with patch("scanner.ser.phases.web_interact.fetch_url", return_value=R()) as m:
        out = web_interact("https://ex.example/x", session)
    m.assert_called_once()
    assert out["status_code"] == 204
    assert "s" in json.dumps(session.model_for_audit()["cookies"])


def test_controlled_validation_requires_approval() -> None:
    s = AuthSession(
        source=SessionSource.CLI,
        allowed_url_prefixes=("https://a.example",),
    )
    with pytest.raises(ApprovalRequiredError):
        run_controlled_validation("https://a.example/z", s, approved=False)


def test_controlled_validation_after_approval(monkeypatch: pytest.MonkeyPatch) -> None:
    s = AuthSession(
        source=SessionSource.CLI,
        allowed_url_prefixes=("https://b.example",),
    )

    class R:
        status_code = 200
        headers: dict[str, str] = {}

    with patch("scanner.ser.phases.controlled_validation.fetch_url", return_value=R()):
        out = run_controlled_validation("https://b.example/", s, approved=True)
    assert out["approval_applied"] is True
    rep = json.dumps(out)
    assert "bearer" in rep.lower() or "present" in rep  # redacted path


def test_httpx_client_kwargs_includes_cookies_and_bearer() -> None:
    s = AuthSession(
        cookies={"a": "b"},
        bearer_token="x",
        source=SessionSource.CLI,
    )
    kw = httpx_client_kwargs(s)
    assert kw["cookies"]["a"] == "b"
    assert kw["headers"]["Authorization"] == "Bearer x"


def test_fetch_url_uses_httpx() -> None:
    """Smoke: patch Client.request at httpx layer."""

    session = AuthSession(
        headers={"Z": "1"},
        cookies={"c": "k"},
        bearer_token="bt",
        source=SessionSource.CLI,
    )
    mock_resp = MagicMock(status_code=200, headers={}, text="ok")

    with patch("scanner.ser.http_client.httpx.Client") as Client:
        inst = Client.return_value.__enter__.return_value
        inst.request.return_value = mock_resp
        r = fetch_url("http://example.test/", session)
        assert r.status_code == 200
        inst.request.assert_called_once()
        call_kw = inst.request.call_args[1]
        assert call_kw["cookies"]["c"] == "k"
