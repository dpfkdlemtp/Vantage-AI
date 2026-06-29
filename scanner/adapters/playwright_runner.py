"""Headless browser adapter built on Playwright.

Provides three capabilities:
1. JS-rendered page crawling — captures final DOM, links, scripts, XHR endpoints.
2. SPA recursive crawling — follows in-scope links up to a depth.
3. Auth form auto-login — fills a login form, returns session cookies/headers.

Playwright is an optional dependency. All entry points fail gracefully via
`is_playwright_available()` and return empty results if the runtime is missing.
"""
from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

_log = logging.getLogger(__name__)


@dataclass(frozen=True)
class FormDescriptor:
    method: str
    action: str
    fields: list[str]
    has_password: bool


@dataclass(frozen=True)
class CrawlPageResult:
    url: str
    final_url: str
    status: int
    title: str
    dom_links: list[str]
    js_files: list[str]
    xhr_endpoints: list[str]
    forms: list[FormDescriptor]
    error: str = ""


@dataclass(frozen=True)
class CrawlRunResult:
    start_urls: list[str]
    pages: list[CrawlPageResult]
    discovered_endpoints: list[str]
    visited_count: int = 0


@dataclass(frozen=True)
class LoginResult:
    success: bool
    final_url: str
    cookies: list[dict[str, Any]] = field(default_factory=list)
    cookie_header: str = ""
    storage_origins: list[str] = field(default_factory=list)
    message: str = ""


def is_playwright_available() -> bool:
    try:
        import playwright.sync_api as _pw  # noqa: F401
    except ImportError:
        return False
    return True


def crawl_pages(
    start_urls: list[str],
    *,
    max_depth: int = 1,
    max_pages: int = 50,
    timeout_seconds: int = 15,
    wait_until: str = "networkidle",
    user_agent: str = "",
    same_origin_only: bool = True,
    extra_headers: dict[str, str] | None = None,
    cookies: list[dict[str, Any]] | None = None,
) -> CrawlRunResult:
    """Render each start URL, optionally follow in-scope links up to max_depth."""
    if not is_playwright_available():
        return CrawlRunResult(start_urls=list(start_urls), pages=[], discovered_endpoints=[])
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return CrawlRunResult(start_urls=list(start_urls), pages=[], discovered_endpoints=[])

    visited: set[str] = set()
    pages: list[CrawlPageResult] = []
    all_endpoints: set[str] = set()
    queue: list[tuple[str, int]] = [(u, 0) for u in start_urls]

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            context_kwargs: dict[str, Any] = {"ignore_https_errors": True}
            if user_agent:
                context_kwargs["user_agent"] = user_agent
            if extra_headers:
                context_kwargs["extra_http_headers"] = dict(extra_headers)
            context = browser.new_context(**context_kwargs)
            if cookies:
                try:
                    context.add_cookies(_normalize_cookies(cookies))
                except Exception as exc:  # noqa: BLE001
                    _log.debug("cookie injection failed: %s", exc)
            try:
                while queue and len(visited) < max_pages:
                    url, depth = queue.pop(0)
                    if url in visited or depth > max_depth:
                        continue
                    visited.add(url)
                    page_result = _render_one(
                        context, url,
                        timeout_seconds=timeout_seconds,
                        wait_until=wait_until,
                    )
                    pages.append(page_result)
                    all_endpoints.update(page_result.dom_links)
                    all_endpoints.update(page_result.xhr_endpoints)
                    if depth < max_depth:
                        scope_origin = _origin_of(url) if same_origin_only else None
                        for link in page_result.dom_links:
                            if link in visited:
                                continue
                            if same_origin_only and scope_origin and _origin_of(link) != scope_origin:
                                continue
                            queue.append((link, depth + 1))
            finally:
                context.close()
                browser.close()
    except Exception as exc:  # noqa: BLE001
        _log.warning("playwright crawl failed: %s", exc)
        return CrawlRunResult(
            start_urls=list(start_urls),
            pages=pages,
            discovered_endpoints=sorted(all_endpoints),
            visited_count=len(visited),
        )

    return CrawlRunResult(
        start_urls=list(start_urls),
        pages=pages,
        discovered_endpoints=sorted(all_endpoints),
        visited_count=len(visited),
    )


def auto_login(
    login_url: str,
    username: str,
    password: str,
    *,
    username_field_hints: Iterable[str] = ("username", "email", "user", "login", "userid", "id"),
    password_field_hints: Iterable[str] = ("password", "passwd", "pwd", "pass"),
    submit_field_hints: Iterable[str] = ("login", "signin", "sign in", "submit", "log in", "로그인"),
    timeout_seconds: int = 20,
    extra_headers: dict[str, str] | None = None,
    success_url_keyword: str = "",
) -> LoginResult:
    """Open login_url, find credentials inputs, submit. Returns cookies on success."""
    if not is_playwright_available():
        return LoginResult(success=False, final_url="", message="playwright not installed")
    if not login_url or not username or not password:
        return LoginResult(success=False, final_url="", message="login_url, username, password required")
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return LoginResult(success=False, final_url="", message="playwright import failed")

    user_hints = [h.lower() for h in username_field_hints]
    pass_hints = [h.lower() for h in password_field_hints]
    submit_hints = [h.lower() for h in submit_field_hints]

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            context_kwargs: dict[str, Any] = {"ignore_https_errors": True}
            if extra_headers:
                context_kwargs["extra_http_headers"] = dict(extra_headers)
            context = browser.new_context(**context_kwargs)
            try:
                page = context.new_page()
                page.goto(login_url, timeout=timeout_seconds * 1000, wait_until="domcontentloaded")
                # Try to fill credentials
                if not _fill_field(page, user_hints, username, password_field=False):
                    return LoginResult(success=False, final_url=page.url, message="username field not found")
                if not _fill_field(page, pass_hints, password, password_field=True):
                    return LoginResult(success=False, final_url=page.url, message="password field not found")
                # Submit
                submit_ok = _click_submit(page, submit_hints)
                if not submit_ok:
                    # As a fallback, press Enter in the password field
                    try:
                        page.keyboard.press("Enter")
                    except Exception:  # noqa: BLE001
                        pass
                # Wait for navigation
                try:
                    page.wait_for_load_state("networkidle", timeout=timeout_seconds * 1000)
                except Exception:  # noqa: BLE001
                    pass
                final_url = page.url
                cookies = context.cookies()
                cookie_header = "; ".join(f"{c['name']}={c['value']}" for c in cookies if c.get("name"))
                storage_origins = []
                try:
                    state = context.storage_state()
                    storage_origins = [o.get("origin", "") for o in state.get("origins", [])]
                except Exception:  # noqa: BLE001
                    pass
                success = _login_looks_successful(final_url, login_url, cookies, success_url_keyword)
                return LoginResult(
                    success=success,
                    final_url=final_url,
                    cookies=cookies,
                    cookie_header=cookie_header,
                    storage_origins=storage_origins,
                    message="login submitted" if success else "submission completed but success uncertain",
                )
            finally:
                context.close()
                browser.close()
    except Exception as exc:  # noqa: BLE001
        _log.warning("playwright login failed: %s", exc)
        return LoginResult(success=False, final_url=login_url, message=f"exception: {exc}")


def _render_one(context: Any, url: str, *, timeout_seconds: int, wait_until: str) -> CrawlPageResult:
    page = context.new_page()
    xhr_endpoints: set[str] = set()
    js_files: set[str] = set()

    def _on_request(request: Any) -> None:
        try:
            rtype = request.resource_type
            rurl = request.url
            if rtype in ("xhr", "fetch"):
                xhr_endpoints.add(rurl)
            if rtype == "script" or rurl.endswith(".js"):
                js_files.add(rurl)
        except Exception:  # noqa: BLE001
            pass

    page.on("request", _on_request)
    try:
        response = page.goto(url, timeout=timeout_seconds * 1000, wait_until=wait_until)
        status = response.status if response is not None else 0
        final_url = page.url
        try:
            title = page.title()
        except Exception:  # noqa: BLE001
            title = ""
        try:
            hrefs = page.eval_on_selector_all(
                "a[href]",
                "elements => elements.map(e => e.href).filter(h => h)",
            )
        except Exception:  # noqa: BLE001
            hrefs = []
        dom_links = sorted({_normalize_url(h, final_url) for h in hrefs if h})
        forms = _extract_forms(page, final_url)
        return CrawlPageResult(
            url=url, final_url=final_url, status=status, title=title,
            dom_links=dom_links, js_files=sorted(js_files),
            xhr_endpoints=sorted(xhr_endpoints), forms=forms,
        )
    except Exception as exc:  # noqa: BLE001
        return CrawlPageResult(
            url=url, final_url=url, status=0, title="",
            dom_links=[], js_files=[], xhr_endpoints=[], forms=[],
            error=str(exc),
        )
    finally:
        page.close()


def _extract_forms(page: Any, base_url: str) -> list[FormDescriptor]:
    try:
        raw = page.eval_on_selector_all(
            "form",
            """forms => forms.map(f => ({
                method: (f.getAttribute('method') || 'GET').toUpperCase(),
                action: f.getAttribute('action') || '',
                fields: Array.from(f.querySelectorAll('input,textarea,select')).map(i => i.getAttribute('name') || i.getAttribute('id') || ''),
                hasPassword: !!f.querySelector("input[type='password']")
            }))""",
        )
    except Exception:  # noqa: BLE001
        return []
    out: list[FormDescriptor] = []
    for raw_form in raw or []:
        action = raw_form.get("action") or ""
        absolute = urljoin(base_url, action) if action else base_url
        out.append(FormDescriptor(
            method=str(raw_form.get("method", "GET")).upper(),
            action=absolute,
            fields=[str(name) for name in (raw_form.get("fields") or []) if name],
            has_password=bool(raw_form.get("hasPassword")),
        ))
    return out


def _fill_field(page: Any, name_hints: list[str], value: str, *, password_field: bool) -> bool:
    type_filter = "input[type='password']" if password_field else "input:not([type='password']):not([type='hidden']):not([type='submit']):not([type='button'])"
    try:
        candidates = page.query_selector_all(f"{type_filter}, textarea") if not password_field else page.query_selector_all(type_filter)
    except Exception:  # noqa: BLE001
        candidates = []
    for handle in candidates or []:
        try:
            attrs = page.evaluate(
                """(e) => ({
                    name: (e.getAttribute('name') || '').toLowerCase(),
                    id: (e.getAttribute('id') || '').toLowerCase(),
                    type: (e.getAttribute('type') || '').toLowerCase(),
                    placeholder: (e.getAttribute('placeholder') || '').toLowerCase(),
                    autocomplete: (e.getAttribute('autocomplete') || '').toLowerCase(),
                })""",
                handle,
            )
        except Exception:  # noqa: BLE001
            attrs = {}
        haystack = " ".join(str(attrs.get(k, "")) for k in ("name", "id", "type", "placeholder", "autocomplete"))
        if any(hint in haystack for hint in name_hints):
            try:
                handle.fill(value)
                return True
            except Exception:  # noqa: BLE001
                continue
    # Fallback: first input of the expected type
    if candidates:
        try:
            candidates[0].fill(value)
            return True
        except Exception:  # noqa: BLE001
            return False
    return False


def _click_submit(page: Any, hints: list[str]) -> bool:
    try:
        # Prefer explicit submit buttons
        buttons = page.query_selector_all("button[type='submit'], input[type='submit'], button:not([type]), [role='button']")
    except Exception:  # noqa: BLE001
        return False
    for btn in buttons or []:
        try:
            text = (btn.inner_text() or "").lower()
        except Exception:  # noqa: BLE001
            text = ""
        if any(hint in text for hint in hints):
            try:
                btn.click()
                return True
            except Exception:  # noqa: BLE001
                continue
    # As a fallback, click the first submit button
    if buttons:
        try:
            buttons[0].click()
            return True
        except Exception:  # noqa: BLE001
            return False
    return False


def _login_looks_successful(final_url: str, login_url: str, cookies: list[dict[str, Any]], keyword: str) -> bool:
    if keyword and keyword.lower() in final_url.lower():
        return True
    # Heuristic: redirected away from login page AND has at least one cookie
    if final_url and final_url.rstrip("/") != login_url.rstrip("/"):
        session_like = any(
            re.search(r"(session|sid|token|auth|jwt|sso)", str(c.get("name", ""))[:64], re.IGNORECASE)
            for c in cookies
        )
        return session_like or len(cookies) >= 1
    return False


def _normalize_url(href: str, base: str) -> str:
    try:
        absolute = urljoin(base, href)
        parts = urlsplit(absolute)
        if parts.scheme not in ("http", "https"):
            return ""
        # Strip fragment
        return absolute.split("#", 1)[0]
    except Exception:  # noqa: BLE001
        return ""


def _origin_of(url: str) -> str:
    try:
        p = urlsplit(url)
        return f"{p.scheme}://{p.netloc}"
    except Exception:  # noqa: BLE001
        return ""


def _normalize_cookies(cookies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for c in cookies:
        if not isinstance(c, dict):
            continue
        name = c.get("name")
        value = c.get("value")
        if not name:
            continue
        entry: dict[str, Any] = {"name": str(name), "value": str(value or "")}
        for key in ("domain", "path", "expires", "httpOnly", "secure", "sameSite", "url"):
            if key in c and c[key] is not None:
                entry[key] = c[key]
        out.append(entry)
    return out
