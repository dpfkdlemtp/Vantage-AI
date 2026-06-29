from __future__ import annotations

from collections.abc import Sequence

from scanner.config import derive_extensions_from_tech

MAX_RECOMMENDED_EXTENSIONS = 10

_EXTENSION_ORDER = (
    "microsoft-iis",
    "httpapi",
    "microsoft httpapi",
    "openresty",
    "nginx",
    "apache",
    "httpd",
    "caddy",
    "lighttpd",
    "iis",
    "tomcat",
    "jetty",
    "gunicorn",
    "uwsgi",
)

# Keys matched as substrings in (service + " " + tech).lower()
EXTENSION_MAP: dict[str, tuple[str, ...]] = {
    "wordpress": (".php", ".bak", ".zip"),
    "nginx": (".php", ".html"),
    "openresty": (".php", ".html", ".lua"),
    "apache": (".php", ".html", ".pl", ".cgi"),
    "httpd": (".php", ".html", ".pl", ".cgi"),
    "caddy": (".php", ".html"),
    "lighttpd": (".php", ".html", ".pl"),
    "iis": (".aspx", ".asp", ".ashx"),
    "microsoft-iis": (".aspx", ".asp", ".ashx"),
    "microsoft httpapi": (".aspx",),
    "httpapi": (".aspx",),
    "tomcat": (".jsp", ".jspx", ".do", ".action"),
    "jetty": (".jsp", ".jspx", ".do"),
    "gunicorn": (".py", ".html"),
    "uwsgi": (".py", ".html", ".wsgi"),
    "node": (".js", ".json"),
    "django": (".py", ".json"),
}


def getRecommendedExtensions(service: str, tech: str) -> list[str]:
    """
    Suggest file extensions (with leading dot) for ffuf -e, using stack/service/tech heuristics
    and the shared TECH list via derive_extensions_from_tech.
    """
    blob = f"{service or ''} {tech or ''}".lower()
    from_map: list[str] = []
    seen: set[str] = set()
    for key in _EXTENSION_ORDER:
        exts = EXTENSION_MAP.get(key, ())
        if not exts or key not in blob:
            continue
        for ext in exts:
            if ext not in seen:
                seen.add(ext)
                from_map.append(ext)
    for key, exts in sorted(
        (k, v) for k, v in EXTENSION_MAP.items() if k not in _EXTENSION_ORDER
    ):
        if key in blob:
            for ext in exts:
                if ext not in seen:
                    seen.add(ext)
                    from_map.append(ext)
    token_source = f"{service or ''} {tech or ''}"
    tokens = [t.strip() for t in token_source.replace(",", " ").split() if t.strip()]
    from_tech = derive_extensions_from_tech(tokens)
    merged: list[str] = []
    seen2: set[str] = set()
    for ext in from_tech + from_map:
        if ext in seen2:
            continue
        seen2.add(ext)
        merged.append(ext)
    return merged[:MAX_RECOMMENDED_EXTENSIONS]


def merge_auto_extensions(derived: Sequence[str], recommended: Sequence[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for ext in list(derived) + list(recommended):
        if ext in seen:
            continue
        seen.add(ext)
        out.append(ext)
    return out[:MAX_RECOMMENDED_EXTENSIONS]


# Common checkboxes in UI (ffuf -e, leading dot)
FFUF_EXTENSION_CATALOG: tuple[str, ...] = (
    ".php",
    ".html",
    ".htm",
    ".asp",
    ".aspx",
    ".ashx",
    ".jsp",
    ".jspx",
    ".do",
    ".py",
    ".pl",
    ".cgi",
    ".json",
    ".xml",
    ".js",
    ".css",
    ".md",
    ".yml",
    ".yaml",
)


def normalize_ffuf_extension_item(raw: str) -> str:
    t = (raw or "").strip()
    if not t:
        return ""
    t = t.lstrip(".")
    if not t:
        return ""
    if not t.startswith("."):
        t = "." + t
    return t


def normalize_ffuf_extensions(values: Sequence[str] | None) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for v in values or ():
        n = normalize_ffuf_extension_item(str(v))
        if not n or n in seen:
            continue
        seen.add(n)
        out.append(n)
    return out[:MAX_RECOMMENDED_EXTENSIONS]
