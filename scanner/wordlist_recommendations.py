from __future__ import annotations

from pathlib import Path

_WORDLISTS_ROOT = Path("wordlists")
_SECLISTS_ROOT = _WORDLISTS_ROOT / "SecLists-master"
_WEB_CONTENT = _SECLISTS_ROOT / "Discovery" / "Web-Content"
_GENERIC_WORDLIST = _WEB_CONTENT / "common.txt"

_TECH_WORDLIST_MAP: dict[str, tuple[Path, ...]] = {
    "wordpress": (
        _WEB_CONTENT / "CMS" / "wordpress.fuzz.txt",
    ),
    "nginx": (
        _WEB_CONTENT / "raft-medium-directories.txt",
    ),
    "apache": (
        _WEB_CONTENT / "Web-Servers" / "Apache.txt",
    ),
    # Next.js / Node — App Router, _next assets and API routes (custom list).
    "next": (
        _WORDLISTS_ROOT / "nextjs.txt",
    ),
    # JEUS WAS + WatJs framework (.dpg/.cpg) — Korean financial-sector stack.
    "jeus": (
        _WORDLISTS_ROOT / "jeus-watjs.txt",
    ),
    "watjs": (
        _WORDLISTS_ROOT / "jeus-watjs.txt",
    ),
    # Spring Boot — actuator endpoints (info/env/heapdump leaks).
    "spring": (
        _WEB_CONTENT / "Programming-Language-Specific" / "Java-Spring-Boot.txt",
    ),
    # Java application servers.
    "tomcat": (
        _WEB_CONTENT / "Web-Servers" / "Apache-Tomcat.txt",
    ),
    "jboss": (
        _WEB_CONTENT / "Web-Servers" / "JBoss.txt",
    ),
    "glassfish": (
        _WEB_CONTENT / "Web-Servers" / "Glassfish-Sun-Microsystems.txt",
    ),
    "servlet": (
        _WEB_CONTENT / "JavaServlets-Common.fuzz.txt",
    ),
    # Microsoft IIS / ASP.NET.
    "iis": (
        _WEB_CONTENT / "Web-Servers" / "IIS.txt",
    ),
    "asp.net": (
        _WEB_CONTENT / "Web-Servers" / "IIS.txt",
    ),
    # Adobe ColdFusion.
    "coldfusion": (
        _WEB_CONTENT / "coldfusion.txt",
    ),
}


def getRecommendedWordlists(technologies: list[str]) -> list[str]:
    normalized_tech = [str(item or "").strip().lower() for item in technologies if str(item or "").strip()]
    candidates: list[Path] = []
    seen: set[str] = set()
    for tech in normalized_tech:
        for key, paths in _TECH_WORDLIST_MAP.items():
            if key not in tech:
                continue
            for path in paths:
                _append_unique(candidates, seen, path)
    if not candidates:
        _append_unique(candidates, seen, _GENERIC_WORDLIST)

    resolved: list[str] = []
    for path in candidates:
        try:
            resolved.append(str(path.resolve()))
        except Exception:
            resolved.append(str(path))
    return resolved


def _append_unique(items: list[Path], seen: set[str], path: Path) -> None:
    key = str(path).replace("\\", "/").lower()
    if key in seen:
        return
    seen.add(key)
    items.append(path)
