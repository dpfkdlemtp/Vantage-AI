from __future__ import annotations

from scanner.wordlist_recommendations import getRecommendedWordlists


def test_get_recommended_wordlists_fallback_common() -> None:
    rows = getRecommendedWordlists([])
    assert rows
    assert rows[0].replace("\\", "/").endswith("wordlists/SecLists-master/Discovery/Web-Content/common.txt")


def test_get_recommended_wordlists_wordpress_and_nginx() -> None:
    rows = getRecommendedWordlists(["WordPress", "nginx"])
    normalized = [item.replace("\\", "/") for item in rows]
    assert any(path.endswith("wordlists/SecLists-master/Discovery/Web-Content/CMS/wordpress.fuzz.txt") for path in normalized)
    assert any(path.endswith("wordlists/SecLists-master/Discovery/Web-Content/raft-medium-directories.txt") for path in normalized)


def test_get_recommended_wordlists_nextjs() -> None:
    rows = getRecommendedWordlists(["Next.js"])
    normalized = [item.replace("\\", "/") for item in rows]
    assert any(path.endswith("wordlists/nextjs.txt") for path in normalized)


def test_get_recommended_wordlists_jeus_watjs() -> None:
    rows = getRecommendedWordlists(["JEUS"])
    normalized = [item.replace("\\", "/") for item in rows]
    assert any(path.endswith("wordlists/jeus-watjs.txt") for path in normalized)


def test_get_recommended_wordlists_spring_actuator() -> None:
    rows = getRecommendedWordlists(["Spring"])
    normalized = [item.replace("\\", "/") for item in rows]
    assert any(
        path.endswith("Programming-Language-Specific/Java-Spring-Boot.txt")
        for path in normalized
    )


def test_get_recommended_wordlists_tomcat_and_iis() -> None:
    tomcat = [p.replace("\\", "/") for p in getRecommendedWordlists(["Apache Tomcat"])]
    assert any(p.endswith("Web-Servers/Apache-Tomcat.txt") for p in tomcat)
    iis = [p.replace("\\", "/") for p in getRecommendedWordlists(["Microsoft-IIS/10.0"])]
    assert any(p.endswith("Web-Servers/IIS.txt") for p in iis)


def test_all_mapped_wordlists_resolve_to_existing_files() -> None:
    # Every recommendation we ship must point at a file that actually exists,
    # otherwise the dirscan auto-selection silently falls back to the default.
    from pathlib import Path

    from scanner.wordlist_recommendations import _TECH_WORDLIST_MAP

    missing = [
        str(path)
        for paths in _TECH_WORDLIST_MAP.values()
        for path in paths
        if not Path(path).exists()
    ]
    assert missing == []
