from __future__ import annotations

from scanner.extension_recommendations import (
    FFUF_EXTENSION_CATALOG,
    getRecommendedExtensions,
    merge_auto_extensions,
    normalize_ffuf_extensions,
)


def test_get_recommended_extensions_nginx_php_html() -> None:
    ex = getRecommendedExtensions("http", "nginx/1.24.0")
    assert ".php" in ex
    assert ".html" in ex


def test_get_recommended_extensions_iis_aspx() -> None:
    ex = getRecommendedExtensions("https", "Microsoft-IIS/10.0")
    assert ".aspx" in ex
    assert ".ashx" in ex or ".asp" in ex


def test_get_recommended_extensions_with_wappalyzer_stack() -> None:
    ex = getRecommendedExtensions("http", "WordPress nginx node django")
    assert ".php" in ex
    assert ".bak" in ex
    assert ".zip" in ex
    assert ".js" in ex
    assert ".json" in ex
    assert len(ex) <= 10


def test_merge_auto_and_normalize() -> None:
    m = merge_auto_extensions([".php"], [".html", ".php"])
    assert m == [".php", ".html"]
    assert normalize_ffuf_extensions(["php", ".jsp", ""]) == [".php", ".jsp"]


def test_catalog_nonempty() -> None:
    assert ".php" in FFUF_EXTENSION_CATALOG
    assert len(FFUF_EXTENSION_CATALOG) >= 10
