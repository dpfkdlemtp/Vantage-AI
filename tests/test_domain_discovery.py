from __future__ import annotations

from scanner.execution.domain_discovery import parse_tls_pem_to_domains, reverse_dns_for_ip


def test_parse_tls_pem_to_domains_dns_and_cn() -> None:
    pem = """
    DNS:example.com
    DNS:*.example.org
    commonName=cn.test
    """
    out = parse_tls_pem_to_domains(pem)
    assert "example.com" in out
    assert "*.example.org" in out
    assert "cn.test" in out


def test_reverse_dns_fallback_on_oserror() -> None:
    def fake_gethostbyaddr(_ip: str) -> tuple[str, list[str], list[str]]:
        raise OSError("nxdomain")

    assert reverse_dns_for_ip("8.8.8.8", gethostbyaddr=fake_gethostbyaddr) is None


def test_reverse_dns_ok() -> None:
    def fake_gethostbyaddr(ip: str) -> tuple[str, list[str], list[str]]:
        return ("ptr.example.com", [], [ip])

    assert reverse_dns_for_ip("8.8.8.8", gethostbyaddr=fake_gethostbyaddr) == "ptr.example.com"
