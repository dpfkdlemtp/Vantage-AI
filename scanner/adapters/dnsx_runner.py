from __future__ import annotations

import json
import shutil
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from uuid import uuid4

from scanner.utils.process import run_text_capture

# Common subdomain prefixes used for active brute-force
BUILTIN_SUBDOMAIN_WORDS: tuple[str, ...] = (
    "www", "mail", "ftp", "api", "dev", "staging", "test", "admin", "portal",
    "vpn", "remote", "secure", "auth", "login", "app", "web", "beta", "cdn",
    "static", "assets", "media", "images", "docs", "help", "support", "blog",
    "shop", "store", "payment", "account", "dashboard", "monitor", "status",
    "internal", "intranet", "git", "gitlab", "jenkins", "jira", "confluence",
    "wiki", "ns1", "ns2", "mx", "smtp", "pop", "imap", "webmail", "mobile",
    "m", "api2", "v1", "v2", "old", "new", "stage", "uat", "qa", "prod",
    "sandbox", "demo", "lab", "cdn2", "download", "uploads", "files", "img",
    "corp", "cloud", "office", "ws", "socket", "push", "broker", "cache",
    "db", "redis", "mysql", "dev2", "test2", "api3", "gateway", "proxy",
    "monitor", "grafana", "kibana", "elastic", "consul", "vault", "k8s",
    "kubernetes", "docker", "registry", "harbor", "sonar", "nexus",
)


# Number of random non-existent labels probed to detect a DNS wildcard.
WILDCARD_PROBE_COUNT = 3


@dataclass(frozen=True)
class DnsxBruteforceResult:
    hosts: list[str]
    wildcard_ips: list[str] = field(default_factory=list)
    # hosts that resolved only to the wildcard IP(s) and were filtered out
    filtered_hosts: list[str] = field(default_factory=list)


def is_dnsx_available(dnsx_bin: str = "dnsx") -> bool:
    return shutil.which(dnsx_bin) is not None


def _resolve_names(
    names: Sequence[str],
    *,
    dnsx_bin: str,
    threads: int,
) -> dict[str, set[str]]:
    """Resolve names via dnsx, returning host -> set of A-record IPs.

    Hosts that resolve with no A record (e.g. CNAME-only) map to an empty set.
    """
    candidates = [str(name).strip() for name in names if str(name).strip()]
    if not candidates:
        return {}

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, encoding="utf-8"
    ) as f:
        f.write("\n".join(candidates))
        tmp_path = Path(f.name)

    resolved: dict[str, set[str]] = {}
    try:
        command = [
            dnsx_bin,
            "-l", str(tmp_path),
            "-silent",
            "-json",
            "-a",
            "-resp",
            "-t", str(threads),
        ]
        completed = run_text_capture(command)
        # dnsx exits non-zero when nothing resolves — that's fine
        for line in completed.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                # plain-text mode fallback (no IPs available)
                host = line.lower().rstrip(".")
                if "." in host:
                    resolved.setdefault(host, set())
                continue
            host = str(entry.get("host") or "").strip().lower().rstrip(".")
            if not host:
                continue
            ips = {
                str(ip).strip()
                for ip in (entry.get("a") or [])
                if str(ip).strip()
            }
            resolved.setdefault(host, set()).update(ips)
    finally:
        tmp_path.unlink(missing_ok=True)
    return resolved


def detect_wildcard_ips(
    root_domain: str,
    *,
    dnsx_bin: str = "dnsx",
    threads: int = 50,
    probe_count: int = WILDCARD_PROBE_COUNT,
) -> set[str]:
    """Probe random non-existent labels; any IPs they resolve to are a wildcard.

    A wildcard DNS record answers every label under the zone, so brute-forced
    subdomains "resolve" even though they do not exist (the dnsx fake-subdomain
    trap). The union of IPs returned for guaranteed-nonexistent labels is the
    wildcard answer set.
    """
    probes = [
        f"wildcard-probe-{uuid4().hex[:18]}.{root_domain}"
        for _ in range(max(1, probe_count))
    ]
    resolved = _resolve_names(probes, dnsx_bin=dnsx_bin, threads=threads)
    wildcard_ips: set[str] = set()
    for ips in resolved.values():
        wildcard_ips.update(ips)
    return wildcard_ips


def run_dnsx_bruteforce_detailed(
    root_domain: str,
    *,
    dnsx_bin: str = "dnsx",
    wordlist: Sequence[str] | None = None,
    threads: int = 50,
    detect_wildcard: bool = True,
) -> DnsxBruteforceResult:
    """Brute-force subdomains, filtering DNS-wildcard false positives."""
    words = list(wordlist) if wordlist is not None else list(BUILTIN_SUBDOMAIN_WORDS)
    candidates = [f"{w}.{root_domain}" for w in words if w.strip()]
    if not candidates:
        return DnsxBruteforceResult(hosts=[])

    wildcard_ips = (
        detect_wildcard_ips(root_domain, dnsx_bin=dnsx_bin, threads=threads)
        if detect_wildcard
        else set()
    )

    resolved = _resolve_names(candidates, dnsx_bin=dnsx_bin, threads=threads)
    kept: list[str] = []
    filtered: list[str] = []
    for host, ips in resolved.items():
        if host == root_domain or not host.endswith(f".{root_domain}"):
            continue
        # Drop only when the host resolves exclusively to wildcard IP(s): a
        # guessed name pointing solely at the wildcard answer does not really
        # exist. Hosts with any non-wildcard IP (or no captured A record) stay.
        if wildcard_ips and ips and ips.issubset(wildcard_ips):
            filtered.append(host)
            continue
        kept.append(host)

    return DnsxBruteforceResult(
        hosts=sorted(set(kept)),
        wildcard_ips=sorted(wildcard_ips),
        filtered_hosts=sorted(set(filtered)),
    )


def run_dnsx_bruteforce(
    root_domain: str,
    *,
    dnsx_bin: str = "dnsx",
    wordlist: Sequence[str] | None = None,
    threads: int = 50,
    detect_wildcard: bool = True,
) -> list[str]:
    """Brute-force subdomains via DNS resolution. Returns resolved hostnames.

    Wildcard DNS false positives are filtered out by default.
    """
    return run_dnsx_bruteforce_detailed(
        root_domain,
        dnsx_bin=dnsx_bin,
        wordlist=wordlist,
        threads=threads,
        detect_wildcard=detect_wildcard,
    ).hosts
