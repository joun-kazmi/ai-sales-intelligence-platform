"""Name candidates per record (signals-scoring.md section 1, D29, D44).

Sources in priority order: scan hostname > non-wildcard cert CN > http.host > named PTR.
Each hostname is reduced to its registrable domain with the bundled Public Suffix List
(private section included, so platform tenants and dynamic-DNS hosts stay separate accounts).
"""

import ipaddress
import re
from functools import cache

import tldextract

from salesintel.pipeline.infra import InfraLists, is_infra_hostname

SOURCES = ("scan_hostname", "cert_cn", "http_host", "ptr")

_HOSTNAME = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$")
# Four 1-3 digit groups joined by separators: generic ISP / cloud PTR naming.
_DOTTED_QUAD = re.compile(r"(?<!\d)\d{1,3}[.\-_x]\d{1,3}[.\-_x]\d{1,3}[.\-_x]\d{1,3}(?!\d)")


@cache
def _extractor() -> tldextract.TLDExtract:
    # No network: use the PSL snapshot bundled with tldextract (its version is the PSL version).
    return tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)


def psl_version() -> str:
    return f"tldextract-{tldextract.__version__}-bundled"


def normalize(name: str | None) -> str | None:
    if not name or not isinstance(name, str):
        return None
    host = name.strip().lower().rstrip(".")
    if host.startswith("[") or host.count(":") > 1:
        return None  # IPv6 literal
    host = host.split(":", 1)[0]  # drop :port
    if not _HOSTNAME.match(host):
        return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        return host


def registrable(host: str) -> str | None:
    return _extractor()(host).top_domain_under_public_suffix or None


def ip_like(host: str, ip: str) -> bool:
    """PTR names that embed the IP (ISP / cloud reverse DNS), e.g. 1-2-3-4.static.isp.net."""
    if _DOTTED_QUAD.search(host):
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version != 4:
        return False
    octets = ip.split(".")
    labels = re.split(r"[.\-_]", host)
    # All four octets present as labels in order or reversed, or the IP in hex.
    for seq in (octets, octets[::-1]):
        it = iter(labels)
        if all(any(o == label for label in it) for o in seq):
            return True
    return format(int(addr), "08x") in host


def candidates(
    lists: InfraLists,
    ip: str,
    scan_hostname: str | None,
    cert_cn: str | None,
    http_host: str | None,
    ptr: list[str],
) -> list[tuple[str, str]]:
    """Non-infra (source, registrable domain) pairs in priority order, one per domain."""
    raw: list[tuple[str, str | None]] = [("scan_hostname", scan_hostname)]
    if cert_cn and not cert_cn.lstrip().startswith("*"):
        raw.append(("cert_cn", cert_cn))
    raw.append(("http_host", http_host))
    raw.extend(("ptr", h) for h in ptr)

    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for source, name in raw:
        host = normalize(name)
        if host is None or is_infra_hostname(lists, host):
            continue
        if source == "ptr" and ip_like(host, ip):
            continue
        domain = registrable(host)
        if domain is None or domain in seen or is_infra_hostname(lists, domain):
            continue
        seen.add(domain)
        out.append((source, domain))
    return out
