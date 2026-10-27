"""One Shodan record -> one feature row (signals-scoring.md section 3), or a drop reason.

Record contents are untrusted: strings are truncated and stored, never interpreted.
"""

from typing import Any

import pyarrow as pa

from salesintel.pipeline import names
from salesintel.pipeline.infra import InfraLists, appliance, infra_class

MAX_STR = 200
MAX_LIST = 20

SCHEMA = pa.schema(
    [
        ("ip", pa.string()),
        ("port", pa.int32()),
        ("transport", pa.string()),
        ("timestamp", pa.string()),
        ("module", pa.string()),
        ("shodan_id", pa.string()),
        ("crawler", pa.string()),
        ("banner_hash", pa.int64()),
        ("org", pa.string()),
        ("isp", pa.string()),
        ("asn", pa.string()),
        ("cloud_provider", pa.string()),
        ("tags", pa.list_(pa.string())),
        ("infra_class", pa.string()),
        ("appliance", pa.string()),
        ("scan_hostname", pa.string()),
        ("cert_cn", pa.string()),
        ("http_host", pa.string()),
        ("hostnames", pa.list_(pa.string())),
        ("domains", pa.list_(pa.string())),
        ("names", pa.list_(pa.struct([("source", pa.string()), ("domain", pa.string())]))),
        ("product", pa.string()),
        ("version", pa.string()),
        ("cpe23", pa.list_(pa.string())),
        (
            "vulns",
            pa.list_(
                pa.struct(
                    [
                        ("cve", pa.string()),
                        ("cvss", pa.float64()),
                        ("cvss_version", pa.string()),
                        ("epss", pa.float64()),
                        ("kev", pa.bool_()),
                        ("ransomware", pa.string()),
                        ("verified", pa.bool_()),
                    ]
                )
            ),
        ),
        ("opts_vulns", pa.list_(pa.string())),
        ("has_ssl", pa.bool_()),
        ("cert_expired", pa.bool_()),
        ("cert_expires", pa.string()),
        ("cert_issued", pa.string()),
        ("cert_self_signed", pa.bool_()),
        ("cert_o", pa.string()),
        ("ssl_versions", pa.list_(pa.string())),
        ("has_http", pa.bool_()),
        ("has_hsts", pa.bool_()),
        ("http_status", pa.int32()),
        ("http_server", pa.string()),
        ("http_title", pa.string()),
        ("http_waf", pa.string()),
        ("has_docker", pa.bool_()),
        ("sample_ip_domain_count", pa.int32()),
    ]
)
COLUMNS = SCHEMA.names


def _s(v: Any) -> str | None:
    if v is None or v == "":
        return None
    return str(v)[:MAX_STR]


def _strs(v: Any) -> list[str]:
    if not isinstance(v, list):
        return []
    return [str(x)[:MAX_STR] for x in v[:MAX_LIST] if x is not None]


def _float(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _vulns(v: Any) -> list[dict]:
    if not isinstance(v, dict):
        return []
    out = []
    for cve, info in v.items():
        info = info if isinstance(info, dict) else {}
        out.append(
            {
                "cve": str(cve)[:40],
                "cvss": _float(info.get("cvss")),
                "cvss_version": _s(info.get("cvss_version")),
                "epss": _float(info.get("epss")),
                "kev": info.get("kev") is True,
                "ransomware": _s(info.get("ransomware_campaign")),
                "verified": info.get("verified") is True,
            }
        )
    return out


def _d(v: Any) -> dict:
    return v if isinstance(v, dict) else {}


def _has_hsts(headers: Any) -> bool:
    if not isinstance(headers, dict):
        return False
    return any(str(k).lower() == "strict-transport-security" for k in headers)


def project(rec: dict, lists: InfraLists) -> tuple[dict | None, str]:
    """Return (row, 'kept') or (None, drop_reason)."""
    tags = _strs(rec.get("tags"))
    shodan = _d(rec.get("_shodan"))
    module = _s(shodan.get("module"))
    if "honeypot" in tags:
        return None, "honeypot"
    if module in lists.noise_modules:
        return None, "noise_module"

    ip = _s(rec.get("ip_str")) or _s(rec.get("ipv6"))
    if ip is None:
        return None, "no_ip"
    org = _s(rec.get("org")) or ""
    isp = _s(rec.get("isp")) or ""
    cloud_provider = _s(_d(rec.get("cloud")).get("provider"))
    klass = infra_class(lists, tags, org, isp, cloud_provider or "")

    ssl = _d(rec.get("ssl"))
    cert = _d(ssl.get("cert"))
    subject = _d(cert.get("subject"))
    issuer = _d(cert.get("issuer"))
    http = _d(rec.get("http"))
    options = _d(shodan.get("options"))

    scan_hostname = _s(options.get("hostname"))
    cert_cn = _s(subject.get("CN"))
    http_host = _s(http.get("host"))
    hostnames = _strs(rec.get("hostnames"))
    cands = names.candidates(lists, ip, scan_hostname, cert_cn, http_host, hostnames)

    # Shared CDN edge records only survive if they name a customer domain themselves (D24).
    if klass == "cdn" and not cands:
        return None, "cdn_edge_unnamed"

    cert_o = _s(subject.get("O"))
    http_server = _s(http.get("server"))
    http_title = _s(http.get("title"))
    product = _s(rec.get("product"))
    opts = _d(rec.get("opts"))

    row = {
        "ip": ip,
        "port": _int(rec.get("port")),
        "transport": _s(rec.get("transport")),
        "timestamp": _s(rec.get("timestamp")),
        "module": module,
        "shodan_id": _s(shodan.get("id")),
        "crawler": _s(shodan.get("crawler")),
        "banner_hash": _int(rec.get("hash")),
        "org": org or None,
        "isp": isp or None,
        "asn": _s(rec.get("asn")),
        "cloud_provider": cloud_provider,
        "tags": tags,
        "infra_class": klass,
        "appliance": appliance(lists, product or "", http_title or "", http_server or "", cert_o or ""),
        "scan_hostname": scan_hostname,
        "cert_cn": cert_cn,
        "http_host": http_host,
        "hostnames": hostnames,
        "domains": _strs(rec.get("domains")),
        "names": [{"source": s, "domain": d} for s, d in cands],
        "product": product,
        "version": _s(rec.get("version")),
        "cpe23": _strs(rec.get("cpe23")),
        "vulns": _vulns(rec.get("vulns")),
        "opts_vulns": _strs(opts.get("vulns")),
        "has_ssl": bool(ssl),
        "cert_expired": cert.get("expired") is True,
        "cert_expires": _s(cert.get("expires")),
        "cert_issued": _s(cert.get("issued")),
        "cert_self_signed": (bool(subject) and subject == issuer) or "self-signed" in tags,
        "cert_o": cert_o,
        "ssl_versions": [v for v in _strs(ssl.get("versions")) if not v.startswith("-")],
        "has_http": bool(http),
        "has_hsts": _has_hsts(http.get("headers")),
        "http_status": _int(http.get("status")),
        "http_server": http_server,
        "http_title": http_title,
        "http_waf": _s(http.get("waf")),
        "has_docker": isinstance(rec.get("docker"), dict),
        "sample_ip_domain_count": _int(_d(rec.get("_sample")).get("ip_domain_count")),
    }
    return row, "kept"
