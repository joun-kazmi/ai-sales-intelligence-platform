"""Infrastructure lists and record classification (signals-scoring.md section 1, D24)."""

import hashlib
import re
import tomllib
from dataclasses import dataclass
from functools import cache
from pathlib import Path

INFRA_TOML = Path(__file__).with_name("infra.toml")


@dataclass(frozen=True)
class InfraLists:
    version: str
    noise_modules: frozenset[str]
    cdn_orgs: re.Pattern[str]
    hosting_orgs: re.Pattern[str]
    infra_suffixes: tuple[str, ...]
    appliances: tuple[tuple[str, re.Pattern[str]], ...]


@cache
def load(path: Path = INFRA_TOML) -> InfraLists:
    raw = path.read_bytes()
    cfg = tomllib.loads(raw.decode())
    return InfraLists(
        version=hashlib.sha256(raw).hexdigest()[:12],
        noise_modules=frozenset(cfg["noise_modules"]),
        cdn_orgs=re.compile("|".join(cfg["cdn_orgs"]), re.I),
        hosting_orgs=re.compile("|".join(cfg["hosting_orgs"]), re.I),
        infra_suffixes=tuple(s.lower() for s in cfg["infra_domain_suffixes"]),
        appliances=tuple((k, re.compile(v, re.I)) for k, v in cfg["appliances"].items()),
    )


def infra_class(lists: InfraLists, tags: list[str], org: str, isp: str, cloud_provider: str) -> str | None:
    """'cdn', 'cloud_hosting' or None (customer or ISP network)."""
    owner = f"{org} {isp}"
    if "cdn" in tags or lists.cdn_orgs.search(owner):
        return "cdn"
    if cloud_provider or "cloud" in tags or lists.hosting_orgs.search(owner):
        return "cloud_hosting"
    return None


def is_infra_hostname(lists: InfraLists, hostname: str) -> bool:
    return any(hostname == s or hostname.endswith("." + s) for s in lists.infra_suffixes)


def appliance(lists: InfraLists, *texts: str) -> str | None:
    blob = " ".join(t for t in texts if t).lower()
    if not blob:
        return None
    for vendor, pattern in lists.appliances:
        if pattern.search(blob):
            return vendor
    return None
