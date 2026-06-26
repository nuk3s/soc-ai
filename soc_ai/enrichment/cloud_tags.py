"""Cloud-provider tagging — vendored prefix JSON, no runtime egress.

Each provider's prefix file is downloaded out-of-band by `soc-ai
blocklists refresh` and stored in `cloud_prefix_data_dir`. We support
the canonical published JSON formats:

- aws.json (Amazon's https://ip-ranges.amazonaws.com/ip-ranges.json shape)
- gcp.json (Google's https://www.gstatic.com/ipranges/cloud.json shape)
- azure.json (Microsoft's https://download.microsoft.com/.../ServiceTags_Public_<date>.json)
- cloudflare.json (Cloudflare's https://www.cloudflare.com/ips-v4 — converted
  to JSON list-of-prefixes by the refresh CLI)

Lookup is a linear scan per provider. Prefix counts are typically a few
thousand combined; if performance becomes a concern, switch to an
interval tree.

Privacy invariant: zero runtime egress. All data is local files.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from pathlib import Path

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class CloudTag:
    provider: str  # "AWS" | "GCP" | "Azure" | "Cloudflare"
    region: str | None = None
    service: str | None = None


@dataclass
class CloudPrefixDB:
    """In-memory CIDR → CloudTag lookup, populated from local JSON files at start."""

    aws_prefixes: list[tuple[IPv4Network, CloudTag]] = field(default_factory=list)
    gcp_prefixes: list[tuple[IPv4Network, CloudTag]] = field(default_factory=list)
    azure_prefixes: list[tuple[IPv4Network, CloudTag]] = field(default_factory=list)
    cloudflare_prefixes: list[tuple[IPv4Network, CloudTag]] = field(default_factory=list)

    @classmethod
    def from_dir(cls, data_dir: Path) -> CloudPrefixDB:
        db = cls()
        for fname, loader in (
            ("aws.json", _load_aws),
            ("gcp.json", _load_gcp),
            ("azure.json", _load_azure),
            ("cloudflare.json", _load_cloudflare),
        ):
            path = data_dir / fname
            if not path.exists():
                continue
            try:
                loader(db, path)
            except Exception as e:
                _LOGGER.warning("cloud-prefix loader for %s failed: %s", fname, e)
        return db

    def lookup_ip(self, ip: str) -> CloudTag | None:
        try:
            addr = ip_address(ip)
        except ValueError:
            return None
        if not isinstance(addr, IPv4Address):
            return None  # IPv6 not yet supported; v1.1
        for prefixes in (
            self.aws_prefixes,
            self.gcp_prefixes,
            self.azure_prefixes,
            self.cloudflare_prefixes,
        ):
            for net, tag in prefixes:
                if addr in net:
                    return tag
        return None


def _load_aws(db: CloudPrefixDB, path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    for entry in data.get("prefixes", []):
        cidr = entry.get("ip_prefix", "")
        try:
            net = ip_network(cidr, strict=False)
        except ValueError:
            continue
        if not isinstance(net, IPv4Network):
            continue
        tag = CloudTag(
            provider="AWS",
            region=entry.get("region"),
            service=entry.get("service"),
        )
        db.aws_prefixes.append((net, tag))


def _load_gcp(db: CloudPrefixDB, path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    for entry in data.get("prefixes", []):
        cidr = entry.get("ipv4Prefix") or entry.get("ipv6Prefix")
        if not cidr:
            continue
        try:
            net = ip_network(cidr, strict=False)
        except ValueError:
            continue
        if not isinstance(net, IPv4Network):
            continue
        tag = CloudTag(provider="GCP", region=entry.get("scope"), service=entry.get("service"))
        db.gcp_prefixes.append((net, tag))


def _load_azure(db: CloudPrefixDB, path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    for entry in data.get("values", []):
        props = entry.get("properties", {})
        for cidr in props.get("addressPrefixes", []):
            try:
                net = ip_network(cidr, strict=False)
            except ValueError:
                continue
            if not isinstance(net, IPv4Network):
                continue
            tag = CloudTag(
                provider="Azure",
                region=props.get("region"),
                service=props.get("systemService") or entry.get("name"),
            )
            db.azure_prefixes.append((net, tag))


def _load_cloudflare(db: CloudPrefixDB, path: Path) -> None:
    """Cloudflare publishes a TXT.

    Refresh job converts to JSON: {"prefixes": ["1.0.0.0/24", ...]}.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    for cidr in data.get("prefixes", []):
        try:
            net = ip_network(cidr, strict=False)
        except ValueError:
            continue
        if not isinstance(net, IPv4Network):
            continue
        db.cloudflare_prefixes.append((net, CloudTag(provider="Cloudflare")))


__all__ = ["CloudPrefixDB", "CloudTag"]
