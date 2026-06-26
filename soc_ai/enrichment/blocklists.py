"""BlocklistDB — vendored public IOC blocklists, queried from local files only.

Privacy invariant: NO runtime egress. The data files are downloaded by
the `soc-ai blocklists refresh` CLI subcommand (see refresh.py) and
read at process start. All lookups are pure in-memory dict/set probes.

Sources (initial v1 set):
    urlhaus       - abuse.ch URLhaus (CC0)
    threatfox     - abuse.ch ThreatFox (CC0)
    feodo         - abuse.ch Feodo Tracker (CC0)
    tor           - Tor Project exit-node list (public)
    internal_seed - operator-curated YAML in the deployment repo
    spamhaus_drop - Spamhaus DROP/EDROP (license; default OFF)
"""

from __future__ import annotations

import csv
import json
import logging
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
from pathlib import Path
from urllib.parse import urlparse

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class BlocklistHit:
    """One IOC hit, traceable to its source list + tags."""

    indicator: str
    indicator_type: str  # "ip", "domain", "url", "sha256"
    source: str  # human-readable: "abuse.ch URLhaus"
    tags: tuple[str, ...]
    first_seen: datetime | None = None
    raw_url: str | None = None  # for URLhaus, the original full URL


@dataclass
class BlocklistDB:
    """In-memory IOC reputation lookup, populated from on-disk files at start.

    Construct via `BlocklistDB.from_dir(data_dir, sources=[...])`.
    Lookups are O(1) dict/set probes; safe to call from hot paths.
    """

    ips: dict[str, list[BlocklistHit]] = field(default_factory=dict)
    domains: dict[str, list[BlocklistHit]] = field(default_factory=dict)
    hashes: dict[str, list[BlocklistHit]] = field(default_factory=dict)
    spamhaus_networks: list[tuple[IPv4Network | IPv6Network, str]] = field(default_factory=list)
    loaded_sources: list[str] = field(default_factory=list)
    missing_sources: list[str] = field(default_factory=list)
    file_mtimes: dict[str, datetime] = field(default_factory=dict)

    @classmethod
    def from_dir(
        cls,
        data_dir: Path,
        *,
        sources: list[str],
        spamhaus_license_acknowledged: bool = False,
    ) -> BlocklistDB:
        db = cls()
        for source in sources:
            if source == "spamhaus_drop" and not spamhaus_license_acknowledged:
                _LOGGER.warning(
                    "blocklist source spamhaus_drop is enabled in settings but "
                    "Spamhaus license_acknowledged=False; skipping. Set "
                    "settings.spamhaus_license_acknowledged=True after reading "
                    "the Spamhaus terms (free for non-commercial use only)."
                )
                db.missing_sources.append(source)
                continue
            loader = _LOADERS.get(source)
            if loader is None:
                _LOGGER.warning("unknown blocklist source: %s (skipping)", source)
                db.missing_sources.append(source)
                continue
            try:
                loader(db, data_dir)
                db.loaded_sources.append(source)
            except FileNotFoundError as e:
                _LOGGER.warning("blocklist source %s: file missing (%s)", source, e)
                db.missing_sources.append(source)
        return db

    def lookup_ip(self, ip: str) -> list[BlocklistHit]:
        key = _norm_ip(ip) or ip
        hits = list(self.ips.get(key, []))
        hits.extend(_spamhaus_lookup(self, key))
        return hits

    def lookup_domain(self, domain: str) -> list[BlocklistHit]:
        return self.domains.get(domain.lower(), [])

    def lookup_hash(self, sha256: str) -> list[BlocklistHit]:
        return self.hashes.get(sha256.lower(), [])


def _load_urlhaus(db: BlocklistDB, data_dir: Path) -> None:
    """Parse abuse.ch URLhaus CSV; populate db.ips and db.domains.

    Filters rows where url_status is "offline" — those URLs are no longer
    serving payloads and indexing them produces FP noise on hosts whose
    IPs were briefly abused historically. Online + unknown rows are kept.
    """
    path = data_dir / "urlhaus.csv"
    if not path.exists():
        raise FileNotFoundError(f"urlhaus.csv not found in {data_dir}")
    db.file_mtimes["urlhaus"] = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
    with path.open(encoding="utf-8") as f:
        # URLhaus CSV has comment lines starting with '#'
        rows = (row for row in f if not row.startswith("#"))
        reader = csv.reader(rows, quotechar='"')
        header = next(reader, None)
        if header is None:
            return
        # Header: id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter
        for row in reader:
            if len(row) < 6:
                continue
            url_status = row[3].strip().lower() if len(row) > 3 else ""
            if url_status == "offline":
                continue
            url = row[2].strip()
            tags_str = row[5].strip()
            tags = tuple(t.strip() for t in tags_str.split(",") if t.strip())
            try:
                first_seen = datetime.fromisoformat(row[1].strip().replace(" ", "T"))
            except (ValueError, IndexError):
                first_seen = None
            host = urlparse(url).hostname
            if host is None:
                continue
            # If host is a literal IP, index in ips; else in domains.
            if _is_ip_literal(host):
                norm_host = _norm_ip(host) or host
                ip_hit = BlocklistHit(
                    indicator=norm_host,
                    indicator_type="ip",
                    source="abuse.ch URLhaus",
                    tags=tags,
                    first_seen=first_seen,
                    raw_url=url,
                )
                db.ips.setdefault(norm_host, []).append(ip_hit)
            else:
                domain_hit = BlocklistHit(
                    indicator=host,
                    indicator_type="domain",
                    source="abuse.ch URLhaus",
                    tags=tags,
                    first_seen=first_seen,
                    raw_url=url,
                )
                db.domains.setdefault(host.lower(), []).append(domain_hit)


def _norm_ip(s: str) -> str | None:
    """Normalise an IP literal to its canonical (compressed) form.

    Python ≥ 3.9 rejects zero-padded octets in :func:`ipaddress.ip_address`
    (e.g. ``"192.168.001.005"`` raises ``ValueError``), so we pre-strip per-octet
    leading zeros for IPv4-looking strings before calling the stdlib.  The guard
    ``all(p.isdecimal() and p.isascii() for p in parts)`` ensures we only touch
    strings that look like bare ASCII dotted-decimals and leave everything else
    (hostnames, CIDRs, IPv6 with zone ids, non-ASCII digits) to the stdlib.
    Non-IP strings return ``None``.

    This function is *total* — it never raises.
    """
    stripped = s.strip()
    # IPv4-looking: four dot-separated tokens, each all-digits → strip leading zeros.
    parts = stripped.split(".")
    if len(parts) == 4 and all(p.isdecimal() and p.isascii() for p in parts):
        with suppress(ValueError):
            stripped = ".".join(str(int(p)) for p in parts)
    try:
        return ip_address(stripped).compressed
    except ValueError:
        return None


def _is_ip_literal(s: str) -> bool:
    return _norm_ip(s) is not None


def _strip_port(ioc_value: str) -> str:
    """Strip a port suffix from a ThreatFox `ip:port` value.

    Handles three shapes:
        '1.2.3.4:443'      -> '1.2.3.4'
        '[2001:db8::1]:443' -> '2001:db8::1'
        '2001:db8::1'      -> '2001:db8::1' (bare IPv6, no port)
    Returns the validated IP literal or '' if neither a v4 nor v6 address.
    """
    raw = ioc_value
    # Bracketed IPv6 with explicit port
    if raw.startswith("["):
        end = raw.find("]")
        if end > 0:
            raw = raw[1:end]
    # IPv4-with-port (single colon, dotted)
    elif raw.count(":") == 1 and "." in raw:
        raw = raw.split(":", 1)[0]
    # else: bare v4 or bare v6 — pass through as-is
    return raw if _is_ip_literal(raw) else ""


def _load_threatfox(db: BlocklistDB, data_dir: Path) -> None:
    """Parse abuse.ch ThreatFox JSON; populate db.ips/domains/hashes."""
    path = data_dir / "threatfox.json"
    if not path.exists():
        raise FileNotFoundError(f"threatfox.json not found in {data_dir}")
    db.file_mtimes["threatfox"] = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    # ThreatFox dump shape: { "<id>": [ { "ioc_value": ..., "ioc_type": ... } ] }
    for entries in data.values():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            ioc_value = entry.get("ioc_value", "").strip()
            ioc_type = entry.get("ioc_type", "").strip()
            tags_str = entry.get("tags", "") or ""
            tags = tuple(t.strip() for t in tags_str.split(",") if t.strip())
            try:
                first_seen = datetime.fromisoformat(entry.get("first_seen", "").replace(" ", "T"))
            except (ValueError, AttributeError):
                first_seen = None
            if not ioc_value:
                continue
            # ioc_value for "ip:port" is "1.2.3.4:443"; strip the port.
            if ioc_type.startswith("ip"):
                ip = _strip_port(ioc_value)
                if not ip:
                    continue
                ip = _norm_ip(ip) or ip
                hit = BlocklistHit(
                    indicator=ip,
                    indicator_type="ip",
                    source="abuse.ch ThreatFox",
                    tags=tags,
                    first_seen=first_seen,
                )
                db.ips.setdefault(ip, []).append(hit)
            elif ioc_type == "domain":
                hit = BlocklistHit(
                    indicator=ioc_value,
                    indicator_type="domain",
                    source="abuse.ch ThreatFox",
                    tags=tags,
                    first_seen=first_seen,
                )
                db.domains.setdefault(ioc_value.lower(), []).append(hit)
            elif ioc_type.endswith("sha256_hash"):
                h = ioc_value.lower()
                hit = BlocklistHit(
                    indicator=h,
                    indicator_type="sha256",
                    source="abuse.ch ThreatFox",
                    tags=tags,
                    first_seen=first_seen,
                )
                db.hashes.setdefault(h, []).append(hit)


def _load_feodo(db: BlocklistDB, data_dir: Path) -> None:
    """Parse abuse.ch Feodo Tracker IP blocklist CSV; populate db.ips."""
    path = data_dir / "feodo.csv"
    if not path.exists():
        raise FileNotFoundError(f"feodo.csv not found in {data_dir}")
    db.file_mtimes["feodo"] = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
    with path.open(encoding="utf-8") as f:
        rows = (row for row in f if not row.startswith("#") and row.strip())
        reader = csv.reader(rows)
        header_or_first = next(reader, None)
        if header_or_first is None:
            return
        # Header has 'first_seen_utc'; if so skip; else treat as first row.
        if header_or_first and "first_seen_utc" in header_or_first[0].lower():
            pass
        else:
            _process_feodo_row(db, header_or_first)
        for row in reader:
            _process_feodo_row(db, row)


def _process_feodo_row(db: BlocklistDB, row: list[str]) -> None:
    if len(row) < 6:
        return
    try:
        first_seen = datetime.fromisoformat(row[0].strip().replace(" ", "T"))
    except (ValueError, IndexError):
        first_seen = None
    raw_ip = row[1].strip()
    if not raw_ip:
        return
    ip = _norm_ip(raw_ip) or raw_ip
    malware = row[5].strip()
    tags = ("c2", malware.lower()) if malware else ("c2",)
    hit = BlocklistHit(
        indicator=ip,
        indicator_type="ip",
        source="abuse.ch Feodo Tracker",
        tags=tags,
        first_seen=first_seen,
    )
    db.ips.setdefault(ip, []).append(hit)


def _load_tor(db: BlocklistDB, data_dir: Path) -> None:
    """Parse Tor exit-node list (one IP per line, # comments); populate db.ips."""
    path = data_dir / "tor_exits.txt"
    if not path.exists():
        raise FileNotFoundError(f"tor_exits.txt not found in {data_dir}")
    db.file_mtimes["tor"] = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
    with path.open(encoding="utf-8") as f:
        for line in f:
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue
            ip = _norm_ip(raw)
            if ip is None:
                _LOGGER.debug("tor: skipping non-IP line %r", raw)
                continue
            hit = BlocklistHit(
                indicator=ip,
                indicator_type="ip",
                source="Tor Project exit list",
                tags=("tor_exit",),
            )
            db.ips.setdefault(ip, []).append(hit)


def _load_internal_seed(db: BlocklistDB, data_dir: Path) -> None:
    """Parse the operator-curated YAML seed list."""
    import yaml  # noqa: PLC0415 — lazy: only required when this loader runs

    path = data_dir / "internal_seed.yaml"
    if not path.exists():
        raise FileNotFoundError(f"internal_seed.yaml not found in {data_dir}")
    db.file_mtimes["internal_seed"] = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
    with path.open(encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    for attr, ind_type in (("ips", "ip"), ("domains", "domain"), ("hashes", "sha256")):
        for entry in data.get(attr) or []:
            indicator = entry.get("indicator", "").strip()
            raw_tags = entry.get("tags") or []
            tags = tuple(raw_tags) if isinstance(raw_tags, list) else (str(raw_tags),)
            if not indicator:
                continue
            hit = BlocklistHit(
                indicator=indicator,
                indicator_type=ind_type,
                source="internal_seed",
                tags=tags,
            )
            target = getattr(db, attr)
            key_norm = (_norm_ip(indicator) or indicator) if ind_type == "ip" else indicator.lower()
            target.setdefault(key_norm, []).append(hit)


def _load_spamhaus_drop(db: BlocklistDB, data_dir: Path) -> None:
    """Parse Spamhaus DROP/EDROP TXT format; populate db.spamhaus_networks.

    Spamhaus is CIDR-based; we keep the CIDR list rather than expanding to
    per-IP entries (CIDRs can be /14 = 250K IPs). CIDRs are pre-parsed at
    load time so per-lookup cost is just CIDR-membership tests, not string
    parsing.
    """
    path = data_dir / "spamhaus_drop.txt"
    if not path.exists():
        raise FileNotFoundError(f"spamhaus_drop.txt not found in {data_dir}")
    db.file_mtimes["spamhaus_drop"] = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
    with path.open(encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith(";") or line.startswith("#"):
                continue
            # Format: "192.0.2.0/24 ; SBL12345"
            parts = line.split(";", 1)
            cidr_str = parts[0].strip()
            sbl = parts[1].strip() if len(parts) > 1 else ""
            try:
                net = ip_network(cidr_str, strict=False)
            except ValueError:
                continue
            db.spamhaus_networks.append((net, sbl))


def _spamhaus_lookup(db: BlocklistDB, ip: str) -> list[BlocklistHit]:
    """Resolve a Spamhaus CIDR membership lookup to BlocklistHit list."""
    if not db.spamhaus_networks:
        return []
    try:
        addr = ip_address(ip)
    except ValueError:
        return []
    hits: list[BlocklistHit] = []
    for net, sbl in db.spamhaus_networks:
        if addr in net:
            hits.append(
                BlocklistHit(
                    indicator=ip,
                    indicator_type="ip",
                    source="Spamhaus DROP",
                    tags=(sbl,) if sbl else (),
                )
            )
    return hits


_LOADERS: dict[str, Callable[[BlocklistDB, Path], None]] = {
    "urlhaus": _load_urlhaus,
    "threatfox": _load_threatfox,
    "feodo": _load_feodo,
    "tor": _load_tor,
    "internal_seed": _load_internal_seed,
    "spamhaus_drop": _load_spamhaus_drop,
}


__all__ = ["BlocklistDB", "BlocklistHit"]
