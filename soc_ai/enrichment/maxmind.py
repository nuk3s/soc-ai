"""MaxMind GeoLite2 reader — local .mmdb files only.

Wraps `geoip2.database.Reader` so callers don't have to think about
file presence, lookup exceptions, or returning typed Pydantic objects.

Privacy invariant: all lookups are local file reads. No runtime egress.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class AsnInfo:
    number: int
    org: str


@dataclass(frozen=True)
class GeoIpInfo:
    country_iso: str | None
    region: str | None
    city: str | None


@dataclass
class MaxmindReader:
    """Holds open Reader handles for ASN + City .mmdb files (mmap'd)."""

    asn_reader: Any | None = None
    city_reader: Any | None = None

    @classmethod
    def from_dir(cls, data_dir: Path) -> MaxmindReader:
        try:
            import geoip2.database  # noqa: PLC0415
        except ImportError:
            _LOGGER.warning("geoip2 not installed; MaxMind enrichment disabled")
            return cls()
        asn_path = data_dir / "GeoLite2-ASN.mmdb"
        city_path = data_dir / "GeoLite2-City.mmdb"
        asn = None
        city = None
        if asn_path.exists():
            try:
                asn = geoip2.database.Reader(str(asn_path))
            except Exception as e:
                _LOGGER.warning("MaxMind ASN file %s failed to open: %s", asn_path, e)
        if city_path.exists():
            try:
                city = geoip2.database.Reader(str(city_path))
            except Exception as e:
                _LOGGER.warning("MaxMind City file %s failed to open: %s", city_path, e)
        return cls(asn_reader=asn, city_reader=city)

    @property
    def is_available(self) -> bool:
        return self.asn_reader is not None or self.city_reader is not None

    def lookup_asn(self, ip: str) -> AsnInfo | None:
        if self.asn_reader is None:
            return None
        try:
            r = self.asn_reader.asn(ip)
        except Exception:  # geoip2.errors.AddressNotFoundError + ValueError
            return None
        return AsnInfo(
            number=r.autonomous_system_number or 0,
            org=r.autonomous_system_organization or "",
        )

    def lookup_geoip(self, ip: str) -> GeoIpInfo | None:
        if self.city_reader is None:
            return None
        try:
            r = self.city_reader.city(ip)
        except Exception:  # geoip2.errors.AddressNotFoundError + ValueError
            return None
        return GeoIpInfo(
            country_iso=r.country.iso_code,
            region=(r.subdivisions.most_specific.name if r.subdivisions else None),
            city=r.city.name,
        )

    def close(self) -> None:
        if self.asn_reader is not None:
            self.asn_reader.close()
        if self.city_reader is not None:
            self.city_reader.close()


__all__ = ["AsnInfo", "GeoIpInfo", "MaxmindReader"]
