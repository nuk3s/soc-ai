"""Local-only enrichment subsystem (synth-first redesign).

Privacy invariant: every source is a local file refreshed out-of-band by
`soc-ai blocklists refresh`. No runtime egress to third parties.

Modules:
    blocklists  - BlocklistDB (vendored public blocklists; abuse.ch + Tor + ...)
    maxmind     - GeoIP/ASN reader wrapping MaxMind .mmdb files
    cloud_tags  - Cloud-provider tagging from vendored prefix JSON
    zeek_parser - Parse embedded Zeek message JSON into typed fields
    refresh     - CLI for refreshing all the above data files
"""

from soc_ai.enrichment.blocklists import BlocklistDB, BlocklistHit

__all__ = ["BlocklistDB", "BlocklistHit"]
