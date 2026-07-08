"""Synthetic demo dataset shared by the seed script and the mock Elasticsearch.

EVERYTHING here is fictional. IPs come exclusively from the TEST-NET ranges
reserved by RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24); hostnames
belong to a made-up company ("Meridian Freight" — demo.example.com); detections
are Suricata/Zeek-style signature names with synthetic counts. Nothing in this
module may reference a real deployment (no RFC-1918 addresses, no internal
hostnames or domains from any real network).

The story the dataset tells (for the docs screenshots):
  - fin-ws-041 (198.51.100.23) beacons to a fake "Emotet C2" at 203.0.113.147
    → a fully-investigated true_positive with a rich timeline.
  - the security team's authorized scanner (192.0.2.66) trips an Nmap signature
    → false_positive, auto-acknowledged (hidden behind "hide acked").
  - assorted benign noise (curl policy hits, stream retransmissions) plus a
    needs_more_info DNS case and an inconclusive Zeek ATTACK::Discovery notice,
    so every verdict class appears in the UI.
  - a self-signed-TLS group whose only run is a pipeline-failure fallback
    (E1.2 "Pipeline error" chip) and a curl group whose newest re-run errored
    on top of a standing verdict (E2.1 failed-retry hint).
"""

from __future__ import annotations

# --- fictional org -----------------------------------------------------------
ORG_DOMAIN = "demo.example.com"  # RFC 2606 reserved — never resolves
DNS_SERVER = "198.51.100.2"  # "corp DNS/DC"
C2_IP = "203.0.113.147"  # fake Emotet C2 (TEST-NET-3)
SCANNER_IP = "192.0.2.66"  # authorized vuln scanner (TEST-NET-1)

# --- detection groups (drive both the mock ES aggregation and the seeds) ------
# acked=True groups are fully acknowledged → hidden when the UI asks hide_acked.
GROUPS: list[dict] = [
    {
        "rule": "SURICATA STREAM excessive retransmissions",
        "kind": "suricata",
        "dataset": "suricata.alert",
        "sev": "low",
        "count": 27,
        "latest_min": 13,
        "src": "198.51.100.31",
        "dst": "203.0.113.80",
        "dport": 443,
        "host": "eng-ws-112",
        "prefix": "demo-ev-retrans",
        "acked": False,
    },
    {
        "rule": "ET MALWARE Win32/Emotet CnC Activity (POST)",
        "kind": "suricata",
        "dataset": "suricata.alert",
        "sev": "critical",
        "count": 12,
        "latest_min": 8,
        "src": "198.51.100.23",
        "dst": C2_IP,
        "dport": 8080,
        "host": "fin-ws-041",
        "prefix": "demo-ev-emotet",
        "acked": False,
    },
    {
        "rule": "ET POLICY curl User-Agent Outbound",
        "kind": "suricata",
        "dataset": "suricata.alert",
        "sev": "low",
        "count": 9,
        "latest_min": 64,
        "src": "198.51.100.31",
        "dst": "203.0.113.80",
        "dport": 443,
        "host": "eng-ws-112",
        "prefix": "demo-ev-curl",
        "acked": False,
    },
    {
        "rule": "ET DNS Query to a *.top domain - Likely Hostile",
        "kind": "suricata",
        "dataset": "suricata.alert",
        "sev": "medium",
        "count": 4,
        "latest_min": 71,
        "src": "198.51.100.57",
        "dst": DNS_SERVER,
        "dport": 53,
        "host": "hr-ws-023",
        "prefix": "demo-ev-dnstop",
        "acked": False,
    },
    {
        # STANDING verdict for this group is a pipeline-failure fallback (E1.2)
        # → the alerts grid renders the distinct "Pipeline error" chip and the
        # Dashboard excludes it from the Needs-info KPI.
        "rule": "ET INFO Observed Self-Signed TLS Certificate (External)",
        "kind": "suricata",
        "dataset": "suricata.alert",
        "sev": "medium",
        "count": 6,
        "latest_min": 33,
        "src": "198.51.100.66",
        "dst": "203.0.113.29",
        "dport": 8443,
        "host": "mkt-ws-019",
        "prefix": "demo-ev-selfsigned",
        "acked": False,
    },
    {
        # Fully acked by the auto-triage FP verdict → hidden under hide_acked.
        "rule": "ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap NSE)",
        "kind": "suricata",
        "dataset": "suricata.alert",
        "sev": "medium",
        "count": 38,
        "latest_min": 22,
        "src": SCANNER_IP,
        "dst": "198.51.100.14",
        "dport": 443,
        "host": "sec-scan-01",
        "prefix": "demo-ev-nmap",
        "acked": True,
    },
]

# Zeek ATTACK::* notice group (second aggregation, field notice.note).
NOTICE_GROUPS: list[dict] = [
    {
        "rule": "ATTACK::Discovery",
        "kind": "notice",
        "dataset": "zeek.notice",
        "sev": "medium",
        "count": 3,
        "latest_min": 126,
        "src": "198.51.100.44",
        "dst": DNS_SERVER,
        "dport": 445,
        "host": "it-ws-007",
        "prefix": "demo-ev-attackdisc",
        "acked": False,
    },
]

ALL_GROUPS = GROUPS + NOTICE_GROUPS


def event_id(group: dict, n: int) -> str:
    """Deterministic ES _id for the n-th newest event of a group (1 = newest)."""
    return f"{group['prefix']}-{n:03d}"


def group_by_rule(rule: str) -> dict:
    for g in ALL_GROUPS:
        if g["rule"] == rule:
            return g
    raise KeyError(rule)


# ES ids the mock reports as event.acknowledged=true (the auto-acked FP group).
ACKED_EVENT_IDS = {
    event_id(group_by_rule("ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap NSE)"), n)
    for n in range(1, 39)
}

# --- demo login (local throwaway instance only) --------------------------------
DEMO_ADMIN_USER = "admin"
DEMO_ADMIN_PASSWORD = "demo-only-not-a-secret"
