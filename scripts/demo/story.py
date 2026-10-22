"""The demo story: one small estate, one attack chain, and the noise around it.

This module is data. ``build_story.py`` reads it and writes
``soc_ai/demo/fixtures.json``. Every name and address here is synthetic: the
estate sits in 10.20.0.0/16 (RFC 1918), the outside world uses the TEST-NET
ranges of RFC 5737 or public addresses that the recorded runs already name,
and the domain is the RFC 2606 name ``demo.example.com``.

The recorded runs in ``recorded_runs.json`` came from a test grid and were
sanitized at capture: every internal address became a label such as
``IP_22``. The story gives each label one machine of the estate, so the
recorded investigations, the hosts, the leads and the alerts name the same
machines.

The story, oldest first (times are hours before the seed instant):

* 48 h. The DCSync analytic fires on ``it-admin-07``. The catalog trail
  (``soc_ai/demo/catalog_trail.py``) records it.
* 30 h. ws-sales-02 downloads an executable dressed as an image.
* 28 h to 22 h. The sensor is down. The grid holds no data. A profile
  analytic fires on five quiet hosts, and soc-ai holds it in shadow.
* 20 h. ws-sales-04 sends Emotet check-ins. A lead forms, its hunt finds two
  threats, and both findings reuse the Emotet investigation.
* 15 h to 14 h. jump01 asks for an RC4 ticket as jdoe and runs PsExec
  against fs01. The alert goes to a case. A second alert on the same flow
  reads as a false positive, and the console shows the disagreement.
* 12 h. bkp01 uploads 4.2 GB to cloud storage. soc-ai needs more
  information. The analyst answers, and the follow-up run calls it a threat.
* 8 h to 2 h. Benign noise: a certificate download, an IP lookup, the
  vulnerability scanner, Bonjour discovery. One run fails in the pipeline.
* The last hour. A Quasar RAT check-in and a .click lookup wait for a
  verdict. A lead on ws-eng-03 has a hunt in progress.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

# The instant every timestamp in the fixture file is written against. The app
# and the mock move it to the seed instant at startup, so it never ages.
ANCHOR = datetime(2026, 10, 22, 12, 0, 0)

ORG_DOMAIN = "demo.example.com"
SENSOR = "so-sensor-1"


def ago(*, days: float = 0, hours: float = 0, minutes: float = 0, seconds: float = 0) -> datetime:
    """The instant this long before the anchor (naive UTC)."""
    return ANCHOR - timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)


def iso(dt: datetime) -> str:
    """A store timestamp: naive UTC, whole seconds."""
    return dt.replace(microsecond=0).isoformat()


def es_time(dt: datetime) -> str:
    """A grid timestamp, the way Elasticsearch writes ``@timestamp``."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


# --- the estate ----------------------------------------------------------------


@dataclass(frozen=True)
class Machine:
    """One machine of the estate, with what the sweep and the grid know about it."""

    name: str | None
    ip: str
    kind: str  # server | workstation | iot
    os_family: str | None = None
    os_detail: str | None = None
    role: str | None = None
    role_strength: str = "strong"  # strong | weak
    role_evidence: str = ""
    declared: dict[str, str] = field(default_factory=dict)
    agent: bool = True
    dhcp: bool = False
    dns_only: bool = False  # named by DNS answers alone
    mac: int | None = None
    services: tuple[tuple[str, int, int], ...] = ()
    events_per_day: int = 4_000
    first_days: float = 180.0
    last_minutes: float = 2.0
    pattern: str = "office"  # office | server | always
    owner: str | None = None  # the account that logs on to a workstation


_WS_EVIDENCE = (
    "the agent on this machine reports Windows 11, a client operating system. "
    "The answered ports agree (from hostlog)"
)
_SRV_EVIDENCE = "the agent reports a server operating system and the machine serves {ports}"

MACHINES: tuple[Machine, ...] = (
    Machine(
        "dc01",
        "10.20.0.10",
        "server",
        "windows",
        "Windows Server 2022",
        "domain_controller",
        role_evidence=(
            "responds on tcp/88, tcp/389, tcp/445 and udp/53 to every workstation of the estate"
        ),
        declared={"role": "domain_controller", "criticality": "critical"},
        mac=0x10,
        services=(
            ("udp", 53, 61_204),
            ("tcp", 88, 18_330),
            ("tcp", 389, 9_812),
            ("tcp", 445, 4_120),
        ),
        events_per_day=52_000,
        first_days=400,
        pattern="server",
    ),
    Machine(
        "dc02",
        "10.20.0.11",
        "server",
        "windows",
        "Windows Server 2022",
        "domain_controller",
        role_evidence="responds on tcp/88, tcp/389 and udp/53. The second resolver of the estate",
        mac=0x11,
        services=(("udp", 53, 30_114), ("tcp", 88, 9_402), ("tcp", 389, 4_877)),
        events_per_day=31_000,
        first_days=400,
        pattern="server",
    ),
    Machine(
        "fs01",
        "10.20.0.20",
        "server",
        "windows",
        "Windows Server 2019",
        "server",
        role_evidence=_SRV_EVIDENCE.format(ports="tcp/445 to 14 workstations"),
        declared={"role": "server", "criticality": "high"},
        mac=0x20,
        services=(("tcp", 445, 21_552), ("tcp", 135, 1_204)),
        events_per_day=18_000,
        first_days=380,
        pattern="office",
    ),
    Machine(
        "app01",
        "10.20.0.21",
        "server",
        "windows",
        "Windows Server 2019",
        "server",
        role_evidence=_SRV_EVIDENCE.format(ports="tcp/443 and tcp/1433"),
        mac=0x21,
        services=(("tcp", 443, 8_204), ("tcp", 1433, 3_391)),
        events_per_day=9_000,
        first_days=300,
        pattern="office",
    ),
    Machine(
        "bkp01",
        "10.20.0.25",
        "server",
        "linux",
        "Ubuntu 22.04",
        "server",
        role_evidence=_SRV_EVIDENCE.format(ports="tcp/22 and tcp/873"),
        mac=0x25,
        services=(("tcp", 22, 1_890), ("tcp", 873, 1_204)),
        events_per_day=6_000,
        first_days=290,
        pattern="server",
    ),
    Machine(
        "web01",
        "10.20.0.30",
        "server",
        "linux",
        "Ubuntu 22.04",
        "server",
        role_evidence=_SRV_EVIDENCE.format(ports="tcp/443 to the office"),
        mac=0x30,
        services=(("tcp", 443, 12_870), ("tcp", 22, 310)),
        events_per_day=14_000,
        first_days=350,
        pattern="office",
    ),
    Machine(
        "build01",
        "10.20.0.35",
        "server",
        "linux",
        "Ubuntu 22.04",
        "server",
        role_evidence=_SRV_EVIDENCE.format(ports="tcp/22 and tcp/8080"),
        mac=0x35,
        services=(("tcp", 22, 920), ("tcp", 8080, 2_310)),
        events_per_day=5_000,
        first_days=210,
        pattern="always",
    ),
    Machine(
        "scan01",
        "10.20.0.40",
        "server",
        "linux",
        "Rocky Linux 9",
        "server",
        role_evidence="opens connections to every address of the estate on many ports",
        declared={"role": "security_appliance"},
        mac=0x40,
        services=(("tcp", 8834, 140),),
        events_per_day=3_000,
        first_days=330,
        pattern="always",
    ),
    Machine(
        "jump01",
        "10.20.0.50",
        "server",
        "windows",
        "Windows Server 2022",
        "server",
        role_evidence=_SRV_EVIDENCE.format(ports="tcp/3389 to the IT team"),
        mac=0x50,
        services=(("tcp", 3389, 640),),
        events_per_day=2_500,
        first_days=260,
        pattern="office",
    ),
    Machine(
        "vpn01",
        "10.20.0.60",
        "server",
        "linux",
        "Ubuntu 22.04",
        "server",
        role_evidence=_SRV_EVIDENCE.format(ports="tcp/22 and udp/1194 to the internet"),
        mac=0x60,
        services=(("udp", 1194, 7_420), ("tcp", 22, 2_115)),
        events_per_day=8_000,
        first_days=320,
        pattern="always",
    ),
    Machine(
        None,
        "10.20.0.5",
        "server",
        role="hypervisor",
        role_evidence="serves tcp/443 and tcp/902, the ports of a hypervisor console",
        agent=False,
        dns_only=True,
        services=(("tcp", 443, 410), ("tcp", 902, 380)),
        events_per_day=900,
        first_days=400,
        pattern="always",
    ),
    Machine(
        "ws-it-02",
        "10.20.10.12",
        "workstation",
        "windows",
        "Windows 11",
        "workstation",
        role_evidence=_WS_EVIDENCE,
        mac=0x82,
        owner="it-admin-07",
    ),
    Machine(
        "ws-ops-01",
        "10.20.10.17",
        "workstation",
        "windows",
        "Windows 11",
        "workstation",
        role_evidence=_WS_EVIDENCE,
        mac=0x87,
        owner="l.nguyen",
    ),
    Machine(
        "ws-mkt-01",
        "10.20.10.21",
        "workstation",
        "windows",
        "Windows 11",
        "workstation",
        role_evidence=_WS_EVIDENCE,
        mac=0x91,
        owner="s.okafor",
    ),
    Machine(
        "ws-fin-02",
        "10.20.10.22",
        "workstation",
        "windows",
        "Windows 11",
        "workstation",
        role_evidence=_WS_EVIDENCE,
        mac=0x92,
        owner="p.lindqvist",
    ),
    Machine(
        "ws-sales-04",
        "10.20.10.24",
        "workstation",
        "windows",
        "Windows 11",
        "workstation",
        role_evidence=_WS_EVIDENCE,
        mac=0x94,
        owner="m.ortiz",
    ),
    Machine(
        "ws-sales-02",
        "10.20.10.26",
        "workstation",
        "windows",
        "Windows 11",
        "workstation",
        role_evidence=_WS_EVIDENCE,
        mac=0x96,
        owner="a.kim",
    ),
    Machine(
        "ws-hr-01",
        "10.20.10.31",
        "workstation",
        "windows",
        "Windows 11",
        "workstation",
        role_evidence=_WS_EVIDENCE,
        mac=0xA1,
        owner="d.haddad",
    ),
    Machine(
        "ws-eng-03",
        "10.20.10.33",
        "workstation",
        "windows",
        "Windows 11",
        "workstation",
        role_evidence=_WS_EVIDENCE,
        mac=0xA3,
        owner="t.brennan",
    ),
    Machine(
        "ws-eng-05",
        "10.20.10.35",
        "workstation",
        "windows",
        "Windows 11",
        "workstation",
        role_evidence=_WS_EVIDENCE,
        mac=0xA5,
        owner="k.sato",
    ),
    Machine(
        "mac-design-01",
        "10.20.10.40",
        "workstation",
        "apple",
        "macOS 14",
        "workstation",
        role_evidence=(
            "the agent on this machine reports macOS 14, a client operating system (from hostlog)"
        ),
        mac=0xB0,
        owner="j.chen",
    ),
    Machine(
        "prn-02",
        "10.20.30.12",
        "iot",
        role="iot",
        role_strength="weak",
        role_evidence="serves tcp/9100 and tcp/631 and runs no agent. A printer, most likely",
        agent=False,
        dhcp=True,
        mac=0xC2,
        services=(("tcp", 9100, 220), ("tcp", 631, 61)),
        events_per_day=600,
        first_days=240,
        pattern="office",
    ),
    Machine(
        "cam-lobby",
        "10.20.30.20",
        "iot",
        agent=False,
        dhcp=True,
        mac=0xC8,
        services=(("tcp", 554, 1_440),),
        events_per_day=1_400,
        first_days=200,
        pattern="always",
    ),
    Machine(
        None,
        "10.20.30.77",
        "iot",
        agent=False,
        events_per_day=120,
        first_days=3,
        last_minutes=48,
        pattern="always",
    ),
)

BY_NAME: dict[str, Machine] = {m.name: m for m in MACHINES if m.name}
BY_IP: dict[str, Machine] = {m.ip: m for m in MACHINES}


def ip_of(name: str) -> str:
    return BY_NAME[name].ip


# --- the recorded runs' labels ------------------------------------------------

# One machine per label. Two labels share a machine only where no recorded
# record names both (dc01 is IP_02 in the DNS runs and IP_23 in the
# lateral-movement runs), so no sentence reads "dc01 and dc01".
IP_LABELS: dict[str, str] = {
    "IP_01": ip_of("ws-mkt-01"),
    "IP_02": ip_of("dc01"),
    # The top peers of ws-mkt-01 in its host summary.
    "IP_03": ip_of("dc02"),
    "IP_04": ip_of("fs01"),
    "IP_05": ip_of("app01"),
    "IP_06": ip_of("web01"),
    "IP_07": ip_of("prn-02"),
    "IP_08": ip_of("ws-fin-02"),
    "IP_09": ip_of("ws-sales-04"),
    "IP_10": ip_of("ws-sales-02"),
    "IP_11": ip_of("mac-design-01"),
    "IP_12": ip_of("ws-hr-01"),
    "IP_13": ip_of("bkp01"),
    "IP_14": ip_of("ws-fin-02"),
    "IP_15": ip_of("scan01"),
    "IP_16": ip_of("web01"),
    "IP_17": ip_of("ws-it-02"),
    "IP_18": ip_of("app01"),
    "IP_19": ip_of("ws-sales-04"),
    "IP_20": ip_of("ws-sales-02"),
    "IP_21": ip_of("vpn01"),
    "IP_22": ip_of("jump01"),
    "IP_23": ip_of("dc01"),
    "IP_24": ip_of("fs01"),
    "IP_25": ip_of("bkp01"),
    "IP_26": ip_of("ws-ops-01"),
    "IP_27": ip_of("ws-hr-01"),
    "IP_28": ip_of("dc02"),
    # "Both IPs are internal (IP_29/24)": the server network.
    "IP_29": "10.20.0.0",
    "IP_30": ip_of("mac-design-01"),
    "IP_31": ip_of("ws-eng-03"),
    "IP_41": ip_of("ws-eng-05"),
    # The Cobalt Strike team server. The recorded replay of the same alert
    # names it in the clear, so the label takes that address.
    "IP_42": "193.29.13.44",
}

# The sanitizer replaced a tool flag with a label in a few citations
# ("tool t_enrich_ip:HOST_02=true"). The flag said the address is internal.
HOST_FLAG_PATTERN = r"t_enrich_ip:HOST_\d+=true"
HOST_FLAG_TEXT = "t_enrich_ip:internal=true"

HOST_LABELS: dict[str, str] = {
    # A name in the top DNS answers of ws-mkt-01.
    "HOST_01": f"intranet.{ORG_DOMAIN}",
    # The hosts of the SSH hunt.
    "HOST_02": "web01",
    "HOST_05": "bkp01",
    "HOST_11": "build01",
    # The Bonjour discovery query and its domain.
    "HOST_03": f"lb._dns-sd._udp.{ORG_DOMAIN}",
    "HOST_04": ORG_DOMAIN,
    # Only in the tool flag above. Kept so a missed flag still reads clean.
    "HOST_06": "internal",
    # The update poller of the DNS hunt: the printer.
    "HOST_07": "prn-02",
}

# --- accounts -------------------------------------------------------------------

# The admin account the attacker holds. The catalog trail fires DCSync on it.
ADMIN_ACCOUNT = "it-admin-07"
# The account the recorded kerberoasting alert names.
KERBEROAST_ACCOUNT = "jdoe"
BACKUP_ACCOUNT = "svc-backup"
ANALYSTS = ("j.chen", "r.patel")

# --- outside addresses ------------------------------------------------------------

# Public addresses the recorded runs already name.
EMOTET_C2 = "162.243.103.246"
DROPPER_HOST = "193.42.39.117"
R2_STORAGE = "162.159.140.42"
QUASAR_C2 = "185.45.43.21"
# Documentation addresses for what the story adds.
FIRMWARE_CDN = "203.0.113.80"
PYPI_MIRROR = "198.51.100.120"
CLOUD_SYNC = "198.51.100.44"
# The contracted backup provider of bkp01.
BACKUP_PROVIDER = "198.51.100.150"
# The destination of the alerts the newest backtest replayed.
BACKTEST_PEER = "198.51.100.77"

# MAC addresses come from the RFC 7042 documentation block.
DOC_MAC = "00:00:5e:00:53:{:02x}"


def mac_of(m: Machine) -> str | None:
    return DOC_MAC.format(m.mac) if m.mac is not None else None


# --- the grid gap -------------------------------------------------------------------

GAP_START = ago(hours=28)
GAP_END = ago(hours=22)

# --- every address the story writes, for the leak gate's allowlist ----------------


def story_addresses() -> set[str]:
    out = {m.ip for m in MACHINES}
    out.update(IP_LABELS.values())
    out.update({FIRMWARE_CDN, PYPI_MIRROR, CLOUD_SYNC, BACKUP_PROVIDER, BACKTEST_PEER})
    out.update(mac for m in MACHINES if (mac := mac_of(m)))
    return out


def story_names() -> set[str]:
    out = {m.name for m in MACHINES if m.name}
    out.update(f"{n}.{ORG_DOMAIN}" for n in list(out))
    out.update(HOST_LABELS.values())
    out.update(m.owner for m in MACHINES if m.owner)
    out.update({ADMIN_ACCOUNT, KERBEROAST_ACCOUNT, BACKUP_ACCOUNT, *ANALYSTS, ORG_DOMAIN})
    return out
