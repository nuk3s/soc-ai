"""Allow-known-safe egress backstop for the Oracle tool-result path.

This is the load-bearing hardening that converts the Oracle egress from a
BLOCKLIST (block the identifier shapes/fields we thought of) to an ALLOWLIST
(pass only values that are provably not an internal identifier, mask the rest),
so the boundary is complete by construction rather than by enumeration.

WHY IT EXISTS
-------------
The wire residue gate (:func:`~soc_ai.oracle.sanitize.unsafe_residue`) cannot
catch a shapeless bare internal name — ``filesrv``, a NetBIOS ``CORP``, ``PDC01``
— by shape: none has a regex form distinguishing it from an ordinary word. The
gate can only catch such a name through its ``known_values`` arm, which is
populated by the field-aware harvest in :mod:`soc_ai.oracle.redact`. The harvest
is keyed on field PATHS, so the true boundary is "did the harvest recognise the
field this tool put the identifier in?" — a blocklist over an open set of fields,
never provably complete (five prior commits each closed one missed category, and
a sixth is always possible; see ``docs/dev/design/2026-08-27-oracle-tool-use.md``
§"The wire gate is a blocklist").

WHAT THIS DOES
--------------
Runs as a FINAL pass over an oracle tool result AFTER
:func:`~soc_ai.oracle.redact.sanitize_case` has tokenised every internal
identifier it recognises. For each residual STRING scalar, it applies an
allow-known-safe policy:

- ALLOW if the value is provably not an internal identifier — a minted opaque
  label (``HOST_01``), a number, a boolean/null token, a timestamp/date, an IP
  or CIDR, a file hash, a CVE / ATT&CK id, a public email/URL/FQDN, or a
  composite of those plus non-word punctuation (see
  :func:`_scalar_is_provably_safe`).
- ALLOW if the value sits on a field in an explicit allowlist of known-safe
  fields — categorical/enumerated taxonomy (event.category, log.level,
  network.protocol …), opaque machine ids (community_id, agent.id …), or a
  small set of generic enum leaf keys (severity, outcome, port …). Enumerated
  and justified in the ``_SAFE_*`` sets below.
- Otherwise MASK it with :data:`MASK_PLACEHOLDER` — because a free-form string on
  a field neither the harvest nor this allowlist recognises is exactly where a
  bare internal name hides.

SCOPE. This is bound to the ORACLE tool-result sanitize path
(:meth:`soc_ai.oracle.client.OracleToolGuard.sanitize_obj`) — mirroring how the
prior re-key and ``_WINLOG_*`` fixes were contained. It deliberately does NOT
touch the shared analyst/investigator sanitization (plain ``sanitize_obj`` on the
:class:`~soc_ai.agent.egress_guard.EgressGuard`), whose utility budget is
different and whose emitting model is the operator's own.

UTILITY COST. Masking a free-form string the Oracle might have reasoned over (a
rule name, a free-text note, an echoed query) is the deliberate, quantified cost
of completeness. Dict KEYS are never masked (they are schema field names, and
``sanitize_case`` already tokenises any identifier that appears in one); only
scalar VALUES at leaves are considered. The mask count is returned so the owner
can measure the cost.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from soc_ai.oracle.redact import _path_suffixes

MASK_PLACEHOLDER = "<redacted:unclassified>"
"""Stable, value-free placeholder a masked scalar is replaced with. Stable so it
never itself looks like an identifier and never varies the outbound bytes."""


# ---------------------------------------------------------------------------
# The safe-field allowlist — fields whose free-form string values are, by the
# field's semantics, NOT internal host/user/domain identifiers. Matched against
# every dotted-path SUFFIX (so a nested ``_source.event.category`` matches
# ``event.category``) and, for the generic leaves, against the last segment.
# Kept lowercase; the path is lowercased before matching (winlog ``_source``
# keys are mixed-case).
# ---------------------------------------------------------------------------

# Categorical / enumerated ECS fields — closed, public value spaces (the event
# taxonomy, log level, protocol/method/version names, OS descriptors). An
# internal hostname/username is not a value these fields legitimately take.
_SAFE_ENUM_FIELDS: frozenset[str] = frozenset(
    {
        "event.category",
        "event.type",
        "event.kind",
        "event.action",
        "event.outcome",
        "event.dataset",
        "event.module",
        "event.provider",
        "event.severity",
        "event.timezone",
        "log.level",
        "log.logger",
        "log.syslog.severity.name",
        "log.syslog.facility.name",
        "network.protocol",
        "network.transport",
        "network.direction",
        "network.type",
        "network.application",
        "http.request.method",
        "http.version",
        "tls.version",
        "tls.version_protocol",
        "tls.cipher",
        "tls.curve",
        "observer.type",
        "observer.vendor",
        "observer.product",
        "os.family",
        "os.platform",
        "os.type",
        "os.name",
        "os.full",
        "os.kernel",
        "os.version",
        "rule.category",
        "rule.ruleset",
    }
)

# Opaque machine identifiers — random / uuid / hash-ish ids, never a
# human-assigned internal NAME. UUIDs and pure-hex ids already pass the value
# shape check; base64-ish ES doc ids do not, so allowlist the id-bearing fields
# so a legitimate ``_id`` / ``community_id`` is not masked.
_SAFE_ID_FIELDS: frozenset[str] = frozenset(
    {
        "_id",
        "id",
        "event.id",
        "event.code",
        "event.sequence",
        "agent.id",
        "agent.ephemeral_id",
        "agent.type",
        "agent.version",
        "community_id",
        "network.community_id",
        "rule.id",
        "rule.uuid",
        "rule.version",
        "trace.id",
        "transaction.id",
        "flow.id",
        "process.entity_id",
        "process.parent.entity_id",
    }
)

# The initial-payload app envelope — the fields
# :func:`soc_ai.oracle.client._assemble_case_dict` mints around an adjudication.
# These are the SOC app's OWN framing, NOT raw grid data: the local
# verdict/summary/citations the Oracle is asked to adjudicate, the loop
# transcript and the investigator's evidence bullets (both already tokenised by
# ``sanitize_case`` — analyst English over opaque labels, not identifiers), and
# each tool result's tool NAME (an app-controlled constant like
# ``t_query_events_oql``). Their values are app constants or already-sanitized
# prose, so they are known-safe BY FIELD. Without this exemption the initial-
# payload backstop would mask the entire local narrative the Oracle exists to
# adjudicate — and these same prose fields already egress on the shipped single-
# shot path under only the sanitize + wire-residue gate, so exempting them keeps
# the tool path at parity there while the backstop still covers the grid-data
# portions (``alert_summary`` + ``loop_tool_results.result``). Matched as dotted
# suffixes (``loop_tool_results.tool`` is 2-segment so a nested ``x.y.tool`` on a
# real tool result is NOT exempted).
_SAFE_ORACLE_ENVELOPE_FIELDS: frozenset[str] = frozenset(
    {
        "local_verdict",
        "local_summary",
        "local_citations",
        "loop_evidence",
        "loop_evidence_bullets",
        "loop_tool_results.tool",
    }
)

_SAFE_DOTTED_FIELDS: frozenset[str] = (
    _SAFE_ENUM_FIELDS | _SAFE_ID_FIELDS | _SAFE_ORACLE_ENVELOPE_FIELDS
)

# Generic bare-leaf keys whose values are categorical / enumerated / numeric
# regardless of the envelope they arrive in (a vendor tool result rarely uses
# ECS paths). These are the SOFTEST allowlist entries — an internal name in a
# ``status`` / ``type`` value would be bizarre but is not structurally
# impossible; they are included for utility and called out in the release notes.
# Deliberately EXCLUDES the ``result`` wrapper key (a bare free-form string tool
# result is wrapped under it — see the guard) so such a result is still masked.
_SAFE_LEAF_KEYS: frozenset[str] = frozenset(
    {
        "severity",
        "severity_label",
        "level",
        "priority",
        "outcome",
        "direction",
        "transport",
        "protocol",
        "disposition",
        "action",
        "status",
        "state",
        "category",
        "kind",
        "type",
        "decision",
        "verdict",
        "method",
        "encoding",
        "encoding_used",  # t_decode_payload: base64 | hex | text
        "protocol_guess",  # t_decode_payload L7 sniff: tls-client-hello | http-request | …
        "count",
        "doc_count",
        "total",
        "port",
        "src_port",
        "dst_port",
        "source_port",
        "destination_port",
        # SoAlert routing/enum leaves. The typed alert
        # (:class:`soc_ai.so_client.models.SoAlert`) flattens ECS ``event.*`` to
        # ``event_*`` (underscore), so the dotted ``event.category`` allowlist
        # above does not match ``alert_summary.alert.event_category``; these are
        # the flattened aliases plus Suricata's rule-class and two Zeek
        # connection enums. Every one is a CLOSED value space (a routing/protocol
        # taxonomy) — never a host/user/domain identifier — so admitting them
        # recovers legit structured context an internal name could not hide in.
        # (The alert's genuinely free-form leaves — rule_name, message,
        # payload_printable, tags — are deliberately NOT here: they are an open
        # value space where a bare internal name CAN hide, so they stay masked.)
        "event_category",
        "event_module",
        "event_dataset",
        "classtype",
        "zeek_conn_state",
        "zeek_conn_history",
        "zeek_http_method",
    }
)


def _field_is_safe(path: str) -> bool:
    """Whether *path* names a field on the known-safe allowlist.

    Matches any dotted-path suffix against :data:`_SAFE_DOTTED_FIELDS` (so a
    nested wrapper prefix does not defeat the match, exactly like the harvest's
    ``_try_harvest_scalar``) and the last segment against
    :data:`_SAFE_LEAF_KEYS`.
    """
    low = path.lower()
    if any(s in _SAFE_DOTTED_FIELDS for s in _path_suffixes(low)):
        return True
    return low.rsplit(".", maxsplit=1)[-1] in _SAFE_LEAF_KEYS


# ---------------------------------------------------------------------------
# Provably-safe VALUE shapes — allowed regardless of field.
# ---------------------------------------------------------------------------

# A minted opaque label anywhere / as the whole value (IGNORECASE so a
# lower-cased echo is still recognised, symmetric with desanitize).
_LABEL_ANY_RE = re.compile(r"(?<!\w)(?:USER|HOST|IP|MAC|EMAIL)_\d+(?!\w)", re.IGNORECASE)
_LABEL_FULL_RE = re.compile(r"(?:USER|HOST|IP|MAC|EMAIL)_\d+\Z", re.IGNORECASE)

# Numbers: ints/floats, hex, comma/underscore grouping, exponent, trailing %.
_NUMERIC_RE = re.compile(r"[+-]?(?:0[xX][0-9a-fA-F]+|(?:\d[\d,_]*)(?:\.\d+)?(?:[eE][+-]?\d+)?)%?\Z")

# Timestamps / dates: ISO-8601 (``2026-08-27T14:00:00.123Z`` / offset), the
# space-separated variant, and the ``YYYY/MM/DD`` form. Epoch is numeric.
_TIMESTAMP_RE = re.compile(
    r"\d{4}[-/]\d{2}[-/]\d{2}"
    r"(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?\Z"
)

_CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}\Z", re.IGNORECASE)
_ATTACK_RE = re.compile(r"TA?\d{4}(?:\.\d{3})?\Z")  # T1059 / T1059.001 / TA0001

# A DNS label / FQDN (used for the public-FQDN, URL-host and email-domain tests).
_FQDN_LABEL = r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?"
_FQDN_RE = re.compile(rf"{_FQDN_LABEL}(?:\.{_FQDN_LABEL})*\.[A-Za-z]{{2,63}}\Z")
_EMAIL_RE = re.compile(rf"[\w.+-]{{1,64}}@({_FQDN_LABEL}(?:\.{_FQDN_LABEL})*\.[A-Za-z]{{2,63}})\Z")
_URL_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://(?P<host>[^/\\:?#\s]+)")

# Boolean / null / absence tokens that are not identifiers.
_BOOL_NULL_TOKENS: frozenset[str] = frozenset(
    {"true", "false", "yes", "no", "null", "none", "nil", "n/a", "na", "-", "--", "—", "unknown"}
)

# Hash lengths (hex): md5=32, sha1=40, sha224=56, sha256=64, sha384=96, sha512=128.
_HASH_LENGTHS: frozenset[int] = frozenset({32, 40, 56, 64, 96, 128})
_HEX_RE = re.compile(r"[0-9a-fA-F]+\Z")


def _is_ip_or_cidr(value: str) -> bool:
    """A valid IPv4/IPv6 address or CIDR network of either family.

    Any IP is allowed here: a PRIVATE one that reached this point is still caught
    independently by the wire residue gate's IP-shape sweep, so allowing the shape
    does not weaken that net — the backstop's unique job is the shapeless-NAME
    class, not shaped identifiers.
    """
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def _is_hash(value: str) -> bool:
    return len(value) in _HASH_LENGTHS and bool(_HEX_RE.fullmatch(value))


def _endswith_internal_suffix(value: str, suffixes: tuple[str, ...]) -> bool:
    low = value.lower().rstrip(".")
    return any(low.endswith(s.lower()) for s in suffixes)


def _is_public_fqdn(value: str, suffixes: tuple[str, ...]) -> bool:
    """A multi-label FQDN with an alphabetic TLD that does NOT end in a
    configured internal suffix.

    Single-label bare names (``filesrv``, NetBIOS ``CORP``) have no dot and are
    therefore NOT matched — that shapeless class is precisely what the backstop
    masks. A multi-label internal FQDN on a NON-configured suffix
    (``dc01.ad.example.com``) is allowed here, unchanged from the documented,
    operator-mitigated behaviour today (the ``_warn_if_privacy_gate_unconfigured``
    nudge): the backstop's new guarantee is about the single-label class, not
    this pre-existing accepted gap.
    """
    if "." not in value:
        return False
    if _endswith_internal_suffix(value, suffixes):
        return False
    return bool(_FQDN_RE.fullmatch(value.rstrip(".")))


def _is_public_email(value: str, suffixes: tuple[str, ...]) -> bool:
    m = _EMAIL_RE.fullmatch(value)
    if m is None:
        return False
    return not _endswith_internal_suffix(m.group(1), suffixes)


def _is_public_url(value: str, suffixes: tuple[str, ...]) -> bool:
    """A ``scheme://host…`` URL whose host is itself provably safe.

    An internal-suffixed host inside a URL is tokenised to a label by
    ``sanitize_case`` first, so a URL that still carries a bare internal host by
    the time it reaches here is not host-safe and is deliberately NOT allowed.
    """
    m = _URL_RE.match(value)
    if m is None:
        return False
    host = m.group("host").split("@")[-1]  # strip any userinfo
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]  # bracketed IPv6
    if _is_ip_or_cidr(host) or _is_public_fqdn(host, suffixes):
        return True
    return bool(_LABEL_FULL_RE.match(host))


def _scalar_is_provably_safe(value: str, *, suffixes: tuple[str, ...]) -> bool:
    """Whether a STRING scalar is provably not an internal identifier.

    The allow side of allow-known-safe. Errs toward MASKING: an unrecognised
    free-form string returns ``False`` (mask) rather than leak.
    """
    v = value.strip()
    if not v:
        return True
    if v.lower() in _BOOL_NULL_TOKENS:
        return True
    if _LABEL_FULL_RE.match(v):
        return True
    if _NUMERIC_RE.fullmatch(v):
        return True
    if _is_ip_or_cidr(v):
        return True
    if _is_hash(v):
        return True
    if _TIMESTAMP_RE.fullmatch(v):
        return True
    if _CVE_RE.fullmatch(v) or _ATTACK_RE.fullmatch(v):
        return True
    if _is_public_email(v, suffixes):
        return True
    if _is_public_url(v, suffixes):
        return True
    if _is_public_fqdn(v, suffixes):
        return True
    # Composite fallback: a value whose ONLY alphabetic runs live inside minted
    # labels (``IP_01:443``, ``HOST_01\\HOST_02``, an ISO time's lone ``T``/``Z``)
    # carries no free-standing word token that could BE a bare name. Strip the
    # labels, then require no residual run of >=2 letters. This is what keeps a
    # label-plus-port / label-composite value from being masked wholesale while
    # still masking any genuine word residue (which is shape-indistinguishable
    # from an internal name).
    stripped = _LABEL_ANY_RE.sub(" ", v)
    return not re.search(r"[A-Za-z]{2,}", stripped)


def mask_unclassified_scalars(
    obj: Any,
    *,
    suffixes: tuple[str, ...],
) -> tuple[Any, int]:
    """Mask every residual free-form string scalar in *obj*, returning the masked
    copy and the count masked.

    *obj* is an ALREADY-sanitized oracle tool result (post ``sanitize_case``).
    Walks dicts / lists / tuples path-aware (dict KEYS are preserved verbatim —
    only leaf VALUES are considered) and replaces a string that is neither
    :func:`_scalar_is_provably_safe` nor on a :func:`_field_is_safe` field with
    :data:`MASK_PLACEHOLDER`. Non-string scalars (int / float / bool / None) are
    always kept.
    """
    counter = [0]

    def _walk(node: Any, path: str) -> Any:
        if isinstance(node, str):
            if _scalar_is_provably_safe(node, suffixes=suffixes) or _field_is_safe(path):
                return node
            counter[0] += 1
            return MASK_PLACEHOLDER
        if isinstance(node, dict):
            return {k: _walk(v, f"{path}.{k}" if path else str(k)) for k, v in node.items()}
        if isinstance(node, list):
            return [_walk(item, path) for item in node]
        if isinstance(node, tuple):
            return tuple(_walk(item, path) for item in node)
        return node

    masked = _walk(obj, "")
    return masked, counter[0]


__all__ = ["MASK_PLACEHOLDER", "mask_unclassified_scalars"]
