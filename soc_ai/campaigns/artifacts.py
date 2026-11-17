"""The text rules of an artifact. Pure.

An artifact is a thing that two runs can share: a rule, a CVE id, or an HTTP
method with a URI path. A named host is a host or an address that a document
names in its URI, its payload or its Host header.
"""

from __future__ import annotations

import ipaddress
import re

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.]*\w)")
_URL_HOST_RE = re.compile(r"://([A-Za-z0-9._\-]+|\[[0-9A-Fa-f:]+\])")
_DEV_TCP_RE = re.compile(r"/dev/(?:tcp|udp)/([A-Za-z0-9._\-]+)/\d+")
_HOST_ONLY_RE = re.compile(r"^[A-Za-z0-9._\-]+(?::\d{1,5})?$")
_NAME_RE = re.compile(
    r"^(?=.*[a-z])[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$"
)


def cve_ids(*texts: str | None) -> frozenset[str]:
    """Each CVE id in the texts, in upper case."""
    found: set[str] = set()
    for text in texts:
        if isinstance(text, str) and text:
            found.update(m.group(0).upper() for m in _CVE_RE.finditer(text))
    return frozenset(found)


def http_key(method: str | None, uri: str | None) -> str | None:
    """``<METHOD> <path>`` with the query and the fragment removed.

    None with no method, with no URI and for the path ``/``: each site has
    that path, so it joins nothing.
    """
    verb = method.strip().upper() if isinstance(method, str) else ""
    raw = uri.strip() if isinstance(uri, str) else ""
    if not verb or not raw:
        return None
    path = raw.split("#", 1)[0].split("?", 1)[0]
    if "://" in path:
        path = "/" + path.split("://", 1)[1].partition("/")[2]
    if not path.startswith("/") or path == "/":
        return None
    return f"{verb} {path}"


def _host(value: str) -> str | None:
    """One candidate as a host name or an address, or None."""
    text = value.strip().strip("[]").rstrip(".").lower()
    if not text:
        return None
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return text if "." in text and _NAME_RE.match(text) else None
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        return None
    return str(address)


def named_hosts(*texts: str | None) -> tuple[str, ...]:
    """The addresses and the host names that the texts name. Sorted, no duplicate.

    Read from four forms: an IPv4 literal, a host after ``://``, a host in
    ``/dev/tcp/<host>/<port>``, and a text that is one host with an optional
    port, the form of a Host header. A name needs a dot and a letter. A
    loopback address and ``0.0.0.0`` name no host.
    """
    found: set[str] = set()
    for text in texts:
        if not isinstance(text, str) or not text.strip():
            continue
        body = text.strip()
        candidates: list[str] = []
        if _HOST_ONLY_RE.match(body):
            candidates.append(body.rsplit(":", 1)[0] if ":" in body else body)
        candidates.extend(m.group(0) for m in _IPV4_RE.finditer(body))
        candidates.extend(m.group(1) for m in _URL_HOST_RE.finditer(body))
        candidates.extend(m.group(1) for m in _DEV_TCP_RE.finditer(body))
        for candidate in candidates:
            host = _host(candidate)
            if host is not None:
                found.add(host)
    return tuple(sorted(found))


def shell_hosts(*texts: str | None) -> tuple[str, ...]:
    """The hosts that a ``/dev/tcp/<host>/<port>`` path names. Sorted, no duplicate.

    For a payload: it holds headers with many URLs, and only this form names
    a host that the target must connect to.
    """
    found: set[str] = set()
    for text in texts:
        if not isinstance(text, str):
            continue
        for match in _DEV_TCP_RE.finditer(text):
            host = _host(match.group(1))
            if host is not None:
                found.add(host)
    return tuple(sorted(found))
