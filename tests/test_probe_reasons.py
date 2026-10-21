"""Plain reasons for a failed connection (dogfood 2026-10-19, H1-D21).

"the grid could not be reached: Connection error caused by:
ClientConnectorError(Cannot connect to host 127.0.0.1:19200 ...)" reached the
health popover and Test ES as is. The operator needs the address and the layer
that failed, in one sentence each.
"""

from __future__ import annotations

import httpx
from elastic_transport import ConnectionError as TransportConnectionError
from soc_ai.webui import probes


def _transport_error(inner: str) -> TransportConnectionError:
    return TransportConnectionError("Connection error caused by", errors=(Exception(inner),))


def test_grid_refusal_names_the_address_and_the_layer() -> None:
    exc = _transport_error(
        "ClientConnectorError(Cannot connect to host 192.0.2.10:9200 ssl:default "
        "[Connect call failed ('192.0.2.10', 9200)])"
    )
    kind, reason = probes._grid_failure(exc)
    assert kind == probes.KIND_REFUSED
    assert reason == "soc-ai cannot connect to 192.0.2.10:9200. Nothing answers on that port."


def test_grid_dns_failure_names_the_layer() -> None:
    exc = _transport_error(
        "Cannot connect to host es.example.test:9200 ssl:default [Name or service not known]"
    )
    _kind, reason = probes._grid_failure(exc)
    assert reason == (
        "soc-ai cannot connect to es.example.test:9200. The host name does not resolve."
    )


def test_an_unrecognised_connection_text_keeps_the_scrubbed_cause() -> None:
    """Inventing a diagnosis is the failure to avoid: an unknown shape stays as is."""
    exc = _transport_error("[Errno 104] Connection reset by peer")
    _kind, reason = probes._grid_failure(exc)
    assert reason.startswith("the grid could not be reached: ")
    assert "Connection reset by peer" in reason


def test_so_api_refusal_names_the_address() -> None:
    exc = httpx.ConnectError(
        "Cannot connect to host so.example.test:443 ssl:default [Connect call failed]"
    )
    kind, reason = probes._so_failure(exc)
    assert kind == probes.KIND_REFUSED
    assert reason == (
        "soc-ai cannot connect to the API at so.example.test:443. Nothing answers on that port."
    )


def test_transport_why_reads_each_layer() -> None:
    assert probes.transport_why(httpx.ConnectTimeout("timed out")) == "The connection timed out."
    assert probes.transport_why(httpx.ConnectError("[Errno -2] Name or service not known")) == (
        "The host name does not resolve."
    )
    assert probes.transport_why(httpx.ConnectError("Connection refused")) == (
        "Nothing answers on that port."
    )
