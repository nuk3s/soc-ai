"""The generalization check: a drafted analytic describes a behaviour, not one case.

The owner's case: "Draft an analytic" on a hunt finding wrote
``local-dead-domain-dns-polling``, titled after one host and two domain names,
with both domains as clause values. It could fire on that host and those
domains only. The check names each pin so the drafter can rewrite once, and
the console can warn when the rewrite still pins.
"""

from __future__ import annotations

from typing import Any

import pytest
from soc_ai.detection.validators import _IDENTITY_FIELDS, generalization_pins
from soc_ai.hunting.spec import CATALOG_DIR, HuntSpec, load_catalog


def _spec(
    *,
    all_: list[dict[str, Any]] | None = None,
    any_: list[dict[str, Any]] | None = None,
    none: list[dict[str, Any]] | None = None,
    title: str = "A host queries a name the resolver answers NXDOMAIN",
    spec_id: str = "local-dns-query-nxdomain",
    scope_field: str = "source.ip",
) -> HuntSpec:
    detection: dict[str, Any] = {
        "all": [{"field": "event.dataset", "value": "zeek.dns"}, *(all_ or [])],
    }
    if any_:
        detection["any"] = any_
    if none:
        detection["none"] = none
    return HuntSpec.model_validate(
        {
            "id": spec_id,
            "title": title,
            "scope_field": scope_field,
            "scope_kind": "ip",
            "precondition": {"all": [{"field": "event.dataset", "value": "zeek.dns"}]},
            "detection": detection,
        }
    )


# One value per identity field that a draft from one case would carry.
_CASE_VALUES: dict[str, str] = {
    "address": "198.51.100.7",
    "host": "atlas",
    "user": "alice",
    "domain": "deadname.example.test",
    "URL": "http://deadname.example.test/a",
    "path": "/home/alice/drop.bin",
    "command line": "drop.exe --run",
}


@pytest.mark.parametrize("field", sorted(_IDENTITY_FIELDS))
@pytest.mark.parametrize("op", ["equals", "prefix", "contains", "wildcard"])
def test_a_value_test_on_an_identity_field_is_a_pin(field: str, op: str) -> None:
    value = _CASE_VALUES[_IDENTITY_FIELDS[field]]
    if op == "wildcard":
        value = f"*{value}*"
    # A few listed fields are off the OQL whitelist today, so a spec cannot
    # name them yet. The check still covers them: the whitelist can grow.
    spec = _spec(all_=[{"field": "event.code", "op": op, "value": value}])
    assert spec.detection is not None
    spec.detection.all[1].field = field
    pins = generalization_pins(spec)
    assert pins, f"{op} on {field} must pin"
    assert pins[0].startswith(f"The clause on {field} pins the analytic to one ")
    assert pins[0].endswith("Describe the behaviour.")
    # The sentence goes back to the model. It names the field and never the value.
    assert value.strip("*") not in " ".join(pins)


def test_the_owner_case_pins_and_its_behaviour_does_not() -> None:
    """The dead-domain draft against the rewrite the prompt teaches."""
    pinned = _spec(
        spec_id="local-dead-domain-dns-polling",
        title="Atlas repeatedly queries unreachable dead domains",
        all_=[
            {"field": "source.ip", "value": "198.51.100.7"},
            {
                "field": "dns.query.name",
                "op": "one_of",
                "value": ["zexil.example.test", "saxlori.example.test"],
            },
        ],
    )
    pins = generalization_pins(pinned, hosts=["Atlas", "198.51.100.7"])
    assert "The clause on source.ip pins the analytic to one address. Describe the behaviour." in (
        pins
    )
    assert (
        "The clause on dns.query.name pins the analytic to a fixed list of domain values. "
        "Describe the behaviour."
    ) in pins
    assert "The title names a host from the finding. Name the behaviour." in pins

    behaviour = _spec(all_=[{"field": "dns.response.code_name", "value": "NXDOMAIN"}])
    assert generalization_pins(behaviour, hosts=["Atlas", "198.51.100.7"]) == []


def test_an_address_inside_a_one_of_list_is_a_pin_on_any_field() -> None:
    """The IP hides among stable values on a field the identity list does not name."""
    spec = _spec(
        all_=[
            {
                "field": "network.protocol",
                "op": "one_of",
                "value": ["dns", "203.0.113.9", "http"],
            }
        ]
    )
    assert generalization_pins(spec) == [
        "The clause on network.protocol names a literal IP address. Describe the behaviour."
    ]


def test_an_ipv6_literal_is_a_pin() -> None:
    spec = _spec(all_=[{"field": "network.protocol", "value": "2001:db8::7"}])
    assert generalization_pins(spec) == [
        "The clause on network.protocol names a literal IP address. Describe the behaviour."
    ]


def test_a_host_of_the_finding_on_any_field_is_a_pin() -> None:
    spec = _spec(all_=[{"field": "network.protocol", "value": "Atlas"}])
    assert generalization_pins(spec, hosts=["atlas.example.test"]) == [
        "The clause on network.protocol names a host from the finding. Describe the behaviour."
    ]


def test_a_value_test_on_the_scope_field_is_a_pin() -> None:
    spec = _spec(
        scope_field="winlog.event_data.MemberName",
        all_=[{"field": "winlog.event_data.MemberName", "value": "CN=alice"}],
    )
    assert generalization_pins(spec) == [
        "The clause on winlog.event_data.MemberName pins the analytic to one entity. "
        "Describe the behaviour."
    ]


def test_a_stable_discriminator_passes() -> None:
    spec = _spec(
        all_=[
            {"field": "event.code", "value": "4662"},
            {"field": "destination.port", "value": 53},
            {"field": "network.transport", "op": "one_of", "value": ["udp", "tcp"]},
            {"field": "source.ip", "op": "exists"},
        ]
    )
    assert generalization_pins(spec, hosts=["atlas"]) == []


def test_the_machine_account_wildcard_names_a_class() -> None:
    """``*$`` is every machine account, so the clause describes a behaviour."""
    spec = _spec(
        all_=[{"field": "winlog.event_data.SubjectUserName", "op": "wildcard", "value": "*$"}]
    )
    assert generalization_pins(spec) == []
    # The negative control: a named account on the same field and op pins.
    named = _spec(
        all_=[{"field": "winlog.event_data.SubjectUserName", "op": "wildcard", "value": "alice*"}]
    )
    assert generalization_pins(named)


def test_an_indicator_of_the_finding_is_no_pin() -> None:
    """A known-bad domain from a feed is the point of the finding."""
    spec = _spec(all_=[{"field": "dns.question.name", "value": "bad.example.test"}])
    assert generalization_pins(spec, indicators=["BAD.example.test"]) == []
    # Without the indicator list the same clause pins.
    assert generalization_pins(spec)
    # The exception covers the listed value only. A second value still pins.
    two = _spec(
        all_=[
            {
                "field": "dns.question.name",
                "op": "one_of",
                "value": ["bad.example.test", "other.example.test"],
            }
        ]
    )
    assert generalization_pins(two, indicators=["bad.example.test"])


def test_an_exclusion_is_no_pin() -> None:
    """A none clause removes one service account from a behaviour."""
    spec = _spec(none=[{"field": "user.name", "value": "svc-backup"}])
    assert generalization_pins(spec) == []


def test_a_pin_in_an_any_list_counts() -> None:
    spec = _spec(
        any_=[
            {"field": "dns.response.code_name", "value": "NXDOMAIN"},
            {"field": "host.name", "value": "atlas"},
        ]
    )
    assert generalization_pins(spec) == [
        "The clause on host.name pins the analytic to one host. Describe the behaviour."
    ]


def test_a_title_with_a_hostname_is_a_pin() -> None:
    spec = _spec(title="Atlas queries a name the resolver answers NXDOMAIN")
    assert generalization_pins(spec, hosts=["atlas.example.test"]) == [
        "The title names a host from the finding. Name the behaviour."
    ]
    # The word boundary holds: a host named "her" is not in "where".
    other = _spec(title="A host queries a name where the resolver answers NXDOMAIN")
    assert generalization_pins(other, hosts=["her"]) == []


def test_a_title_with_an_address_is_a_pin() -> None:
    spec = _spec(title="198.51.100.7 queries a name the resolver answers NXDOMAIN")
    assert generalization_pins(spec) == ["The title names an IP address. Name the behaviour."]


def test_an_id_with_a_host_or_an_address_is_a_pin() -> None:
    by_host = _spec(spec_id="local-atlas-nxdomain")
    assert generalization_pins(by_host, hosts=["Atlas"]) == [
        "The id names a host from the finding. Name the behaviour."
    ]
    by_ip = _spec(spec_id="local-nxdomain-from-198-51-100-7")
    assert generalization_pins(by_ip) == ["The id names an IP address. Name the behaviour."]


def test_an_address_host_does_not_match_its_first_octet() -> None:
    """An IP host splits into numbers. "198" is no host name."""
    spec = _spec(title="A host queries 198 names the resolver answers NXDOMAIN")
    assert generalization_pins(spec, hosts=["198.51.100.7"]) == []


@pytest.mark.parametrize(
    "spec_id",
    sorted(sid for sid, spec in load_catalog(CATALOG_DIR).items() if spec.detection is not None),
)
def test_every_shipped_match_analytic_describes_a_behaviour(spec_id: str) -> None:
    """The shipped specs are the right generalization level. The check passes each one.

    The privileged group change analytic keys on TargetUserName with the
    well-known group names, and the DCSync one excludes ``*$``. Both are classes.
    """
    spec = load_catalog(CATALOG_DIR)[spec_id]
    assert generalization_pins(spec) == []
