"""The HuntSpec document, its clause compiler, and the ``match`` evaluator.

A spec is YAML on disk, versioned in the repo, diffable in review. It compiles
to exactly one Elasticsearch query and produces zero or more
:class:`Candidate` objects, each carrying real document ids so anything
downstream can cite evidence rather than assert it.

**Not Sigma, and the reason matters.** Sigma is the obvious candidate for this
format and soc-ai already exports it. It is not used here because there is no
Sigma-to-ES-DSL compiler in this tree and writing one is not a first slice:
``validators._sigma_selection_fields`` extracts field *names*,
``_condition_references_selection`` only checks a condition names a defined
selection, and ``_sigma_oql_divergence`` diffs two artifacts a model authored
separately. Implementing ``contains`` / ``startswith`` / ``re`` / ``all of`` /
``1 of`` from nothing is a compiler project. Sigma stays the export format;
importing it into this clause form is later work, and the clause form is
deliberately a subset it can be mapped onto.

**What a spec can express, and what it cannot.** Field-level predicates joined
by all/any/not. That is enough for the majority of high-value identity
detections, which are single-field predicates over near-zero base rates. It is
deliberately not enough for thresholds, sequences or statistics: those need
their own evaluators, they need per-grid numbers nobody has measured yet, and
shipping them in the same breath as the predicate form would hide the fact that
the predicate form needs no tuning at all.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

from soc_ai.so_client.oql import get_whitelist
from soc_ai.tools._provenance import LIVE, Provenance, provenance_must_not
from soc_ai.tools._synth_scope import SynthScope, synth_scope_must_not

# A spec id is used as a state key, a filename stem and a finding attribute, so
# it is constrained to something safe in all three.
_SPEC_ID_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")

# An ATT&CK technique, as a catalog file writes it: ``T1558`` or ``T1558.003``.
_TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?\Z")
# The same technique inside a reference URL: ``/techniques/T1558/003/``.
_TECHNIQUE_URL_RE = re.compile(r"attack\.mitre\.org/techniques/(T\d{4})(?:/(\d{3}))?", re.I)


def _technique_id(value: str) -> str | None:
    """``T1558.003`` from a catalog ``attack`` entry, or None."""
    text = value.strip().upper()
    return text if _TECHNIQUE_RE.fullmatch(text) else None


def _technique_from_url(url: str) -> str | None:
    """``T1558.003`` from an ATT&CK technique page URL, or None."""
    match = _TECHNIQUE_URL_RE.search(url)
    if match is None:
        return None
    base = match.group(1).upper()
    return f"{base}.{match.group(2)}" if match.group(2) else base


# Hard ceilings. A spec is data, and data in this repo is reviewed, but a spec
# is also the thing most likely to be copy-pasted and edited in a hurry.
MAX_CLAUSES = 24
MAX_CANDIDATES = 200
DEFAULT_TOP_K = 10

# The ceiling on a precondition's own look-back, in minutes. One year, because
# past that the question has stopped being "is this sensor reporting" and become
# "was it ever installed", and no grid this runs against keeps a year of indices
# to answer it with. The precondition is an exact count over whatever window it
# is given, so the number is also a cost.
MAX_PRECONDITION_LOOKBACK_MINUTES = 365 * 24 * 60

Op = Literal[
    "equals", "one_of", "exists", "contains", "prefix", "wildcard", "gt", "gte", "lt", "lte"
]

# What an exclusion says about a document that does not carry the field it
# reads. There is no third answer available from the document itself, which is
# why the default is neither of the two answers a compiler could pick.
Absent = Literal["report", "match"]


class Clause(BaseModel):
    """One field-level predicate.

    ``contains`` is a substring test compiled to a wildcard, which on a
    ``keyword`` field is an expensive but correct query and on a ``text`` field
    would silently not mean what it looks like. Specs should prefer ``equals``
    or ``one_of`` and reach for ``contains`` only where the field genuinely
    holds a composite value — the DCSync ``Properties`` leaf is the motivating
    case, because it holds a description and a GUID in one string.

    ``absent`` applies to a ``none`` clause and says what the clause means about
    a document with no value for its field. ``report`` is the default and
    declares nothing: the document is neither matched nor dropped, it is counted
    and reported. ``match`` is an author saying they know absence on their data
    and it does not exclude, which is right where the field is one Windows
    simply does not populate for that kind of event. There is deliberately no
    value for "treat it as excluded": that is the silent drop, and a spec that
    wants one copy of a double-shipped event says so by pinning
    ``event.dataset`` in ``all`` rather than by hiding the other copy.
    """

    model_config = {"extra": "forbid"}

    field: str
    op: Op = "equals"
    value: Any = None
    absent: Absent = "report"

    @field_validator("field")
    @classmethod
    def _field_is_queryable(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("clause field must not be empty")
        if not get_whitelist().is_allowed(v):
            raise ValueError(
                f"field {v!r} is not on the OQL whitelist. A spec may only read fields the "
                "query language already admits, so that adding a field is one reviewed "
                "decision with its Oracle-egress classification attached, rather than two "
                "independent ones that can disagree."
            )
        return v

    @model_validator(mode="after")
    def _pattern_means_the_same_thing_in_both_engines(self) -> Clause:
        """Refuse a pattern whose meaning differs between the matcher and ES.

        ``match.py`` evaluates ``wildcard`` with :mod:`fnmatch`, whose
        metacharacters are ``* ? [ ]``; Elasticsearch uses Lucene wildcard,
        whose metacharacters are ``* ?`` with ``\\`` as the escape. ``[``, ``]``
        and ``\\`` are syntax in one engine and literals in the other, in
        OPPOSITE directions — so ``svc[0-9]*`` matches ``svc1`` in the matcher
        and only the literal string ``svc[0-9]…`` in ES.

        That divergence produces a CI-certified false all-clear: the coverage
        gate scores through the matcher, so a spec that can never fire live
        passes the build, and at runtime a broad precondition returns documents
        (``blind=False``) while the detection returns nothing (``clean=True``).

        ``contains`` diverges the other way: it is compiled to ``*{value}*``, so
        a ``*`` or ``?`` inside the value becomes an ES metacharacter while the
        matcher does a literal substring test.

        Writing a full Lucene-dialect translator for the matcher is the better
        long-term answer. Refusing the ambiguous characters costs nothing and
        makes the module's claim that differences are "documented at the
        operator" true by construction rather than by intention.
        """
        if not isinstance(self.value, str):
            return self
        if self.op == "wildcard":
            bad = {c for c in "[]\\" if c in self.value}
            if bad:
                raise ValueError(
                    f"wildcard value {self.value!r} contains {sorted(bad)}, which mean "
                    "different things to fnmatch (the in-memory matcher) and to "
                    "Elasticsearch. Use only * and ?, or express it with 'contains'."
                )
        if self.op == "contains":
            bad = {c for c in "*?" if c in self.value}
            if bad:
                raise ValueError(
                    f"contains value {self.value!r} contains {sorted(bad)}; 'contains' is "
                    "compiled to *value* so those become Elasticsearch wildcards, while "
                    "the in-memory matcher treats them literally. Use 'wildcard' if you "
                    "mean a pattern."
                )
        return self

    @model_validator(mode="after")
    def _value_matches_op(self) -> Clause:
        if self.op == "exists":
            if self.value is not None:
                raise ValueError("op 'exists' takes no value")
            return self
        if self.value is None:
            raise ValueError(f"op {self.op!r} requires a value")
        if self.op == "one_of" and not isinstance(self.value, list):
            raise ValueError("op 'one_of' requires a list value")
        if self.op != "one_of" and isinstance(self.value, list):
            raise ValueError(f"op {self.op!r} takes a scalar, not a list")
        return self

    def to_es(self) -> dict[str, Any]:
        """Compile to a single Elasticsearch query clause."""
        f, v = self.field, self.value
        if self.op == "exists":
            return {"exists": {"field": f}}
        if self.op == "equals":
            return {"term": {f: v}}
        if self.op == "one_of":
            return {"terms": {f: list(v)}}
        if self.op == "prefix":
            return {"prefix": {f: v}}
        if self.op == "wildcard":
            return {"wildcard": {f: v}}
        if self.op == "contains":
            return {"wildcard": {f: f"*{v}*"}}
        return {"range": {f: {self.op: v}}}


class Detection(BaseModel):
    """The predicate tree: everything in ``all``, anything in ``any``, nothing in ``none``.

    **An exclusion is a statement about documents that carry the field.** A
    ``must_not`` on a wildcard over a field a document does not have excludes
    nothing, so a ``none`` clause compiled literally stops working the moment
    the same event arrives from a second dataset with a different schema.
    Windows security events do exactly that on any host running both the winlog
    integration and Elastic Defend: the ``endpoint.events.security`` copy
    carries the same ``event.code`` and none of the ``winlog.event_data`` tree.
    Measured on the development range on 2026-09-05, a spec on event code 4648
    whose precision came from two machine-account exclusions returned 78
    candidates, 74 of them the machine accounts those exclusions exist to
    remove.

    **A field is also absent inside the right dataset, and that is a different
    fact.** Windows writes no ``SubjectUserName`` on a network logon at all,
    because the subject there is the null SID. Measured on the same grid over
    2026-09-05: 5,422 event code 4624 documents carry ``LogonType``, 5,240 of
    those carry no ``SubjectUserName``, and every one of the 5,240 is a network
    logon. Requiring the field of them deletes the population a 4624 detection
    is about.

    Nothing in a document says which of the two it is, so the compiler does not
    choose. A ``none`` clause that reads a VALUE compiles to "has the field and
    does not match it", via :meth:`exclusion_fields`, and the documents that
    filter removes are counted and reported rather than dropped: see
    :meth:`HuntSpec.to_query` with ``undecided=True``. An author who knows what
    absence means on their data writes ``absent: match`` on the clause.

    Positive clauses need no such treatment: a term or range query cannot match
    a document that lacks the field, in either engine. ``none`` with
    ``op: exists`` is left alone, because there the clause already says the
    field must be absent.
    """

    model_config = {"extra": "forbid"}

    all: list[Clause] = Field(default_factory=list)
    any: list[Clause] = Field(default_factory=list)
    none: list[Clause] = Field(default_factory=list)

    @model_validator(mode="after")
    def _has_something_and_not_too_much(self) -> Detection:
        total = len(self.all) + len(self.any) + len(self.none)
        if total == 0:
            raise ValueError("detection must contain at least one clause")
        if total > MAX_CLAUSES:
            raise ValueError(f"detection has {total} clauses, ceiling is {MAX_CLAUSES}")
        if self.none and not (self.all or self.any):
            raise ValueError(
                "a detection of only 'none' clauses matches every document that is not "
                "excluded, which is a sweep of the whole grid rather than a detection"
            )
        return self

    @model_validator(mode="after")
    def _absent_is_declared_where_it_can_mean_something(self) -> Detection:
        """``absent`` off a value-reading ``none`` clause would be parsed and ignored.

        On a positive clause it says nothing, because a term or range query
        cannot match a missing field in either engine. On ``none`` with
        ``op: exists`` it contradicts the clause, which already says the field
        must be absent. Two ``none`` clauses on one field with opposite
        declarations are refused rather than resolved, since whichever the
        compiler picked would silently be the other one's opposite.
        """
        for block, clauses in (("all", self.all), ("any", self.any)):
            for clause in clauses:
                if clause.absent != "report":
                    raise ValueError(
                        f"clause on {clause.field!r} in '{block}' sets absent="
                        f"{clause.absent!r}, which only means something on a 'none' "
                        "clause: a positive clause already cannot match a document "
                        "that lacks the field"
                    )
        for clause in self.none:
            if clause.op == "exists" and clause.absent != "report":
                raise ValueError(
                    f"clause on {clause.field!r} sets absent={clause.absent!r} on "
                    "op 'exists', which already says the field must be absent"
                )
        declared: dict[str, str] = {}
        for clause in self.none:
            if clause.op == "exists":
                continue
            prior = declared.setdefault(clause.field, clause.absent)
            if prior != clause.absent:
                raise ValueError(
                    f"two 'none' clauses on {clause.field!r} disagree about what an "
                    f"absent value means ({prior!r} and {clause.absent!r})"
                )
        return self

    def exclusion_fields(self) -> tuple[str, ...]:
        """Fields an exclusion reads by value and cannot speak for when they are absent.

        The compiled detection requires these present, and the count of
        documents they remove is what ``undecided=True`` asks for. The two uses
        are one list on purpose: a field can only be dropped from the detection
        if something else reports it.

        A field the ``all`` block already pins by value is left out: that clause
        requires the field present on its own, so nothing can be missing it, and
        repeating it would put the same ``exists`` in the filter twice. A clause
        declaring ``absent: match`` is left out because its author has said
        absence does not exclude, so there is nothing undecided about it.
        """
        pinned = {c.field for c in self.all if c.op != "exists"}
        return tuple(
            dict.fromkeys(
                c.field
                for c in self.none
                if c.op != "exists" and c.absent == "report" and c.field not in pinned
            )
        )

    def required_fields(self) -> tuple[str, ...]:
        """Every field this tree needs before it can say anything at all.

        The ``all`` block's value-reading clauses, and only those. Without one
        of them a term or range query cannot match in either engine, so a
        document that lacks it is a copy of the event this detection is not
        written against. :meth:`HuntSpec.to_query` uses it to scope the
        precondition to the same population.

        ``none`` fields were once here too, and that is the rule this method
        corrects. A document missing an exclusion's field is not outside the
        population: it is inside it, undecidable, and counted as such. Dropping
        it from the precondition as well shrank the denominator by exactly the
        documents the detection had discarded, so the run read as clean. On the
        4624 reconstruction, measured over 2026-09-05, that took the
        precondition from 5,422 to 182 while the detection went to zero.

        ``any`` is deliberately excluded as well. Its clauses are alternatives,
        so requiring every field they name would demand a document carry all of
        them at once, which is the opposite of what the block says. What the
        block DOES require is at least one of them, and that is
        :meth:`alternative_fields`.
        """
        return tuple(dict.fromkeys(c.field for c in self.all if c.op != "exists"))

    def alternative_fields(self) -> tuple[str, ...]:
        """The fields the ``any`` block reads by value — at least one is needed.

        A document carrying NONE of them cannot satisfy a single branch of the
        block, so the detection is a decided non-match on it. That is the same
        silent drop :meth:`required_fields` closes for ``all``, arriving through
        the one door that was left open: the field a positive clause reads is
        not required of the precondition, because ``any`` names alternatives and
        requiring them all would be the opposite of what the block says.

        Requiring ONE of them is what the block actually says, and it is what
        scopes the precondition to the population the detection could examine.
        The DCSync spec is the measured case: its ``all`` block is the event code
        alone and its whole discriminator, the three replication rights, lives in
        ``any`` on ``winlog.event_data.Properties``. On a host running both the
        winlog integration and Elastic Defend the same 4662 event is indexed
        twice, and the ``endpoint.events.security`` copy carries the code and
        none of the ``winlog.event_data`` tree. Without this the precondition
        counts both copies, the detection can only ever match one, and a grid
        holding nothing but the copy the spec cannot read reports a clean run
        over a denominator it was never able to look at.

        ``op: exists`` clauses are left out because they read presence rather
        than a value: such a clause reaches a verdict on a document with no
        field at all, so it is never the reason a document is unexaminable.
        """
        return tuple(dict.fromkeys(c.field for c in self.any if c.op != "exists"))

    def to_es(self, *, presence: bool = True) -> dict[str, Any]:
        """Compile the tree. ``presence=False`` drops the exclusion-field filter.

        The undecided query asks about the documents that filter removes, so it
        is compiled from this method with the filter switched off rather than by
        editing a finished query. One compiler, two questions, no second place
        for the clause forms to be translated differently.
        """
        bool_q: dict[str, Any] = {}
        filters = [c.to_es() for c in self.all]
        if presence:
            filters += [{"exists": {"field": f}} for f in self.exclusion_fields()]
        if filters:
            bool_q["filter"] = filters
        if self.any:
            bool_q["should"] = [c.to_es() for c in self.any]
            bool_q["minimum_should_match"] = 1
        if self.none:
            bool_q["must_not"] = [c.to_es() for c in self.none]
        return {"bool": bool_q}


class ProfileTest(BaseModel):
    """What a ``profile`` spec asks of an entity's behavioural profile.

    A prior does not match a document. It asks whether something is novel for
    this entity — or for its role — given what the profile already holds.
    """

    model_config = {"extra": "forbid"}

    # Which profile dimension to read: served_ports, peers_out, process_names…
    dimension: str

    # novel_for:             the observed member is absent from the profile.
    # outside_active_hours:  activity in an hour this entity has never used.
    # below:                 a rate has fallen well under its own median.
    # above:                 …and the mirror image, for rates that spike.
    test: Literal["novel_for", "outside_active_hours", "below", "above"] = "novel_for"

    # Empty means "every role". A named role restricts the prior to entities
    # the dossier has placed in it.
    roles: list[str] = Field(default_factory=list)

    # The INVERTED confidence gate. A prior evaluates only where the dossier is
    # confident about the role; below this it is blind and says so. It is never
    # demoted to a weak observation, because that makes a quiet host a safe
    # harbour, and a quiet host is where a careful attacker lives.
    #
    # Defaulted high on purpose: a permissive default restores exactly the
    # behaviour the inversion exists to remove, and it would do so silently.
    min_role_confidence: float = 0.9

    # For the numeric tests, how many MAD-derived sigmas count as a departure.
    threshold: float = 3.0

    # How many times a novel member must be observed before it is a departure.
    #
    # An ephemeral port is used once and never again; a service — legitimate or
    # hostile — is used repeatedly. Requiring recurrence separates them without
    # guessing about port numbers, which a numeric floor cannot do: against the
    # range, 47908 sat above Linux's ephemeral start and below the IANA dynamic
    # floor, and raising the floor to catch it would have blinded the layer to a
    # C2 listener parked on a high port.
    #
    # Declarable per prior because a single-shot prior covers events where one
    # occurrence IS the finding.
    min_observations: int = 2

    @field_validator("roles")
    @classmethod
    def _roles_are_in_the_vocabulary(cls, v: list[str]) -> list[str]:
        # Imported here rather than at module scope: the dossier package pulls
        # in the whole inference stack, and hunting is imported from inside it.
        from soc_ai.dossier.infer import ROLE_VOCABULARY  # noqa: PLC0415 - lazy, avoids a cycle

        unknown = [role for role in v if role not in ROLE_VOCABULARY]
        if unknown:
            raise ValueError(
                f"unknown role(s) {unknown!r}: a typo'd role matches no entity, and a "
                f"prior that matches nothing reads exactly like a clean network. "
                f"Known roles: {sorted(ROLE_VOCABULARY)}"
            )
        return v


class HuntSpec(BaseModel):
    """One declarative hunt."""

    model_config = {"extra": "forbid"}

    id: str
    title: str
    description: str = ""
    level: Literal["informational", "low", "medium", "high", "critical"] = "medium"
    evaluator: Literal["match", "profile"] = "match"

    # Exactly one of these is set, enforced below and keyed off ``evaluator``.
    # A spec carrying both is ambiguous about which one decides, and the query
    # builder and the evaluator resolved that ambiguity differently.
    detection: Detection | None = None
    profile: ProfileTest | None = None

    # The precondition answers "is this spec blind, or is the grid clean?".
    # Zero candidates from a spec whose precondition also returns zero is a
    # coverage gap, not an all-clear, and the two must never be reported alike.
    precondition: Detection | None = None

    # How much further back than the run window the precondition may look. Zero
    # means the detection's own window, which is right for every sensor that
    # reports on a schedule rather than on an event.
    #
    # It is per spec because sensors differ in the one way that decides the
    # answer. A domain controller with Directory Service Access auditing on
    # writes 4662s all day, so silence in the window means the auditing was
    # switched off and the spec IS blind: the catalog's acceptance test is
    # exactly that. An OpenCanary honeypot writes a record when its service
    # starts and then nothing at all until something touches it, so silence in
    # the window is the healthy case and reporting it as a gap trains an analyst
    # to ignore the marker. Widening every precondition would trade the second
    # lie for the first, which is why this is spec knowledge and not a setting.
    precondition_lookback_minutes: int = 0

    # Whether this detection has a benign population at all.
    #
    # Most detections do: the interesting instance has to be separated from the
    # routine ones, which is what a baseline, a threshold or a volume argument
    # is for. A few do not — directory replication by a non-machine account,
    # an account that does not require Kerberos pre-authentication, anything
    # touching a decoy — and for those the same argument runs backwards: "this
    # happens every hour" is what the attack looks like, not what clears it.
    #
    # A triage gate reads this (soc_ai/agent/doctrine.py) and refuses to close
    # such a detection false_positive, landing it needs_more_info instead. The
    # spec's own ``false_positives`` list is what it hands the reader to check —
    # those are exceptions by identity, and only a human can confirm one.
    #
    # Default False: a spec has to say out loud that no rate can clear it.
    no_benign_baseline: bool = False

    # Which document identifies the thing a candidate is ABOUT. Grouping by this
    # is what makes one condition one candidate instead of one per document.
    scope_field: str = "host.name"
    scope_kind: Literal[
        "host", "ip", "user", "cloud_identity", "mailbox", "decoy", "rule", "dataset"
    ] = "host"

    provenance: Provenance = LIVE
    top_k: int = DEFAULT_TOP_K

    attack: list[str] = Field(default_factory=list)
    false_positives: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)

    @field_validator("id")
    @classmethod
    def _id_is_slug(cls, v: str) -> str:
        if not _SPEC_ID_RE.fullmatch(v):
            raise ValueError(
                f"spec id {v!r} must be lowercase-kebab-case: it is used as a state key, "
                "a filename stem and a finding attribute"
            )
        return v

    @field_validator("scope_field")
    @classmethod
    def _scope_is_queryable(cls, v: str) -> str:
        if not get_whitelist().is_allowed(v):
            raise ValueError(f"scope_field {v!r} is not on the OQL whitelist")
        return v

    @field_validator("top_k")
    @classmethod
    def _top_k_is_bounded(cls, v: int) -> int:
        if not 1 <= v <= MAX_CANDIDATES:
            raise ValueError(f"top_k must be between 1 and {MAX_CANDIDATES}")
        return v

    @field_validator("precondition_lookback_minutes")
    @classmethod
    def _lookback_is_bounded(cls, v: int) -> int:
        if not 0 <= v <= MAX_PRECONDITION_LOOKBACK_MINUTES:
            raise ValueError(
                f"precondition_lookback_minutes must be between 0 and "
                f"{MAX_PRECONDITION_LOOKBACK_MINUTES} (one year)"
            )
        return v

    @model_validator(mode="after")
    def _the_evaluator_decides_which_block_is_required(self) -> HuntSpec:
        """Exactly one of ``detection`` / ``profile``, chosen by ``evaluator``.

        The first cut required a detection block on every spec, so each prior
        carried a dummy clause that then had to be excluded from every query
        path. Allowing both is worse: the query builder read one and the
        evaluator read the other, and nothing reconciled them.
        """
        if self.evaluator == "match":
            if self.detection is None:
                raise ValueError("a 'match' spec needs a detection block")
            if self.profile is not None:
                raise ValueError(
                    "a 'match' spec carries a profile block that would be parsed, "
                    "validated and then ignored by the query path"
                )
        else:
            if self.profile is None:
                raise ValueError(f"a {self.evaluator!r} spec needs a profile block")
            if self.detection is not None:
                raise ValueError(
                    f"a {self.evaluator!r} spec carries a detection block; which of the "
                    "two decides is then ambiguous, and the query path and the "
                    "evaluator answer it differently"
                )
        return self

    @model_validator(mode="after")
    def _a_lookback_needs_a_precondition_to_widen(self) -> HuntSpec:
        if self.precondition_lookback_minutes and self.precondition is None:
            raise ValueError(
                "precondition_lookback_minutes is set on a spec with no precondition, so "
                "it would be parsed, validated and then ignored"
            )
        return self

    @property
    def techniques(self) -> tuple[str, ...]:
        """The ATT&CK technique ids this analytic names, deduplicated and sorted.

        Read from two places, because the catalog writes the same fact twice:
        the ``attack`` list holds the ids, and ``references`` holds the
        technique pages. A sub-technique reads as ``T1558.003`` from both, so
        ``attack.mitre.org/techniques/T1558/003/`` and ``T1558.003`` are one
        entry. Related leads compare analytics on this.
        """
        found: set[str] = set()
        for value in self.attack:
            technique = _technique_id(str(value))
            if technique:
                found.add(technique)
        for url in self.references:
            technique = _technique_from_url(str(url))
            if technique:
                found.add(technique)
        return tuple(sorted(found))

    def matched_fields(self) -> tuple[str, ...]:
        """Every field this analytic reads, for the receipts of a shadow hit.

        The detection first, then the precondition, deduplicated and in the
        order the spec writes them.
        """
        fields: list[str] = []
        for tree in (self.detection, self.precondition):
            if tree is None:
                continue
            for block in (tree.all, tree.any, tree.none):
                fields.extend(clause.field for clause in block)
        return tuple(dict.fromkeys(fields))

    def precondition_since(self, since: str) -> str:
        """Where the precondition's window starts, given the run's own start.

        Shifted from the run's START and never from its end, so the precondition
        window contains the detection window whatever the look-back is. Measured
        back from the end, a look-back shorter than a retro sweep's window would
        ask the precondition about less ground than the detection covers, and a
        spec that matched documents its own precondition could not see would
        report blind while holding the evidence.

        Elasticsearch date math chains straight onto ``now`` and onto a literal
        timestamp only after ``||``. The sweep passes the first form and
        ``spec-sweep --since`` can pass either, so both are handled here rather
        than at each caller.
        """
        if not self.precondition_lookback_minutes:
            return since
        anchor = since.strip()
        separator = "" if anchor.startswith("now") or "||" in anchor else "||"
        return f"{anchor}{separator}-{self.precondition_lookback_minutes}m"

    def to_query(
        self,
        *,
        since: str,
        until: str,
        include_synth: SynthScope = False,
        extra_replay_tags: tuple[str, ...] = (),
        precondition: bool = False,
        undecided: bool = False,
    ) -> dict[str, Any]:
        """Compile to one Elasticsearch query.

        ``precondition=True`` compiles the precondition tree instead of the
        detection, so the same provenance scope and synth scope apply to both. A
        precondition evaluated over a different population than the detection it
        guards would answer a different question.

        The time window is the same too, unless the spec declares a
        ``precondition_lookback_minutes``, in which case the precondition starts
        that much earlier and the detection is untouched. That is the one axis
        on which the two questions legitimately differ: "did anything happen" is
        about the window, "can this spec see" is about the sensor, and a sensor
        that only writes when something touches it answers the second question
        over a longer stretch of time or not at all.

        **Schema presence is one of those scopes, for the fields the detection
        reads by value.** When the same event code arrives from two datasets and
        only one carries those fields, a precondition of the code alone counts
        both copies and reports that the spec examined twice the documents it
        could ever match. So the detection's :meth:`Detection.required_fields`
        are required of the precondition too — every one of them, since ``all``
        is a conjunction — and at least one of its
        :meth:`Detection.alternative_fields`, since ``any`` is a disjunction and
        a document carrying none of its fields cannot satisfy a single branch.
        The second half is the one a spec can be written entirely around: put
        the whole discriminator in ``any``, as the DCSync spec does, and the
        ``all`` block is the bare event code, which both copies carry.

        An exclusion's field is deliberately not one of them. A document that
        lacks it is inside the population and undecidable, not outside it, so
        requiring it here would shrink the denominator by exactly the documents
        ``undecided=True`` exists to count. That was the shape of the miss: on
        the 4624 reconstruction the precondition fell to 182 documents, which is
        greater than zero, so the run was not blind and reported clean over
        5,240 discarded ones.

        ``undecided=True`` compiles the third question. Which documents satisfy
        the positive clauses, fire no exclusion whose field they carry, and are
        missing at least one field an exclusion reads. Those are neither matched
        nor droppable; :mod:`soc_ai.hunting.execute` counts them so a run can
        never claim clean over them.
        """
        if precondition and undecided:
            raise ValueError(
                "precondition and undecided are different questions over different "
                "trees and cannot be compiled into one query"
            )
        if self.detection is None:
            # A ``profile`` spec compiles to no query at all: it is answered
            # from the entity's stored baseline, not from a search. Raising
            # here rather than returning an empty query, because an empty query
            # matches everything and a caller that reached this line has
            # confused the two evaluators.
            raise ValueError(
                f"spec {self.id!r} uses the {self.evaluator!r} evaluator and has no "
                "detection to compile; it is answered from the entity profile, not "
                "from a query"
            )

        tree = self.precondition if precondition else self.detection
        if tree is None:
            raise ValueError(f"spec {self.id!r} has no precondition to compile")

        undecidable = self.detection.exclusion_fields()
        if undecided and not undecidable:
            raise ValueError(
                f"spec {self.id!r} has no exclusion that can go unevaluated, so an "
                "undecided query would return the detection's own matches a second time"
            )

        inner = tree.to_es(presence=not undecided)["bool"]
        must_not = list(inner.get("must_not", []))
        must_not += synth_scope_must_not(include_synth)
        must_not += provenance_must_not(self.provenance, extra_replay_tags=extra_replay_tags)

        filters = list(inner.get("filter", []))
        if precondition:
            implied = set(tree.required_fields())
            filters += [
                {"exists": {"field": f}}
                for f in self.detection.required_fields()
                if f not in implied
            ]
            # The same scope for the ``any`` block, in the shape that block
            # actually asserts: at least one of the fields its branches read.
            # A document carrying none of them is a decided non-match, so
            # counting it in the denominator reports an examination that could
            # not have happened. See Detection.alternative_fields.
            #
            # Skipped WHOLE when the precondition already pins one of them by
            # value, because that clause satisfies the disjunction on its own.
            # Dropping just the pinned field and requiring the rest would turn
            # "at least one of these" into "one of the others", which is a
            # narrower question than either block asks.
            alternatives = self.detection.alternative_fields()
            if alternatives and not implied.intersection(alternatives):
                filters.append(
                    {
                        "bool": {
                            "should": [{"exists": {"field": f}} for f in alternatives],
                            "minimum_should_match": 1,
                        }
                    }
                )
        if undecided:
            # "At least one of them missing", not "all of them missing": one
            # unevaluated exclusion is enough to make the verdict unsafe, and a
            # spec with two of them would otherwise report only the documents
            # that happened to lack both.
            filters.append(
                {
                    "bool": {
                        "should": [
                            {"bool": {"must_not": [{"exists": {"field": f}}]}} for f in undecidable
                        ],
                        "minimum_should_match": 1,
                    }
                }
            )

        window_since = self.precondition_since(since) if precondition else since
        bool_q: dict[str, Any] = {
            "filter": [*filters, {"range": {"@timestamp": {"gte": window_since, "lte": until}}}]
        }
        if "should" in inner:
            bool_q["should"] = inner["should"]
            bool_q["minimum_should_match"] = inner["minimum_should_match"]
        if must_not:
            bool_q["must_not"] = must_not
        return {"bool": bool_q}


def parse_spec(text: str, *, expected_id: str | None = None) -> HuntSpec:
    """Validate one spec from YAML text.

    ``expected_id`` is the filename stem of a shipped spec. A local analytic
    has no file, so its caller passes None and the id in the text stands.

    Text that does not parse raises ValueError. The parser raises
    ``yaml.YAMLError``, which is not a ValueError, so a typo in an analyst's
    YAML reached the route as an unhandled exception and the app answered 500.
    The parser's own message carries the line and the column, and it is kept.
    """
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"the YAML does not parse: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("a spec must be a YAML mapping")
    if isinstance(data.get("title"), str):
        # A title is a label. A full stop at its end lands in every sentence
        # that quotes it ("…controller.: localuser").
        data["title"] = data["title"].strip().rstrip(".")
    spec = HuntSpec.model_validate(data)
    if expected_id is not None and spec.id != expected_id:
        raise ValueError(
            f"spec id {spec.id!r} does not match the filename stem {expected_id!r}. "
            "They are kept identical so a finding's spec_id names the file that "
            "produced it without a lookup."
        )
    return spec


def load_spec(path: Path) -> HuntSpec:
    """Load and validate one spec file."""
    try:
        return parse_spec(path.read_text(), expected_id=path.stem)
    except ValidationError:
        # Pydantic's own report names the field, the rule and the value it
        # read. A plain ValueError wrapped around it keeps the filename and
        # loses all three, and the filename is already in the traceback.
        raise
    except ValueError as exc:
        raise ValueError(f"{path.name}: {exc}") from exc


# Where the shipped specs live. The sweep loop, the CLI and the catalog route
# all mean this directory when they say "the catalog".
CATALOG_DIR = Path(__file__).resolve().parent / "catalog"


def load_catalog(directory: Path) -> dict[str, HuntSpec]:
    """Load every ``*.yaml`` in ``directory``, keyed by spec id.

    Raises on the first invalid spec rather than skipping it. A catalog that
    quietly drops a spec would report a clean sweep it never ran.
    """
    catalog: dict[str, HuntSpec] = {}
    for path in sorted(directory.glob("*.yaml")):
        spec = load_spec(path)
        if spec.id in catalog:
            raise ValueError(f"duplicate spec id {spec.id!r}")
        catalog[spec.id] = spec
    return catalog


__all__ = [
    "CATALOG_DIR",
    "DEFAULT_TOP_K",
    "MAX_CANDIDATES",
    "MAX_CLAUSES",
    "MAX_PRECONDITION_LOOKBACK_MINUTES",
    "Absent",
    "Clause",
    "Detection",
    "HuntSpec",
    "ProfileTest",
    "load_catalog",
    "load_spec",
    "parse_spec",
]
