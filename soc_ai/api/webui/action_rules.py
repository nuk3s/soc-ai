"""Whether the console may execute a recommended action, and why not.

One rule for every surface that offers or counts a write: the action card of
the run page, the row of the pending-action list, the needs-you count and the
execute route. The verify of 2026-10-20 (V3-N2) found the surfaces apart. The
row and the server refused "Escalate to case" on a lead run, and on an alert
run that a promoted lead anchors. The run page offered the same write enabled,
because it read the kind of the run and nothing else. The row then gave the
reason of a promoted finding for a real alert (V3-N3).

The anchor rule refuses a write on the alert of a run only when the anchor is
not a Security Onion alert (:mod:`soc_ai.webui.anchor_check`). The callers
read the answer of the grid into :attr:`ActionFacts.anchor_status`.

:func:`action_block` holds every rule. Each rule has its own sentence, and the
sentence states the fact first and the reason second. The callers gather the
facts of the run into :class:`ActionFacts` with the reads they already make.

A promoted finding has no alert, and one write needs none. Security Onion
creates a case from a title and a description, so "Escalate to case" on a
finding run opens a case from the stored finding
(:func:`soc_ai.api.webui.routes_actions._open_finding_case`). The review of
2026-11-13 found a true positive finding, "a working exploit chain", whose
only action was off. The acknowledge of a finding and every write of a
promoted lead stay off: a lead run judges a whole hunt and names no one
finding.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, replace
from typing import Any

from soc_ai.api.webui._timeline import _ACTION_TAG, REPLAY_ACTION_NOTE, analyst_verdict_block
from soc_ai.tools.write_exec import WRITE_TOOLS
from soc_ai.webui import anchor_check

# The codes the execute route answers with. A code that existed before this
# module keeps its old value, so a client that reads the code keeps working.
CODE_REPLAY = "backtest_replay"
CODE_SUPERSEDED = "superseded"
CODE_NOT_A_WRITE = "not_executable"
CODE_PROMOTED = "hunt_kind_no_so_target"
CODE_ANCHORED = "hunt_kind_no_so_target"
CODE_ANCHOR_UNREAD = "anchor_unread"
CODE_NO_ALERT = "missing_alert_id"
CODE_ANALYST = "analyst_verdict"
CODE_NO_CASE = "no_case_for_comment"
CODE_AUTHORIZED = "authorized_activity"
CODE_DEMO = "demo_mode"
# An investigation that a campaign holds. Its Escalate is blocked: the
# campaign opens the one case (soc_ai/api/webui/routes_campaign_case.py). Its
# other actions stay executable and carry the note of the same code.
CODE_CAMPAIGN = "campaign"

NOT_A_WRITE = "soc-ai cannot execute this action type."
PROMOTED_FINDING = "A promoted finding has no Security Onion alert to act on."
PROMOTED_LEAD = "A promoted lead has no Security Onion alert to act on."
# The sentence names a document: the alert feed does not hold it, or the grid
# did not answer and soc-ai cannot tell. Both refusals use it.
ANCHOR_DOCUMENT_SENTENCE = {
    "finding": "A promoted finding uses this document as its anchor.",
    "lead": "A promoted lead uses this document as its anchor.",
}
ANCHOR_SENTENCE = ANCHOR_DOCUMENT_SENTENCE
ANCHOR_REASON = "The document is not a Security Onion alert."
# The refusal of an ack by id that names more than one anchor.
ANCHORS_REFUSAL = (
    "A promoted finding or lead uses each of these documents as its anchor. "
    "The documents are not Security Onion alerts."
)
ANCHOR_UNREAD = "soc-ai could not read the anchor document. Try again when the grid answers."
# The escalate of a promoted finding attaches the alerts among the documents
# the finding cites. The grid did not say which of them are alerts.
FINDING_UNREAD = (
    "soc-ai could not read the documents that the finding cites. Try again when the grid answers."
)
NO_ALERT = "The investigation names no Security Onion alert."
# The tools that open or feed a case. A run inside an authorized scope
# requests no case, so the rule closes these two and leaves the acknowledge.
CASE_TOOLS = ("escalate_to_case", "add_case_comment")
NO_CASE = "This investigation opened no Security Onion case. Escalate the alert first."
# The words of the console's own demo note (frontend/src/lib/demo.tsx).
DEMO_NOTE = "The read-only demo blocks this action. A live deployment runs it."

# The kinds of anchor :func:`soc_ai.store.investigations.hunt_anchor_kinds`
# names. A lead is a hunt subject with kind "lead". Every other promotion is a
# finding.
ANCHOR_FINDING = "finding"
ANCHOR_LEAD = "lead"


def superseded_sentence(newer: str) -> str:
    """The reason of the superseded rule: the run that replaced this run."""
    return f"Investigation {newer} replaced this one. Act on that investigation."


def authorized_sentence(label: str) -> str:
    """The reason of the authorized activity rule: the authorization of the run."""
    return (
        f'This investigation matches the authorized activity "{label}". '
        "soc-ai requests no case for it."
    )


# The reason of the Escalate of an investigation that a campaign holds.
CAMPAIGN_CASE = "Open the case on the campaign."


def campaign_sentence(title: str, decided: str | None = None) -> str:
    """The note of an action of an investigation that a campaign holds.

    ``decided`` is :func:`campaign_decided_sentence` when a decision is in
    force on the campaign: the campaign then asks for nothing.
    """
    if decided:
        return f"Part of the campaign {title}. {decided}"
    return f"Part of the campaign {title}. Decide on the campaign."


# The words of a decision in force, by its type (round "decide once" part 2,
# OW4). The words of the lead page (leadCampaignDecisionSentence in the
# console) are the same.
_DECIDED_WORDS = {
    "closed": "The analyst closed the campaign",
    "authorized": "The analyst authorized the activity of the campaign",
    "case": "The analyst opened a case for the campaign",
}
NO_ACTION_WAITS = "No action waits."


def campaign_decided_sentence(decision: str | None, decided_at: Any = None) -> str | None:
    """ "The analyst closed the campaign on {date}. No action waits.", or None.

    None when no decision is in force. An investigation of a decided
    campaign showed "Open the case on the campaign." and a next step that
    asked for an escalate (dogfood 2026-11-17, N12). ``decided_at`` is a
    naive UTC datetime or an ISO string. The time reads in UTC, the form of
    the investigation page.
    """
    head = _DECIDED_WORDS.get(decision or "")
    if head is None:
        return None
    when = _utc_words(decided_at)
    return f"{head}{f' on {when}' if when else ''}. {NO_ACTION_WAITS}"


def _utc_words(at: Any) -> str | None:
    """A time as "2026-11-15 14:02 UTC", or None."""
    from datetime import UTC, datetime  # noqa: PLC0415 - light import

    value = at
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is not None:
        value = value.astimezone(UTC).replace(tzinfo=None)
    return value.strftime("%Y-%m-%d %H:%M UTC")


@dataclass(frozen=True)
class ActionFacts:
    """What the rules read about one run.

    ``promoted`` is "finding" or "lead" when a promotion landed the run
    itself, else None. ``anchor`` is "finding" or "lead" when a promoted run
    uses the alert of this run as its anchor. ``anchor_status`` is the
    answer of :func:`soc_ai.webui.anchor_check.alert_status` for that
    document. The default refuses, so a caller that does not ask the grid
    keeps the refusal. ``analyst_verdict`` and
    ``analyst_by`` are the analyst verdict that stands on the alert over
    every run of it. ``case_id`` is the case this run opened, the only case a
    comment may target. ``authorized`` is the label of the authorized activity
    the run matched, while that mark holds
    (:func:`soc_ai.store.authorized_activity.marks_for`). None after a revoke.
    ``campaign_id`` and ``campaign_title`` name the campaign that holds the
    run (:func:`soc_ai.campaigns.service.held`): the analyst decides on the
    campaign. None for a run in no campaign and for a run whose verdict
    differs.
    """

    replay: bool = False
    superseded_by: str | None = None
    promoted: str | None = None
    anchor: str | None = None
    anchor_status: str = anchor_check.NOT_ALERT
    alert_id: str | None = None
    run_verdict: str | None = None
    analyst_verdict: str | None = None
    analyst_by: str | None = None
    case_id: str | None = None
    authorized: str | None = None
    demo: bool = False
    campaign_id: int | None = None
    campaign_title: str | None = None
    # The decision in force on that campaign and its time, else None (OW4).
    campaign_decision: str | None = None
    campaign_decided_at: Any = None


def with_campaign(facts: ActionFacts, link: Any) -> ActionFacts:
    """``facts`` with the campaign that holds the run, from its campaign link.

    ``link`` is a :class:`soc_ai.campaigns.service.CampaignLink` or a
    ``CampaignLinkOut``, or None. A link whose verdict differs holds nothing,
    so the run keeps its own place in Needs you. A run beyond the
    authorization of its campaign is held by nothing too: its actions wait.
    """
    if link is None or bool(getattr(link, "differs", True)) or bool(getattr(link, "beyond", False)):
        return facts
    decision = getattr(link, "decision", None)
    return replace(
        facts,
        campaign_id=int(link.id),
        campaign_title=str(link.title),
        campaign_decision=decision if isinstance(decision, str) and decision else None,
        campaign_decided_at=getattr(link, "decided_at", None) or getattr(link, "decidedAt", None),
    )


@dataclass(frozen=True)
class ActionBlock:
    """A rule that fired: its code for the execute route, and its sentence."""

    code: str
    reason: str


def promoted_kind(run: object) -> str | None:
    """'lead' or 'finding' when a promotion landed this run, else None."""
    from soc_ai.store import investigations as inv_svc  # noqa: PLC0415 - light import

    if not inv_svc.is_promoted(run):
        return None
    return ANCHOR_LEAD if getattr(run, "kind", None) == "lead" else ANCHOR_FINDING


def action_block(facts: ActionFacts, tool_name: str | None) -> ActionBlock | None:
    """The first rule that keeps the console from executing the action, or None.

    ``tool_name`` None asks about the run alone: the rules that hold for every
    action of the run. The order puts the rule that explains the most first.
    A replay and a superseded run close every action. A promotion has no
    alert, so it closes every write that needs one. The escalate of a
    promoted finding needs none (:func:`opens_finding_case`). The anchor of a
    promotion closes every action when it is not a Security Onion alert, or
    when the grid did not answer. A run inside an authorized scope requests
    no case. The Escalate of a run that a campaign holds is blocked: the
    campaign opens the one case. A write needs an alert, may not act against
    an analyst verdict, and a comment needs the case this run opened. The demo
    blocks the rest.
    """
    if facts.replay:
        return ActionBlock(CODE_REPLAY, REPLAY_ACTION_NOTE)
    if facts.superseded_by:
        return ActionBlock(CODE_SUPERSEDED, superseded_sentence(facts.superseded_by))
    if tool_name is not None and tool_name not in WRITE_TOOLS:
        return ActionBlock(CODE_NOT_A_WRITE, NOT_A_WRITE)
    finding_case = opens_finding_case(facts, tool_name)
    if facts.promoted and not finding_case:
        lead = facts.promoted == ANCHOR_LEAD
        return ActionBlock(CODE_PROMOTED, PROMOTED_LEAD if lead else PROMOTED_FINDING)
    if facts.anchor and facts.anchor_status != anchor_check.ALERT:
        if facts.anchor_status == anchor_check.UNKNOWN:
            head = ANCHOR_SENTENCE.get(facts.anchor, ANCHOR_SENTENCE[ANCHOR_FINDING])
            return ActionBlock(CODE_ANCHOR_UNREAD, f"{head} {ANCHOR_UNREAD}")
        return ActionBlock(CODE_ANCHORED, anchor_refusal(facts.anchor))
    if facts.authorized and tool_name in CASE_TOOLS:
        return ActionBlock(CODE_AUTHORIZED, authorized_sentence(facts.authorized))
    if facts.campaign_id is not None and tool_name == "escalate_to_case":
        # One campaign gets one case. An investigation beyond an
        # authorization and one in no campaign carry no campaign here. A
        # campaign with a decision in force asks for nothing.
        decided = campaign_decided_sentence(facts.campaign_decision, facts.campaign_decided_at)
        return ActionBlock(CODE_CAMPAIGN, decided or CAMPAIGN_CASE)
    if tool_name is not None:
        needs_alert = tool_name in ("ack_alert", "escalate_to_case") and not finding_case
        if needs_alert and not facts.alert_id:
            return ActionBlock(CODE_NO_ALERT, NO_ALERT)
        against = analyst_verdict_block(
            _ACTION_TAG.get(tool_name, "comment"),
            facts.run_verdict,
            facts.analyst_verdict,
            facts.analyst_by,
        )
        if against:
            return ActionBlock(CODE_ANALYST, against)
        if tool_name == "add_case_comment" and not facts.case_id:
            return ActionBlock(CODE_NO_CASE, NO_CASE)
    if facts.demo:
        return ActionBlock(CODE_DEMO, DEMO_NOTE)
    return None


def opens_finding_case(facts: ActionFacts, tool_name: str | None) -> bool:
    """Whether this action is the escalate of a promoted finding.

    That escalate opens a case from the stored finding and needs no alert. It
    is the one write a promoted run can make. A question about the run alone
    (``tool_name`` None) is not one: the page reads that answer for the writes
    to the alerts of a rule, and a finding has no rule.
    """
    return facts.promoted == ANCHOR_FINDING and tool_name == "escalate_to_case"


def anchor_refusal(anchor: str) -> str:
    """The sentence of the anchor rule for a document outside the alert feed.

    ``anchor`` is "finding" or "lead", the promotion that uses the document
    as its anchor.
    """
    head = ANCHOR_DOCUMENT_SENTENCE.get(anchor, ANCHOR_DOCUMENT_SENTENCE[ANCHOR_FINDING])
    return f"{head} {ANCHOR_REASON}"


def block_reason(facts: ActionFacts, tool_name: str | None) -> str | None:
    """The sentence of :func:`action_block`, or None when the action may run."""
    block = action_block(facts, tool_name)
    return block.reason if block is not None else None


# The investigation event of an acknowledge or an escalate that the analyst
# made from the card "No automatic action" of the run page (round "decide
# once" part 2, OW1). The card writes through the group routes of the Alerts
# console, and before this record nothing in the store tied the press to the
# investigation. The payload holds ``action`` ("ack" or "escalate"), ``by``,
# ``at`` and ``alerts``: the alerts that Security Onion holds acknowledged or
# on a case after the press.
SETTLED_EVENT = "analyst_settled"

# The verdict whose recommended actions can wait for a person. A false
# positive recommends an acknowledgement, and that housekeeping would drown
# Needs you. A needs-more-info verdict recommends nothing.
WAITING_VERDICT = "true_positive"


def run_requests(run: object) -> bool:
    """Whether the actions of a run can wait for a person: the run half of the rule.

    A complete true positive that is no pipeline fallback, no synthetic run
    and no backtest replay. The needs-you count reads the same facts in SQL
    (:func:`soc_ai.api.webui.routes_meta.needs_you_runs`), and the hunt page
    reads them for the investigation of each finding. The action half is
    :func:`action_waits`. The run page stated "1 action waits for you" on a
    false positive with an open acknowledge, and Needs you held none of them:
    10 of 19 open detections at 24 hours (macro review 2026-11-17, m14).
    """
    from soc_ai.store import investigations as inv_svc  # noqa: PLC0415 - light import

    return (
        getattr(run, "status", None) == "complete"
        and getattr(run, "verdict", None) == WAITING_VERDICT
        and getattr(run, "is_fallback", None) is not True
        and getattr(run, "is_synth_eval", None) is not True
        and not inv_svc.is_backtest(run)
    )


def analyst_decided(
    run: object,
    actions: Sequence[tuple[Any, str]],
    facts: ActionFacts,
    *,
    settled: bool,
) -> bool:
    """Whether the analyst decided on the investigation itself: the part ``handled``.

    Round "decide once" part 2 (OW1). A run with an open action that the
    console can execute is no decision: the write waits for a person. Else
    each of three facts gives a decision:

    * the report holds an analyst resolution (a chat resolve or an override);
    * the run has one or more recommended actions that the console can
      execute, and the analyst applied or dismissed each of them;
    * the run has no such action, and the analyst acknowledged or escalated
      its alert (``settled``: the record of the card "No automatic action",
      or a row of the escalation ledger).

    ``actions`` holds each recommended action with its tool name: an object
    with ``applied`` and ``dismissed``. An action that the console can execute
    is a write whose rule lets it run now (:func:`action_block`, the demo
    aside), or a write that is already applied or dismissed. A blocked write
    and a text-only action are none: the analyst cannot press them, so they
    decide nothing. Production on 2026-11-17 held a true positive with a
    resolution and three text-only actions, and the tile said that it waited.

    A resolution does not close an open write. A chat resolve can write the
    actions of its proposal, and an analyst who sets a true positive has not
    yet decided on the escalate that the verdict recommends.
    """
    from soc_ai.store import investigations as inv_svc  # noqa: PLC0415 - light import

    live = replace(facts, demo=False)
    can_execute = [
        action
        for action, tool_name in actions
        if tool_name in WRITE_TOOLS and (_closed(action) or action_block(live, tool_name) is None)
    ]
    if not all(_closed(action) for action in can_execute):
        return False
    return inv_svc.analyst_resolution(run) is not None or bool(can_execute) or settled


def _closed(action: Any) -> bool:
    """True when the analyst or soc-ai applied the action, or the analyst dismissed it."""
    return bool(getattr(action, "applied", False)) or bool(getattr(action, "dismissed", False))


def action_waits(facts: ActionFacts, tool_name: str | None) -> bool:
    """Whether an open action waits for a person: the needs-you rule.

    An action the console cannot execute waits for no one. A run inside an
    authorized scope requests nothing, so none of its actions waits. Its
    acknowledge stays on the run page, and the analyst can still press it.
    A run that a campaign holds waits on the campaign, so none of its actions
    waits. The actions stay executable (:func:`action_note`).
    """
    if facts.authorized or facts.campaign_id is not None:
        return False
    return action_block(facts, tool_name) is None


def action_note(facts: ActionFacts) -> ActionBlock | None:
    """The note of an action that stays executable and waits on no one, or None.

    The one note: the run is part of a campaign, and the analyst decides on
    the campaign. The code is :data:`CODE_CAMPAIGN`. The Escalate of such a
    run is blocked by :func:`action_block` with the same code.
    """
    if facts.campaign_id is None:
        return None
    decided = campaign_decided_sentence(facts.campaign_decision, facts.campaign_decided_at)
    return ActionBlock(CODE_CAMPAIGN, campaign_sentence(facts.campaign_title or "", decided))
