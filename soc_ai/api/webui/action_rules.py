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
"""

from __future__ import annotations

from dataclasses import dataclass

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
CODE_DEMO = "demo_mode"

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
NO_ALERT = "The investigation names no Security Onion alert."
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
    return f"Investigation {newer} replaced this run. Act on that run."


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
    comment may target.
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
    demo: bool = False


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
    alert. The anchor of a promotion closes every action when it is not a
    Security Onion alert, or when the grid did not answer. A write needs an
    alert, may not act against an analyst verdict, and a comment needs the
    case this run opened. The demo blocks the rest.
    """
    if facts.replay:
        return ActionBlock(CODE_REPLAY, REPLAY_ACTION_NOTE)
    if facts.superseded_by:
        return ActionBlock(CODE_SUPERSEDED, superseded_sentence(facts.superseded_by))
    if tool_name is not None and tool_name not in WRITE_TOOLS:
        return ActionBlock(CODE_NOT_A_WRITE, NOT_A_WRITE)
    if facts.promoted:
        lead = facts.promoted == ANCHOR_LEAD
        return ActionBlock(CODE_PROMOTED, PROMOTED_LEAD if lead else PROMOTED_FINDING)
    if facts.anchor and facts.anchor_status != anchor_check.ALERT:
        if facts.anchor_status == anchor_check.UNKNOWN:
            head = ANCHOR_SENTENCE.get(facts.anchor, ANCHOR_SENTENCE[ANCHOR_FINDING])
            return ActionBlock(CODE_ANCHOR_UNREAD, f"{head} {ANCHOR_UNREAD}")
        return ActionBlock(CODE_ANCHORED, anchor_refusal(facts.anchor))
    if tool_name is not None:
        if tool_name in ("ack_alert", "escalate_to_case") and not facts.alert_id:
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
