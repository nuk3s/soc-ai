"""Canned chat replies for demo mode — no LLM, no egress.

Looks up a scripted assistant answer for an investigation/hunt id from the
demo fixture set's ``chats[]`` section; falls back to a generic, honestly
demo-labelled answer when a specific one isn't authored.
"""

from __future__ import annotations

from typing import Any

_FALLBACK = (
    "This is a recorded demo, so I can't run a live analysis here. In a real "
    "deployment I'd pull the PCAP, check destination reputation, and cite the "
    "specific events behind the verdict. Explore the seeded investigations and "
    "hunts to see full recorded reasoning."
)


def canned_reply(fixtures: dict[str, Any] | None, target: str, target_id: str) -> str:
    """The scripted assistant answer for (target, id), or the generic fallback.

    Never raises: a missing/None fixture set, a ``chats`` section that is absent
    or explicitly ``None``, or an unseeded id all resolve to the generic
    demo-labelled fallback string.
    """
    for entry in (fixtures or {}).get("chats") or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("target") == target and entry.get("id") == target_id:
            for msg in reversed(entry.get("messages", []) or []):
                if isinstance(msg, dict) and msg.get("role") == "assistant" and msg.get("content"):
                    return str(msg["content"])
    return _FALLBACK
