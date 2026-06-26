"""``get_playbooks`` tool - retrieve SOC playbooks (and their checklist questions).

When ``alert_id`` is provided, only return playbooks whose ``linkedRules``
field references the alert's ``rule.uuid``. When omitted, return up to
``max_results`` playbooks ordered by recency.
"""

from __future__ import annotations

from typing import Any

from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.so_client.models import SoAlert, SoPlaybook
from soc_ai.tools._registry import tool


@tool(read_only=True, description="Pull playbooks; optionally scoped to a given alert.")
async def get_playbooks(
    *,
    elastic: ElasticClient,
    settings: Settings,
    alert_id: str | None = None,
    max_results: int = 25,
) -> list[SoPlaybook]:
    """Pull playbooks, optionally scoped to those linked to a given alert's rule.

    Args:
        elastic: client for the SO ES cluster.
        settings: app settings (uses ``events_index_pattern`` for the alert
            lookup and ``playbooks_index_pattern`` for the playbook search).
        alert_id: when provided, fetch the alert, read ``rule.uuid``, and
            return only playbooks linking that rule. If the alert isn't found
            or has no rule UUID, returns ``[]``.
        max_results: hard cap on returned playbooks.
    """
    if max_results <= 0:
        raise ValueError(f"max_results must be positive, got {max_results}")

    es_query: dict[str, Any]

    if alert_id is not None:
        alert_lookup = await elastic.search(
            settings.events_index_pattern,
            {"ids": {"values": [alert_id]}},
            size=1,
        )
        if not alert_lookup.hits:
            return []
        alert = SoAlert.from_es_hit(alert_lookup.hits[0])
        if not alert.rule_uuid:
            return []
        es_query = {"term": {"linkedRules": alert.rule_uuid}}
    else:
        es_query = {"match_all": {}}

    result = await elastic.search(
        settings.playbooks_index_pattern,
        es_query,
        size=max_results,
    )
    return [SoPlaybook.from_so_doc(h.get("_source", {})) for h in result.hits]
