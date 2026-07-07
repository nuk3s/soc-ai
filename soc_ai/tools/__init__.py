"""Tool functions exposed to the agent and MCP server (read + write surface).

Importing this package also imports every tool module so their ``@tool``
decorators populate the registry. Don't remove the explicit imports unless
you're moving registration elsewhere.
"""

# Force registration on package import.
from soc_ai.tools import (  # noqa: F401
    ack_alert,
    add_case_comment,
    cvedb,
    enrichment,
    escalate_to_case,
    get_alert_context,
    get_playbooks,
    greynoise,
    host_summary,
    lookup_runbook,
    prevalence,
    query_cases,
    query_detections,
    query_events,
    query_zeek,
    rule_prevalence,
    rule_tuning,
    shodan_host,
    shodan_internetdb,
)
from soc_ai.tools._registry import (
    ToolSpec,
    get_tool,
    list_tools,
    tool,
)

__all__ = [
    "ToolSpec",
    "get_tool",
    "list_tools",
    "tool",
]
