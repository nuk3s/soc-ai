"""Campaigns: one activity as a set of runs that proven links join.

The design is ``docs/superpowers/specs/2026-11-13-campaign-design.md``.

* :mod:`soc_ai.campaigns.types` holds the records.
* :mod:`soc_ai.campaigns.artifacts` holds the text rules of an artifact.
* :mod:`soc_ai.campaigns.engine` joins the facts of the runs into campaigns.
  It is pure: no store, no grid, no clock.
* :mod:`soc_ai.campaigns.words` writes the title and the bottom line.
* :mod:`soc_ai.campaigns.facts` reads the facts of one stored run.
* :mod:`soc_ai.campaigns.service` writes the campaigns and reads them.

Code decides membership. The model writes no campaign. A hunt reads the
stored facts of a campaign in its campaign block
(:mod:`soc_ai.hunting.campaign_block`).
"""
