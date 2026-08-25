"""The detection-engineering bridge.

Drafts a Sigma rule from a confirmed hunt finding, validates it
deterministically, and exports it for the human to paste into Security
Onion's Detections module. This module never writes to SO — detection stays
in SO; soc-ai only drafts, validates, and hands the analyst something to
copy.
"""

from __future__ import annotations
