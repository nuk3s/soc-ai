"""Declarative hunt specs: a hunt as a document rather than a conversation.

Every hunt soc-ai runs today spends a language model on the whole objective.
That is the right shape when an analyst types a question in English, and the
wrong shape for a condition somebody already knows how to describe exactly.
It puts a floor under what a hunt costs, and a ceiling on how often one can run.

A :class:`~soc_ai.hunting.spec.HuntSpec` is the other shape. It compiles to one
bounded Elasticsearch query, runs without a model, and produces candidates a
model can be spent on afterwards if any survive. The point is not to replace the
agent; it is to stop paying agent prices to learn that nothing happened.

The case that motivated it: on the development range a DCSync, Kerberoasting and
AS-REP roasting chain ran to completion and produced no alert an analyst would
ever see. The detection for DCSync is one predicate over documents that were
already on disk — a replication-right GUID with machine accounts excluded, which
returns 2 documents out of 23 million at 100% precision. There is no threshold
in that and there could not be, because the benign baseline is 36 documents.
Statistics are the minority case here; predicates are the majority.
"""

from __future__ import annotations
