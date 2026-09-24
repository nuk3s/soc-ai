"""Shared Elasticsearch behaviour for the audit-chain test doubles.

The audit logger claims each seq by creating a document at a deterministic
``_id`` (``soc_ai.audit.logger._doc_id``) with ``op_type=create``, and reads
back the run of ids around a refused claim with a realtime multi-get. A double
that ignores either one is not modelling the grid the code is written against
— it would accept a duplicate the real cluster refuses — so the pieces live
here once and every double composes them.
"""

from __future__ import annotations

from typing import Any

from elastic_transport import ApiResponseMeta, HttpHeaders
from elasticsearch import ConflictError


def _meta(status: int) -> ApiResponseMeta:
    return ApiResponseMeta(
        status=status,
        http_version="1.1",
        headers=HttpHeaders({}),
        duration=0.0,
        node=None,  # type: ignore[arg-type]
    )


def conflict_error() -> ConflictError:
    """The exception elasticsearch-py raises for a create on an existing ``_id``.

    The real class, not a stand-in: recognising the grid's version conflict is
    the mechanism under test, and a bespoke exception would let that
    recognition rot the moment the client changes shape.
    """
    return ConflictError(
        "version_conflict_engine_exception",
        meta=_meta(409),
        body={"error": {"type": "version_conflict_engine_exception"}},
    )


class CreateSemantics:
    """Per-(index, ``_id``) store with create-refusal and realtime multi-get."""

    def __init__(self) -> None:
        self.by_id: dict[tuple[str, str], dict[str, Any]] = {}

    def claim(
        self,
        index: str,
        doc_id: str | None,
        op_type: str | None,
        body: dict[str, Any],
    ) -> None:
        """Record the document, refusing a create at an id that already exists."""
        if doc_id is None:
            return
        key = (index, doc_id)
        if op_type == "create" and key in self.by_id:
            raise conflict_error()
        self.by_id[key] = dict(body)

    def mget(self, index: str, ids: list[str]) -> dict[str, Any]:
        """A realtime multi-get response over this store."""
        docs: list[dict[str, Any]] = []
        for doc_id in ids:
            key = (index, doc_id)
            if key in self.by_id:
                docs.append({"_id": doc_id, "found": True, "_source": dict(self.by_id[key])})
            else:
                docs.append({"_id": doc_id, "found": False})
        return {"docs": docs}
