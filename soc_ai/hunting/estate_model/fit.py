"""Fit the estate model: standardize, group, score, explain and measure drift.

This module imports numpy, scipy and scikit-learn at the top. Import it only
after :func:`soc_ai.hunting.estate_model.load_ml` returned the extra. Every
value it returns is a builtin type, so the callers and the store never hold a
numpy object.

**Two key spaces.** The profile store keys the flow and DNS planes on the
address of a host and the process and logon planes on its ``host.name``. A
vector of one space holds zeros in every column of the other. The model fits
each space apart: one standardization, one set of groups and one forest per
space. A space with fewer than 20 hosts forms one group and is not scored.

**Standardize.** Each column is centred on its mean in the space and divided
by its standard deviation in the space. A constant column keeps a scale of 1.

**Peer groups: k-means, k chosen by silhouette.** k runs from 2 to 10, never
past the host count less one. Each k is fitted with 4 seeded starts. A
cluster under 5 hosts is folded into the nearest larger one, because k-means
gives a far outlier a cluster of its own, and a group of one has no peers.
The silhouette score of the folded partition, on a seeded sample of at most
2,000 hosts, picks k. A tie goes to the smaller k.

k-means is the one method here, for three reasons. Every host gets a group,
and a host with no group has no peers. Each group has a centroid, and the
reason on an observation needs a peer value to state. The same data with the
same seed gives the same groups. HDBSCAN (in scikit-learn since 1.3) leaves
the hosts it calls noise without a group, so such a host would have no peer
value to state.

The group ids carry over from the previous fit. The new centroids of a space
are matched to the old centroids of the same space with the Hungarian method.
A match within an RMS distance of 1 standard deviation keeps the old id. A
new group takes an id above every id the previous fit used.

**Outlier score: isolation forest.** 200 trees, a sample of at most 256 hosts
per tree, a fixed seed. The score is the forest's anomaly score, from 0 to 1.
Near 0.5 is ordinary. The forest needs no assumption about the shape of a
group, and it scores a whole space in one pass. Its score does not split into
named features, so the score alone never becomes an observation.

**The reason: a robust deviation against the group.** For each host and each
feature, the deviation is the distance from the group median, in standardized
units, divided by 1.4826 times the group's median absolute deviation. The
divisor has a floor of 0.5 standard deviations, so a group whose members agree
exactly on a feature does not turn a small move into a large one. The three
largest deviations are the top features. A declared role shapes the groups
and is never a reason: a host is not unusual because an operator named its
role. A host whose largest deviation is under :data:`REASON_MIN_DEVIATION`
has no stated reason, and it writes no observation (condition 1 of decision 3).

**A subgroup is not an outlier.** k-means at the silhouette's k can fold a
subgroup of hosts that act alike into a larger group, and then every member of
the subgroup departs from the group median. A host with 5 other hosts within a
Euclidean distance of 1 standard deviation shares its behaviour with them. It
is counted as shared and writes no observation. The cost: the same change on
5 hosts at once is not an outlier here. A spread across hosts is the work of
the scope count in tier 2 and of the whole-estate review.

**Drift: the population stability index.** Each column of each space is cut
into at most 10 bins at the deciles of the previous fit. The index sums
``(q - p) * ln(q / p)`` over the bins, where ``p`` is the previous share and
``q`` the share today. A share has a floor of 0.0001. A feature that only one
of the two fits holds is not compared.
"""

from __future__ import annotations

import math
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import numpy as np
from scipy.optimize import linear_sum_assignment
from sklearn.cluster import KMeans
from sklearn.ensemble import IsolationForest
from sklearn.metrics import silhouette_score
from sklearn.neighbors import NearestNeighbors

from soc_ai.hunting.estate_model.features import PARTITIONS, Feature, partition_of

__all__ = [
    "DEVIATION_FLOOR",
    "FOREST_SAMPLE",
    "FOREST_TREES",
    "K_MAX",
    "K_MIN",
    "MATCH_MAX_RMS",
    "MIN_GROUP_SIZE",
    "MIN_SCORED_HOSTS",
    "PSI_BINS",
    "RANDOM_STATE",
    "REASON_MIN_DEVIATION",
    "SCORE_THRESHOLD",
    "TOP_FEATURES",
    "TWINS",
    "TWIN_RADIUS",
    "Contribution",
    "EstateFit",
    "GroupFit",
    "HostFit",
    "PartitionFit",
    "fit_estate",
    "population_stability",
]

K_MIN = 2
K_MAX = 10
N_INIT = 4
# The smallest group the model keeps: the peer floor of the profile tests.
MIN_GROUP_SIZE = 5
# Below this many hosts a key space forms one group and the forest does not
# score it. A forest over a handful of hosts isolates every one of them.
MIN_SCORED_HOSTS = 20
SILHOUETTE_SAMPLE = 2000
RANDOM_STATE = 0

FOREST_TREES = 200
FOREST_SAMPLE = 256
# The anomaly score at and above which a host is an outlier. scikit-learn's
# own cut (contamination "auto") is 0.5. 0.55 asks for a host the forest
# isolates clearly, and the stated-reason gate does the rest.
SCORE_THRESHOLD = 0.55

# In standard deviations of the space: the smallest spread a group is given.
DEVIATION_FLOOR = 0.5
# The consistency constant that makes a median absolute deviation estimate a
# standard deviation for normal data.
_MAD_SCALE = 1.4826
REASON_MIN_DEVIATION = 3.0
TOP_FEATURES = 3
# The columns that shape the groups and never count as a reason.
_NOT_A_REASON = "role."
# A host with this many other hosts within this Euclidean distance, in
# standard deviations, shares its behaviour with a subgroup. The subgroup is
# a trait of the estate, and its members are not outliers.
TWINS = MIN_GROUP_SIZE
TWIN_RADIUS = 1.0

PSI_BINS = 10
_PSI_FLOOR = 1e-4

# The largest RMS distance, in standard deviations, at which a new group keeps
# the id of an old one.
MATCH_MAX_RMS = 1.0


@dataclass(frozen=True)
class Contribution:
    """One feature behind a host's score: how far it departs, its value, its peers'."""

    name: str
    deviation: float
    value: float
    peer: float


@dataclass(frozen=True)
class HostFit:
    """What the fit says about one host. ``scored`` is False in an unscored space."""

    entity_key: str
    group_id: int
    distance: float
    score: float
    top: tuple[Contribution, ...]
    scored: bool = True
    # The distance to the fifth nearest other host in the space.
    twin_distance: float = math.inf

    @property
    def explained(self) -> bool:
        """Whether a feature departs from the group far enough to state."""
        return bool(self.top) and self.top[0].deviation >= REASON_MIN_DEVIATION

    @property
    def shared(self) -> bool:
        """Whether a subgroup of other hosts acts the same way."""
        return self.twin_distance <= TWIN_RADIUS


@dataclass(frozen=True)
class GroupFit:
    """One learned group.

    ``centroid`` and ``median`` are in the analyst's units, keyed by feature.
    ``centroid_model`` is the centroid in model units before standardizing, in
    feature order. The next fit matches its groups against it.
    """

    id: int
    partition: str
    size: int
    centroid: dict[str, float]
    median: dict[str, float]
    score_median: float
    centroid_model: list[float]


@dataclass(frozen=True)
class PartitionFit:
    """The scale and the grouping of one key space."""

    name: str
    hosts: int
    mean: list[float]
    scale: list[float]
    k: int
    silhouette: float | None
    scored: bool


@dataclass(frozen=True)
class EstateFit:
    """Everything one fit produced, in builtin types.

    ``histograms`` and ``psi`` are keyed ``<space>/<feature>``.
    """

    feature_names: list[str]
    hosts: list[HostFit]
    groups: list[GroupFit]
    partitions: dict[str, PartitionFit]
    histograms: dict[str, dict[str, list[float]]]
    psi: dict[str, float] = field(default_factory=dict)
    aligned: int = 0
    seconds: float = 0.0

    @property
    def k(self) -> int:
        return len(self.groups)

    @property
    def silhouette(self) -> float | None:
        """The silhouette of the grouped spaces, weighted by their hosts."""
        rated = [p for p in self.partitions.values() if p.silhouette is not None]
        total = sum(p.hosts for p in rated)
        if not total:
            return None
        return sum(float(p.silhouette or 0.0) * p.hosts for p in rated) / total

    def group(self, group_id: int) -> GroupFit | None:
        return next((g for g in self.groups if g.id == group_id), None)


def _standardize(x: Any) -> tuple[Any, Any, Any]:
    mean = x.mean(axis=0)
    std = x.std(axis=0)
    scale = np.where(std > 1e-9, std, 1.0)
    return (x - mean) / scale, mean, scale


def _merge_small(z: Any, labels: Any, centers: Any) -> tuple[Any, Any] | None:
    """Fold every cluster under :data:`MIN_GROUP_SIZE` into the nearest large one.

    k-means gives a far outlier a cluster of its own. A group of one has no
    peers, and its median is the host itself, so nothing about it could ever
    depart. None when fewer than two large clusters remain.
    """
    sizes = np.bincount(labels, minlength=centers.shape[0])
    big = [c for c in range(centers.shape[0]) if sizes[c] >= MIN_GROUP_SIZE]
    if len(big) < 2:
        return None
    kept = centers[big]
    if len(big) == centers.shape[0]:
        return labels, kept
    nearest = np.argmin(np.linalg.norm(z[:, None, :] - kept[None, :, :], axis=2), axis=1)
    index = {c: i for i, c in enumerate(big)}
    merged = np.asarray(
        [index[c] if c in index else int(nearest[i]) for i, c in enumerate(labels.tolist())],
        dtype=int,
    )
    return merged, kept


def _one_group(z: Any) -> tuple[Any, Any, int, float | None]:
    n = int(z.shape[0])
    return np.zeros(n, dtype=int), z.mean(axis=0, keepdims=True), 1, None


def _cluster(z: Any) -> tuple[Any, Any, int, float | None]:
    """Labels, centroids, k and the silhouette of the chosen partition."""
    n = int(z.shape[0])
    distinct = int(np.unique(z, axis=0).shape[0]) if n else 0
    top = min(K_MAX, n - 1, distinct)
    best: tuple[float, int, Any, Any] | None = None
    for k in range(K_MIN, top + 1):
        model = KMeans(n_clusters=k, n_init=N_INIT, random_state=RANDOM_STATE)
        raw_labels = model.fit_predict(z)
        folded = _merge_small(z, raw_labels, model.cluster_centers_)
        if folded is None:
            continue
        labels, centers = folded
        try:
            score = float(
                silhouette_score(
                    z,
                    labels,
                    sample_size=min(n, SILHOUETTE_SAMPLE),
                    random_state=RANDOM_STATE,
                )
            )
        except ValueError:
            continue
        # A tie goes to the smaller k: the loop runs upward and only a
        # strictly better score replaces the best.
        if best is None or score > best[0] + 1e-9:
            best = (score, int(centers.shape[0]), labels, centers)
    if best is None:
        return _one_group(z)
    return best[2], best[3], best[1], best[0]


def _group_ids(
    centers_model: Any,
    sizes: Sequence[int],
    scale: Any,
    names: Sequence[str],
    previous: Mapping[str, Any] | None,
    partition: str,
    next_id: int,
) -> tuple[list[int], int, int]:
    """The id of each new cluster, how many kept an old id, and the next free id."""
    k = int(centers_model.shape[0])
    ids: list[int | None] = [None] * k
    aligned = 0
    prev_groups = [
        g
        for g in list((previous or {}).get("groups") or [])
        if str(g.get("partition", "address")) == partition
    ]
    prev_names = list((previous or {}).get("feature_names") or [])
    common = [name for name in names if name in prev_names]
    if prev_groups and common:
        new_idx = [list(names).index(n) for n in common]
        old_idx = [prev_names.index(n) for n in common]
        old = np.asarray(
            [[float(g["centroid_model"][i]) for i in old_idx] for g in prev_groups], dtype=float
        )
        new = centers_model[:, new_idx]
        div = scale[new_idx]
        cost = np.sqrt((((new[:, None, :] - old[None, :, :]) / div) ** 2).mean(axis=2))
        rows, cols = linear_sum_assignment(cost)
        for r, c in zip(rows.tolist(), cols.tolist(), strict=True):
            if cost[r, c] <= MATCH_MAX_RMS:
                ids[r] = int(prev_groups[c]["id"])
                aligned += 1
    # New groups take new ids, the largest first, then by centroid, so the
    # order does not depend on the label k-means happened to give.
    order = sorted(
        (i for i in range(k) if ids[i] is None),
        key=lambda i: (-int(sizes[i]), tuple(float(v) for v in centers_model[i])),
    )
    for i in order:
        ids[i] = next_id
        next_id += 1
    return [int(i) for i in ids if i is not None], aligned, next_id


def _inverse(features: Sequence[Feature], model_values: Any) -> list[float]:
    out: list[float] = []
    for feature, value in zip(features, model_values.tolist(), strict=True):
        out.append(float(math.expm1(value)) if feature.log else float(value))
    return out


def _histograms(x: Any, names: Sequence[str], prefix: str) -> dict[str, dict[str, list[float]]]:
    quantiles = np.linspace(0.0, 1.0, PSI_BINS + 1)[1:-1]
    out: dict[str, dict[str, list[float]]] = {}
    for j, name in enumerate(names):
        column = x[:, j]
        edges = np.unique(np.quantile(column, quantiles))
        counts = np.bincount(np.searchsorted(edges, column, side="left"), minlength=len(edges) + 1)
        out[f"{prefix}/{name}"] = {
            "edges": [float(e) for e in edges.tolist()],
            "proportions": [float(c) / max(1, len(column)) for c in counts.tolist()],
        }
    return out


def population_stability(
    previous: Mapping[str, Mapping[str, Sequence[float]]],
    x: Any,
    names: Sequence[str],
    prefix: str,
) -> dict[str, float]:
    """The index of each feature both fits hold, today's column against the previous bins."""
    out: dict[str, float] = {}
    for j, name in enumerate(names):
        key = f"{prefix}/{name}"
        hist = previous.get(key)
        if not hist:
            continue
        edges = np.asarray(list(hist.get("edges") or []), dtype=float)
        p = np.asarray(list(hist.get("proportions") or []), dtype=float)
        if p.size != edges.size + 1:
            continue
        column = x[:, j]
        counts = np.bincount(np.searchsorted(edges, column, side="left"), minlength=p.size)
        q = counts / max(1, len(column))
        p = np.maximum(p, _PSI_FLOOR)
        q = np.maximum(q, _PSI_FLOOR)
        out[key] = float(np.sum((q - p) * np.log(q / p)))
    return out


def _top(deviations: Any, raw: Any, peer: Any, names: Sequence[str]) -> tuple[Contribution, ...]:
    order = np.argsort(-deviations, kind="stable")
    out: list[Contribution] = []
    for j in order.tolist():
        if names[j].startswith(_NOT_A_REASON):
            continue
        out.append(
            Contribution(
                name=names[j],
                deviation=float(deviations[j]),
                value=float(raw[j]),
                peer=float(peer[j]),
            )
        )
        if len(out) == TOP_FEATURES:
            break
    return tuple(out)


def _score(z: Any) -> tuple[Any, Any]:
    """The forest's anomaly score and the distance to the fifth nearest host."""
    n = int(z.shape[0])
    forest = IsolationForest(
        n_estimators=FOREST_TREES,
        max_samples=min(FOREST_SAMPLE, n),
        random_state=RANDOM_STATE,
    )
    forest.fit(z)
    # The first neighbour of a host is the host itself.
    near = NearestNeighbors(n_neighbors=min(TWINS + 1, n)).fit(z)
    return -forest.score_samples(z), near.kneighbors(z)[0][:, -1]


@dataclass
class _Space:
    """What the fit of one key space adds to the estate fit."""

    hosts: dict[int, HostFit]
    groups: list[GroupFit]
    partition: PartitionFit
    aligned: int
    next_id: int


def _fit_space(
    space: str,
    index: Sequence[int],
    keys: Sequence[str],
    features: Sequence[Feature],
    x: Any,
    raw: Any,
    *,
    previous: Mapping[str, Any] | None,
    next_id: int,
) -> _Space:
    names = [f.name for f in features]
    n = len(index)
    z, mean, scale = _standardize(x)
    scored = n >= MIN_SCORED_HOSTS
    labels, centers, k, silhouette = _cluster(z) if scored else _one_group(z)
    sizes = [int(np.sum(labels == c)) for c in range(k)]
    centers_model = centers * scale + mean
    ids, aligned, next_id = _group_ids(centers_model, sizes, scale, names, previous, space, next_id)
    distances = np.linalg.norm(z - centers[labels], axis=1)
    scores, twins = _score(z) if scored else (np.zeros(n), np.full(n, math.inf))

    hosts: dict[int, HostFit] = {}
    groups: list[GroupFit] = []
    for cluster in range(k):
        members = labels == cluster
        zm = z[members]
        med = np.median(zm, axis=0)
        spread = np.maximum(_MAD_SCALE * np.median(np.abs(zm - med), axis=0), DEVIATION_FLOOR)
        deviations = np.abs(zm - med) / spread
        peer = np.median(raw[members], axis=0)
        groups.append(
            GroupFit(
                id=ids[cluster],
                partition=space,
                size=int(members.sum()),
                centroid=dict(zip(names, _inverse(features, centers_model[cluster]), strict=True)),
                median={name: float(v) for name, v in zip(names, peer.tolist(), strict=True)},
                score_median=float(np.median(scores[members])),
                centroid_model=[float(v) for v in centers_model[cluster].tolist()],
            )
        )
        for row, local in enumerate(np.flatnonzero(members).tolist()):
            hosts[index[local]] = HostFit(
                entity_key=str(keys[index[local]]),
                group_id=ids[cluster],
                distance=float(distances[local]),
                score=float(scores[local]),
                top=_top(deviations[row], raw[local], peer, names) if scored else (),
                scored=scored,
                twin_distance=float(twins[local]),
            )
    partition = PartitionFit(
        name=space,
        hosts=n,
        mean=[float(v) for v in mean.tolist()],
        scale=[float(v) for v in scale.tolist()],
        k=k,
        silhouette=silhouette,
        scored=scored,
    )
    return _Space(hosts=hosts, groups=groups, partition=partition, aligned=aligned, next_id=next_id)


def fit_estate(
    keys: Sequence[str],
    features: Sequence[Feature],
    raw_rows: Sequence[Sequence[float]],
    model_rows: Sequence[Sequence[float]],
    *,
    previous: Mapping[str, Any] | None = None,
) -> EstateFit:
    """Fit the groups, score every host and explain the scores.

    ``previous`` is the payload of the previous model file, read through the
    verified loader. It gives the group ids to carry over and the bins of the
    drift index. None on a first fit, or when the loader refused the file.
    """
    started = time.monotonic()
    names = [f.name for f in features]
    x_all = np.asarray(model_rows, dtype=float).reshape(len(keys), len(names))
    raw_all = np.asarray(raw_rows, dtype=float).reshape(len(keys), len(names))
    spaces = [partition_of(str(key)) for key in keys]
    prev_ids = [int(g["id"]) for g in list((previous or {}).get("groups") or [])]
    next_id = max([0, *prev_ids]) + 1
    prev_hist = (previous or {}).get("histograms") or {}

    hosts: dict[int, HostFit] = {}
    groups: list[GroupFit] = []
    partitions: dict[str, PartitionFit] = {}
    histograms: dict[str, dict[str, list[float]]] = {}
    psi: dict[str, float] = {}
    aligned = 0
    for space in PARTITIONS:
        index = [i for i, s in enumerate(spaces) if s == space]
        if not index:
            continue
        fitted = _fit_space(
            space,
            index,
            keys,
            features,
            x_all[index],
            raw_all[index],
            previous=previous,
            next_id=next_id,
        )
        next_id = fitted.next_id
        aligned += fitted.aligned
        hosts.update(fitted.hosts)
        groups.extend(fitted.groups)
        partitions[space] = fitted.partition
        histograms.update(_histograms(x_all[index], names, space))
        psi.update(population_stability(prev_hist, x_all[index], names, space))

    groups.sort(key=lambda g: g.id)
    return EstateFit(
        feature_names=names,
        hosts=[hosts[i] for i in range(len(keys))],
        groups=groups,
        partitions=partitions,
        histograms=histograms,
        psi=psi,
        aligned=aligned,
        seconds=time.monotonic() - started,
    )
